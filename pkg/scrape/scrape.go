package scrape

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/mr-rizwan-syed/argus/pkg/adaptive"
	"github.com/mr-rizwan-syed/argus/pkg/types"
	"github.com/mr-rizwan-syed/argus/pkg/utils"
	"github.com/mr-rizwan-syed/argus/pkg/workers"
)

func RunScrape(args types.ScrapeArgs) {
	// Adaptive semaphore — auto-detects hardware when args.Concurrency == 0.
	lim := adaptive.New(args.Concurrency)
	go lim.Monitor()
	defer lim.Stop()
	fmt.Fprintln(os.Stderr, "[argus] "+lim.Info())

	// Base context cancelled on SIGINT / SIGTERM so all in-flight work stops cleanly.
	baseCtx, cancelBase := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancelBase()

	cur := lim.Current()

	// Buffered channels decouple the three pipeline stages so no stage blocks another.
	inputChannel  := make(chan string, cur*2)
	resultChannel := make(chan types.Result, cur)
	outputChannel := make(chan string, max(cur/10, 256))

	// ── Result workers ───────────────────────────────────────────────────────
	// cur/20 capped at 32; the cap dominates above cur=640, so at any realistic
	// auto-detected concurrency you get exactly 32 result workers.
	resultCount := max(cur/20, 8)
	if resultCount > 32 {
		resultCount = 32
	}
	var resultWg sync.WaitGroup
	for i := 0; i < resultCount; i++ {
		resultWg.Add(1)
		go func() {
			defer resultWg.Done()
			workers.ProcessResults(resultChannel, outputChannel, args)
		}()
	}

	// ── Buffered stdout writer ────────────────────────────────────────────────
	// Collects output lines into a 256 KB buffer and flushes every 100 ms instead
	// of locking stdout on every single line.
	bw := bufio.NewWriterSize(os.Stdout, 256*1024)
	var outputWg sync.WaitGroup
	outputWg.Add(1)
	go func() {
		defer outputWg.Done()
		flush := time.NewTicker(100 * time.Millisecond)
		defer flush.Stop()
		for {
			select {
			case out, ok := <-outputChannel:
				if !ok {
					bw.Flush()
					return
				}
				fmt.Fprintln(bw, out)
			case <-flush.C:
				bw.Flush()
			}
		}
	}()

	// ── Checkpoint / resume ──────────────────────────────────────────────────
	// Auto-named from the input path (only for file inputs; stdin uses a temp
	// file that is cleaned up on exit, so NoCheckpoint suppresses it).
	checkpointFile := ""
	skipLines := 0
	if !args.NoCheckpoint {
		if _, err := os.Stat(args.Input); err == nil { // is a real file
			checkpointFile = args.Input + ".argchk"
		}
	}
	if args.Resume && checkpointFile != "" {
		n, err := utils.ReadCheckpoint(checkpointFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[argus] checkpoint read error: %v — starting from line 0\n", err)
		} else if n > 0 {
			skipLines = n
			fmt.Fprintf(os.Stderr, "[argus] resuming from line %d\n", skipLines)
		} else {
			fmt.Fprintln(os.Stderr, "[argus] no checkpoint found — starting from line 0")
		}
	}

	// Pre-count total addresses for percentage progress (pure bit-math, fast).
	totalAddrs := utils.CountInputFrom(args.Input, args.Ports, skipLines)

	// ── Input feeder ─────────────────────────────────────────────────────────
	var onLine func(int)
	if checkpointFile != "" {
		onLine = func(lineNum int) {
			if err := utils.WriteCheckpoint(checkpointFile, lineNum); err != nil {
				fmt.Fprintf(os.Stderr, "[argus] checkpoint write error: %v\n", err)
			}
		}
	}
	go func() {
		defer close(inputChannel)
		if err := utils.IntakeFunctionFrom(inputChannel, args.Ports, args.Input, skipLines, onLine); err != nil {
			fmt.Fprintf(os.Stderr, "[argus] input error: %v\n", err)
			cancelBase()
		}
	}()

	// ── Live progress reporter (stderr, every 5 s) ───────────────────────────
	var totalScanned, totalHits atomic.Int64
	go func() {
		start := time.Now()
		tick := time.NewTicker(5 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-baseCtx.Done():
				return
			case <-tick.C:
				scanned := totalScanned.Load()
				hits    := totalHits.Load()
				elapsed := time.Since(start).Seconds()
				rate    := float64(scanned) / elapsed
				if totalAddrs > 0 {
					pct := float64(scanned) / float64(totalAddrs) * 100
					fmt.Fprintf(os.Stderr, "[argus] %d/%d (%.1f%%)  hits=%d  rate=%.0f/s  concurrency=%d\n",
						scanned, totalAddrs, pct, hits, rate, lim.Current())
				} else {
					fmt.Fprintf(os.Stderr, "[argus] scanned=%d  hits=%d  rate=%.0f/s  concurrency=%d\n",
						scanned, hits, rate, lim.Current())
				}
			}
		}
	}()

	// ── TLS workers — spawn-on-demand bounded by adaptive semaphore ──────────
	var tlsWg sync.WaitGroup
SCAN:
	for addr := range inputChannel {
		// Stop spawning new connections on SIGINT; drain the input channel so the
		// feeder goroutine can exit.
		select {
		case <-baseCtx.Done():
			break SCAN
		default:
		}

		lim.Acquire()
		tlsWg.Add(1)
		go func(addr string) {
			defer tlsWg.Done()
			defer lim.Release()

			ctx, cancel := context.WithTimeout(baseCtx, time.Duration(args.Timeout)*time.Second)
			defer cancel()

			cert, err := utils.GetSSLCertContext(ctx, addr)
			totalScanned.Add(1)

			if err != nil {
				resultChannel <- types.Result{
					IP:      addr,
					Hit:     false,
					Timeout: isTimeout(err),
					Error:   err,
				}
				return
			}

			totalHits.Add(1)
			resultChannel <- types.Result{
				IP:  addr,
				Hit: true,
				Certificate: &types.CertificateInfo{
					OriginIP:          addr,
					Organization:      cert.Subject.Organization,
					OrganizationUnit:  cert.Subject.OrganizationalUnit,
					CommonName:        cert.Subject.CommonName,
					SAN:               cert.DNSNames,
					Domains:           append([]string{cert.Subject.CommonName}, cert.DNSNames...),
					Emails:            cert.EmailAddresses,
					IPAddrs:           cert.IPAddresses,
					CertFingerprint:   utils.SHA256Fingerprint(cert.Raw),
					PubkeyFingerprint: utils.SHA256Fingerprint(cert.RawSubjectPublicKeyInfo),
				},
			}
		}(addr)
	}

	// Drain remaining input if we broke out early due to SIGINT.
	if baseCtx.Err() != nil {
		go func() {
			for range inputChannel {
			}
		}()
	}

	tlsWg.Wait()
	close(resultChannel)

	resultWg.Wait()
	close(outputChannel)
	outputWg.Wait()

	// Final summary to stderr.
	scanned := totalScanned.Load()
	hits    := totalHits.Load()
	if totalAddrs > 0 {
		pct := float64(scanned) / float64(totalAddrs) * 100
		if pct > 100 {
			pct = 100
		}
		fmt.Fprintf(os.Stderr, "[argus] done  %d/%d (%.1f%%)  hits=%d\n",
			scanned, totalAddrs, pct, hits)
	} else {
		fmt.Fprintf(os.Stderr, "[argus] done  scanned=%d  hits=%d\n",
			scanned, hits)
	}

	// Remove checkpoint on clean exit; leave it intact on SIGINT so the user
	// can resume with -resume.
	if checkpointFile != "" && baseCtx.Err() == nil {
		os.Remove(checkpointFile)
	}

}

// isTimeout returns true for context deadline / net timeout errors.
// context.Canceled is intentionally excluded: it fires on SIGINT (via
// signal.NotifyContext) and should not be reported as a timeout.
func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	type timeouter interface{ Timeout() bool }
	if t, ok := err.(timeouter); ok {
		return t.Timeout()
	}
	return false
}
