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
	"github.com/mr-rizwan-syed/argus/pkg/order"
	"github.com/mr-rizwan-syed/argus/pkg/pace"
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

	// Random order: a shuffled walk over every address:port. Its checkpoint is a COUNTER (how many positions of the shuffled order were started),
	// kept with the seed in <input>.argchk.rand; a resume goes back a few concurrency-fulls because the probes in flight were not finished.
	var space *order.Space
	var perm *order.Perm
	var startIdx uint64
	randomCkpt := ""
	seed := args.Seed
	if args.Order == "random" {
		var err error
		space, err = order.Build(args.Input, args.Ports)
		if err != nil || space.Total() == 0 {
			if err == nil {
				err = fmt.Errorf("nothing to scan")
			}
			fmt.Fprintf(os.Stderr, "[argus] input error: %v\n", err)
			os.Exit(2)
		}
		if !args.NoCheckpoint {
			if _, e := os.Stat(args.Input); e == nil {
				randomCkpt = args.Input + ".argchk.rand"
			}
		}
		if args.Resume && randomCkpt != "" {
			if sd, k, e := readRandomCheckpoint(randomCkpt); e == nil && k > 0 {
				seed = sd
				back := uint64(lim.Current()) * 4
				if k > back {
					startIdx = k - back
				}
				fmt.Fprintf(os.Stderr, "[argus] resuming the random order at position %d (seed %d)\n", startIdx, seed)
			} else {
				fmt.Fprintln(os.Stderr, "[argus] no checkpoint found — starting from position 0")
			}
		}
		if seed == 0 {
			seed = uint64(time.Now().UnixNano())
		}
		perm = order.NewPerm(space.Total(), seed)
		fmt.Fprintf(os.Stderr, "[argus] order=random seed=%d addresses=%d\n", seed, space.Total())
	}

	// Pre-count total addresses for percentage progress (pure bit-math, fast).
	totalAddrs := utils.CountInputFrom(args.Input, args.Ports, skipLines)
	if space != nil {
		totalAddrs = int64(space.Total() - startIdx)
	}

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
		if space != nil {
			total := space.Total()
			for k := startIdx; k < total; k++ {
				select {
				case inputChannel <- space.At(perm.At(k)):
				case <-baseCtx.Done():
					return
				}
				if randomCkpt != "" && k%100000 == 0 {
					writeRandomCheckpoint(randomCkpt, seed, k)
				}
			}
			return
		}
		if err := utils.IntakeFunctionFrom(inputChannel, args.Ports, args.Input, skipLines, onLine); err != nil {
			fmt.Fprintf(os.Stderr, "[argus] input error: %v\n", err)
			cancelBase()
		}
	}()

	// ── Live progress reporter (stderr, every 5 s) ───────────────────────────
	var totalScanned, totalHits atomic.Int64
	var fails [utils.FailKinds]atomic.Int64
	failLine := func() string { // why probes failed, for the platform to judge the scan: local_err > 0 means OUR side lost probes
		return fmt.Sprintf("  connect_timeout=%d refused=%d unreachable=%d reset=%d local_err=%d handshake_timeout=%d tls_fail=%d no_cert=%d",
			fails[utils.FailConnectTimeout].Load(), fails[utils.FailRefused].Load(), fails[utils.FailUnreachable].Load(), fails[utils.FailReset].Load(),
			fails[utils.FailLocal].Load(), fails[utils.FailHandshakeTimeout].Load(), fails[utils.FailTLS].Load(), fails[utils.FailNoCert].Load())
	}
	sockOpts := utils.SockOpts{SynRetries: args.SynRetries, FastClose: args.FastClose}
	pacer := pace.New(args.Rate)
	defer pacer.Stop()
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
					fmt.Fprintf(os.Stderr, "[argus] %d/%d (%.1f%%)  hits=%d  rate=%.0f/s  concurrency=%d%s\n",
						scanned, totalAddrs, pct, hits, rate, lim.Current(), failLine())
				} else {
					fmt.Fprintf(os.Stderr, "[argus] scanned=%d  hits=%d  rate=%.0f/s  concurrency=%d%s\n",
						scanned, hits, rate, lim.Current(), failLine())
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

		pacer.Wait(baseCtx)
		lim.Acquire()
		tlsWg.Add(1)
		go func(addr string) {
			defer tlsWg.Done()
			defer lim.Release()

			ctx, cancel := context.WithTimeout(baseCtx, time.Duration(args.Timeout)*time.Second)
			defer cancel()

			cert, kind, err := utils.Probe(ctx, addr, sockOpts)
			totalScanned.Add(1)

			if err != nil {
				if baseCtx.Err() == nil { // a probe cut short by our own shutdown says nothing about the target
					fails[kind].Add(1)
				}
				resultChannel <- types.Result{
					IP:       addr,
					Hit:      false,
					Timeout:  isTimeout(err),
					FailKind: int(kind),
					Error:    err,
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
		fmt.Fprintf(os.Stderr, "[argus] done  %d/%d (%.1f%%)  hits=%d%s\n",
			scanned, totalAddrs, pct, hits, failLine())
	} else {
		fmt.Fprintf(os.Stderr, "[argus] done  scanned=%d  hits=%d%s\n",
			scanned, hits, failLine())
	}

	// Remove checkpoint on clean exit; leave it intact on SIGINT so the user
	// can resume with -resume.
	if checkpointFile != "" && baseCtx.Err() == nil {
		os.Remove(checkpointFile)
	}
	if randomCkpt != "" && baseCtx.Err() == nil {
		os.Remove(randomCkpt)
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

// The random order's checkpoint: "<seed> <position>".
func writeRandomCheckpoint(file string, seed, k uint64) {
	tmp := file + ".tmp"
	if err := os.WriteFile(tmp, []byte(fmt.Sprintf("%d %d\n", seed, k)), 0644); err == nil {
		os.Rename(tmp, file)
	}
}

func readRandomCheckpoint(file string) (seed, k uint64, err error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return 0, 0, err
	}
	_, err = fmt.Sscanf(string(data), "%d %d", &seed, &k)
	return seed, k, err
}
