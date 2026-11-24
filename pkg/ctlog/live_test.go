package ctlog

// Live tests against the real logs, off by default (they use the network and take minutes):
//
//	CT_LIVE=1 go test ./pkg/ctlog/ -run TestLiveSmoke -v                  ~30 s: every usable log is read a little
//	CT_LIVE_MEASURE=120 go test ./pkg/ctlog/ -run TestLiveMeasure -v      N seconds of tailing all usable logs, with CPU and bandwidth
//
// CPU is this process's user+system time (getrusage), so it includes the TLS and gzip work, not only parsing.

import (
	"context"
	"os"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func cpuSeconds() float64 {
	var ru syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	return float64(ru.Utime.Sec+ru.Stime.Sec) + float64(ru.Utime.Usec+ru.Stime.Usec)/1e6
}

func TestLiveSmoke(t *testing.T) {
	if os.Getenv("CT_LIVE") == "" {
		t.Skip("set CT_LIVE=1")
	}
	r, err := New(Options{Backfill: 300, PartialWait: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	var got, withNames atomic.Uint64
	var bad atomic.Uint64
	_ = r.Run(ctx, func(e Entry) {
		got.Add(1)
		if len(e.Names) > 0 {
			withNames.Add(1)
		}
		if e.Log == "" || e.Fingerprint == "" || e.NotAfter.Before(e.NotBefore) || e.Logged.IsZero() {
			bad.Add(1)
		}
	})
	s := r.Stats()
	proto := map[string]uint64{}
	for _, l := range s.Logs {
		proto[l.Protocol] += l.Entries
		status := "ok"
		if l.Entries == 0 {
			status = "NO ENTRIES"
		}
		t.Logf("%-12s %-34s %-9s entries=%-6d req=%-4d err=%-3d retry=%-3d parseErr=%-3d %s %s", l.Operator, l.Name, l.Protocol, l.Entries, l.Requests, l.Errors, l.Retries, l.ParseErrors, status, l.LastError)
	}
	t.Logf("%d logs, %d entries (%d with names), %d malformed, wire %.1f MB", len(s.Logs), got.Load(), withNames.Load(), bad.Load(), float64(s.WireBytes)/1e6)
	if len(s.Logs) == 0 || got.Load() == 0 || bad.Load() > 0 {
		t.Fatalf("logs=%d entries=%d malformed=%d", len(s.Logs), got.Load(), bad.Load())
	}
	for p, n := range proto {
		if n == 0 {
			t.Errorf("no entries at all from %s logs", p)
		}
	}
}

func TestLiveMeasure(t *testing.T) {
	secs, _ := strconv.Atoi(os.Getenv("CT_LIVE_MEASURE"))
	if secs <= 0 {
		t.Skip("set CT_LIVE_MEASURE=<seconds>")
	}
	r, err := New(Options{PartialWait: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(secs+15)*time.Second)
	defer cancel()
	var emitted atomic.Uint64
	var dupMu sync.Mutex
	seen := map[string]struct{}{}
	dups := map[string]int{}
	lo, hi := map[string]uint64{}, map[string]uint64{}
	done := make(chan struct{})
	go func() {
		_ = r.Run(ctx, func(e Entry) {
			emitted.Add(1)
			k := e.Log + "#" + strconv.FormatUint(e.Index, 10)
			dupMu.Lock()
			if _, ok := seen[k]; ok {
				dups[e.Log]++
			}
			seen[k] = struct{}{}
			if l, ok := lo[e.Log]; !ok || e.Index < l {
				lo[e.Log] = e.Index
			}
			if e.Index > hi[e.Log] {
				hi[e.Log] = e.Index
			}
			dupMu.Unlock()
		})
		close(done)
	}()

	time.Sleep(15 * time.Second) // positioning and the first polls
	s0, c0, e0, t0 := r.Stats(), cpuSeconds(), emitted.Load(), time.Now()
	time.Sleep(time.Duration(secs) * time.Second)
	s1, c1, e1, t1 := r.Stats(), cpuSeconds(), emitted.Load(), time.Now()
	cancel()
	<-done

	dur := t1.Sub(t0).Seconds()
	before := map[string]LogStats{}
	for _, l := range s0.Logs {
		before[l.Name] = l
	}
	read := map[string]uint64{} // entries read (index advance), by operator
	var total uint64
	for _, l := range s1.Logs {
		n := l.Next - before[l.Name].Next
		if l.Next < before[l.Name].Next {
			n = 0
		}
		read[l.Operator] += n
		total += n
	}
	t.Logf("window %.0f s, %d logs", dur, len(s1.Logs))
	t.Logf("entries read (index advance): %d = %.0f/s; delivered with names or organization: %d = %.0f/s", total, float64(total)/dur, e1-e0, float64(e1-e0)/dur)
	ops := make([]string, 0, len(read))
	for o := range read {
		ops = append(ops, o)
	}
	sort.Strings(ops)
	for _, o := range ops {
		t.Logf("  %-28s %7d entries  %7.1f/s", o, read[o], float64(read[o])/dur)
	}
	cpu := c1 - c0
	t.Logf("CPU %.2f s over the window = %.1f%% of one core; %.3f CPU-s per 1,000 entries", cpu, 100*cpu/dur, 1000*cpu/float64(max(total, 1)))
	wire := float64(s1.WireBytes - s0.WireBytes)
	t.Logf("bandwidth: wire %.2f MB = %.0f KB/s (%.2f Mbit/s); decompressed %.2f MB; %.0f bytes per entry on the wire", wire/1e6, wire/1e3/dur, wire*8/1e6/dur, func() float64 {
		var b0, b1 uint64
		for _, l := range s0.Logs {
			b0 += l.Bytes
		}
		for _, l := range s1.Logs {
			b1 += l.Bytes
		}
		return float64(b1-b0) / 1e6
	}(), wire/float64(max(total, 1)))
	t.Logf("requests %d, errors %d, retries %d, parse errors %d", s1.Requests-s0.Requests, s1.Errors-s0.Errors, s1.Retries-s0.Retries, s1.ParseErrors-s0.ParseErrors)
	for _, l := range s1.Logs {
		b := before[l.Name]
		if l.Errors-b.Errors > 0 || l.Retries-b.Retries > 0 || l.LastError != "" || l.Lag > 5000 {
			t.Logf("  note: %-12s %-34s err=%d retry=%d lag=%d last=%q", l.Operator, l.Name, l.Errors-b.Errors, l.Retries-b.Retries, l.Lag, l.LastError)
		}
	}
	for _, l := range s1.Logs { // a log that delivers more entries than its index advanced would be reading something twice
		b := before[l.Name]
		adv, del := l.Next-b.Next, l.Entries-b.Entries
		if l.Next >= b.Next && del > adv+adv/10+256 {
			dupMu.Lock()
			t.Errorf("%s: %d entries delivered but the position moved %d (next %d -> %d); duplicates %d, indexes seen %d..%d, head %d, requests %d", l.Name, del, adv, b.Next, l.Next, dups[l.Name], lo[l.Name], hi[l.Name], l.Head, l.Requests-b.Requests)
			dupMu.Unlock()
		}
	}
	var lagging int
	for _, l := range s1.Logs {
		if l.Lag > 5000 {
			lagging++
		}
	}
	t.Logf("%d logs more than 5,000 entries behind at the end", lagging)
}
