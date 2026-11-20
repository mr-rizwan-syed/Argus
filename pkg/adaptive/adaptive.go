// Package adaptive provides a dynamic concurrency limiter that adjusts itself
// based on live FD usage and available memory, so the scanner fully utilises
// the host without triggering OOM kills or EMFILE errors.
package adaptive

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	// maxCap is the hard ceiling on the token channel buffer.
	// Set large enough that it never constrains us in practice.
	maxCap = 200_000

	minConcurrency = 50

	checkInterval = 2 * time.Second

	// Thresholds that trigger a step down.
	fdHighWatermark  = 0.85 // severe — drop 20%
	fdMidWatermark   = 0.75 // moderate — drop 7%
	memLowCritical   = 0.10 // severe — drop 20%
	memLowModerate   = 0.20 // moderate — drop 7%

	// Threshold that allows a step up.
	fdHeadroom  = 0.55
	memHeadroom = 0.30
	stepUp      = 0.10 // grow 10% when comfortable
)

// Limiter is a counting semaphore whose capacity adjusts at runtime.
//
// Workers call Acquire() before starting a TLS connection and Release() when done.
// A background goroutine (started by Monitor) shrinks or grows the pool every 2s
// based on FD usage and free memory. When shrinking, Release() destroys the token
// instead of returning it, so active concurrency drains naturally.
type Limiter struct {
	tokens  chan struct{}
	target  atomic.Int64
	fdLimit int64
	done    chan struct{}
}

// New creates a Limiter. When initial <= 0, hardware is probed to pick a value.
// Always call setMaxFDs first so the FD headroom calculation is accurate.
func New(initial int) *Limiter {
	setMaxFDs()
	fdLimit := getFDLimit()

	if initial <= 0 {
		initial = compute(fdLimit)
	}
	if initial < minConcurrency {
		initial = minConcurrency
	}

	cap := int(fdLimit)
	if cap > maxCap {
		cap = maxCap
	}

	l := &Limiter{
		tokens:  make(chan struct{}, cap),
		fdLimit: fdLimit,
		done:    make(chan struct{}),
	}
	l.target.Store(int64(initial))

	// Pre-fill the semaphore with the initial token count.
	for i := 0; i < initial; i++ {
		l.tokens <- struct{}{}
	}
	return l
}

// Acquire blocks until a concurrency slot is available.
func (l *Limiter) Acquire() { <-l.tokens }

// Release returns a token to the pool — unless the pool is already at or above
// target, in which case the token is destroyed (graceful shrink).
// The len check and the send are not atomic: during a scale-down, N concurrent
// callers can each pass the guard and each send, briefly exceeding target by up
// to N slots. This is intentional — a mutex here would serialize every goroutine
// completion, and the transient overshoot is small and self-correcting on the
// next monitor tick.
func (l *Limiter) Release() {
	if int64(len(l.tokens)) < l.target.Load() {
		select {
		case l.tokens <- struct{}{}:
		default:
		}
	}
}

// Current returns the current concurrency target.
func (l *Limiter) Current() int { return int(l.target.Load()) }

// Monitor adjusts the target every 2 seconds. Run it in its own goroutine.
// Stop it with Stop() when the scan is finished.
func (l *Limiter) Monitor() {
	tick := time.NewTicker(checkInterval)
	defer tick.Stop()
	for {
		select {
		case <-l.done:
			return
		case <-tick.C:
			l.adjust()
		}
	}
}

// Stop signals the Monitor goroutine to exit.
func (l *Limiter) Stop() {
	select {
	case <-l.done:
	default:
		close(l.done)
	}
}

// Info returns a one-line startup summary for stderr.
func (l *Limiter) Info() string {
	return fmt.Sprintf("CPUs=%d  FD-limit=%d  MemAvail=%dMB  concurrency=%d (auto)",
		runtime.NumCPU(), l.fdLimit, availableMemMB(), l.Current())
}

// adjust is called on every monitor tick.
func (l *Limiter) adjust() {
	fdOpen  := int64(countOpenFDs())
	fdUsage := float64(fdOpen) / float64(l.fdLimit)
	memFree := freeMemRatio()
	cur     := l.target.Load()

	var next int64
	switch {
	case fdUsage > fdHighWatermark || memFree < memLowCritical:
		next = int64(float64(cur) * 0.80)
		fmt.Fprintf(os.Stderr, "\r[adaptive] ⚠  pressure  fd=%.0f%%  mem-free=%.0f%%  → %d\n",
			fdUsage*100, memFree*100, next)
	case fdUsage > fdMidWatermark || memFree < memLowModerate:
		next = int64(float64(cur) * 0.93)
	case fdUsage < fdHeadroom && memFree > memHeadroom:
		next = int64(float64(cur) * (1.0 + stepUp))
	default:
		return // comfortable — hold current value
	}

	// Clamp: never exceed 80% of FD limit, never go below floor.
	maxAllowed := int64(float64(l.fdLimit) * 0.80)
	if next > maxAllowed {
		next = maxAllowed
	}
	if next < minConcurrency {
		next = minConcurrency
	}
	if next == cur {
		return
	}

	l.target.Store(next)

	if next > cur {
		// Add tokens so waiting goroutines can proceed.
		delta := int(next - cur)
		for i := 0; i < delta; i++ {
			select {
			case l.tokens <- struct{}{}:
			default:
			}
		}
	}
	// Shrinking: Release() destroys tokens until len(tokens) == next.
}

// compute picks an initial concurrency value from hardware constraints.
func compute(fdLimit int64) int {
	cpus  := runtime.NumCPU()
	memMB := availableMemMB()

	// Three independent ceilings — take the smallest.
	//   FD: keep 25% headroom
	fdBased := int(float64(fdLimit) * 0.75)
	//   Memory: TLS handshake peak ≈ 100 KB per active connection
	memBased := int(memMB) * 1024 / 100
	//   CPU: TLS crypto is compute-bound; ~750 concurrent goroutines per core is practical
	cpuBased := cpus * 750

	n := fdBased
	if memBased < n {
		n = memBased
	}
	if cpuBased < n {
		n = cpuBased
	}
	if n < minConcurrency {
		n = minConcurrency
	}
	if n > maxCap {
		n = maxCap
	}
	return n
}

// setMaxFDs raises the soft FD limit to the hard limit (best-effort).
func setMaxFDs() {
	var rlim syscall.Rlimit
	if syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlim) != nil {
		return
	}
	if rlim.Cur < rlim.Max {
		rlim.Cur = rlim.Max
		syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rlim) // best-effort; ignore error
	}
}

func getFDLimit() int64 {
	var rlim syscall.Rlimit
	if syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlim) != nil {
		return 1024
	}
	// RLIM_INFINITY (^uint64(0)) casts to -1 as int64; treat anything
	// non-positive or unreasonably large as a safe hard cap.
	const hardCap = 1_000_000
	v := int64(rlim.Cur)
	if v <= 0 || v > hardCap {
		return hardCap
	}
	return v
}

func countOpenFDs() int {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0
	}
	// ReadDir opens a directory fd that appears in /proc/self/fd while the
	// read is in progress; subtract 1 to avoid over-reporting pressure.
	n := len(entries) - 1
	if n < 0 {
		n = 0
	}
	return n
}

func availableMemMB() int64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 512
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "MemAvailable:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, _ := strconv.ParseInt(fields[1], 10, 64)
				return kb / 1024
			}
		}
	}
	return 512
}

func freeMemRatio() float64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0.5
	}
	defer f.Close()
	var total, avail int64
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		v, _ := strconv.ParseInt(fields[1], 10, 64)
		switch {
		case strings.HasPrefix(line, "MemTotal:"):
			total = v
		case strings.HasPrefix(line, "MemAvailable:"):
			avail = v
		}
	}
	if total == 0 {
		return 0.5
	}
	return float64(avail) / float64(total)
}
