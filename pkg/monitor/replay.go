package monitor

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/mr-rizwan-syed/argus/pkg/ctlog"
)

// ReplaySource feeds recorded entries (one ctlog.Entry as JSON per line) to the monitor: for tests, for tuning rules against yesterday's
// certificates, and for benchmarks. Rate is entries per second (0: as fast as the monitor takes them).
type ReplaySource struct {
	R    io.Reader
	Rate int
	// Bad counts lines that were not valid entries (they are skipped).
	Bad int
}

func (r *ReplaySource) Run(ctx context.Context, emit func(ctlog.Entry)) error {
	sc := bufio.NewScanner(r.R)
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	var tick <-chan time.Time
	if r.Rate > 0 {
		t := time.NewTicker(time.Second / time.Duration(r.Rate))
		if r.Rate > 1000 { // a ticker cannot go faster than about a millisecond: pace in bursts
			t.Stop()
			t = time.NewTicker(time.Millisecond)
		}
		defer t.Stop()
		tick = t.C
	}
	burst := 1
	if r.Rate > 1000 {
		burst = r.Rate / 1000
	}
	n := 0
	for sc.Scan() {
		if err := ctx.Err(); err != nil {
			return nil
		}
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var en ctlog.Entry
		if err := json.Unmarshal(line, &en); err != nil {
			r.Bad++
			continue
		}
		if en.Seen.IsZero() {
			en.Seen = time.Now()
		}
		if tick != nil && n%burst == 0 {
			select {
			case <-tick:
			case <-ctx.Done():
				return nil
			}
		}
		n++
		emit(en)
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("reading the replay file: %w", err)
	}
	return nil
}
