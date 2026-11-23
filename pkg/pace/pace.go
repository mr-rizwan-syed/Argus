// Package pace limits how many probes start per second.
//
// Concurrency alone does not bound the rate: a faster server (or a drop in timeouts) makes it climb until local descriptors run out, and
// the packets-per-second then exceed what the virtual NIC, the connection tracker or the targets' networks tolerate, so replies are lost
// silently. A start-rate cap makes the speed a number we choose and measure instead of an accident of the hardware.
package pace

import (
	"context"
	"sync/atomic"
	"time"
)

// Pacer hands out start permits at a fixed rate. Wait is meant for ONE goroutine (the scan loop).
type Pacer struct {
	tokens atomic.Int64
	burst  int64
	stop   chan struct{}
}

// New returns a pacer for `rate` starts per second, or nil when rate <= 0 (no limit).
func New(rate int) *Pacer {
	if rate <= 0 {
		return nil
	}
	p := &Pacer{burst: int64(rate)/10 + 1, stop: make(chan struct{})}
	go func() {
		tick := time.NewTicker(time.Millisecond)
		defer tick.Stop()
		var carry float64
		perMs := float64(rate) / 1000.0
		for {
			select {
			case <-p.stop:
				return
			case <-tick.C:
				carry += perMs
				n := int64(carry)
				carry -= float64(n)
				if n > 0 {
					if cur := p.tokens.Load(); cur < p.burst {
						p.tokens.Add(n)
					}
				}
			}
		}
	}()
	return p
}

// Wait blocks until one start is allowed (or ctx ends).
func (p *Pacer) Wait(ctx context.Context) {
	if p == nil {
		return
	}
	for {
		if p.tokens.Add(-1) >= 0 {
			return
		}
		p.tokens.Add(1)
		select {
		case <-ctx.Done():
			return
		case <-time.After(150 * time.Microsecond):
		}
	}
}

// Stop ends the refill goroutine.
func (p *Pacer) Stop() {
	if p != nil {
		close(p.stop)
	}
}
