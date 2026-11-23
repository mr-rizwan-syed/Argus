package pace

import (
	"context"
	"testing"
	"time"
)

func TestNoRateMeansNoLimit(t *testing.T) {
	var p *Pacer = New(0)
	start := time.Now()
	for i := 0; i < 100000; i++ {
		p.Wait(context.Background())
	}
	if time.Since(start) > time.Second {
		t.Fatal("an unlimited pacer must not wait")
	}
	p.Stop()
}

func TestTheRateIsHeld(t *testing.T) {
	p := New(5000)
	defer p.Stop()
	time.Sleep(150 * time.Millisecond) // the burst fills
	start := time.Now()
	n := 0
	for time.Since(start) < 500*time.Millisecond {
		p.Wait(context.Background())
		n++
	}
	rate := float64(n) / time.Since(start).Seconds()
	// 5,000/s plus the initial burst (about 500): allow a generous band, the point is that it is not 100,000/s
	if rate < 3500 || rate > 8000 {
		t.Fatalf("rate %.0f/s, wanted about 5000", rate)
	}
}

func TestWaitReturnsWhenTheContextEnds(t *testing.T) {
	p := New(1)
	defer p.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	for i := 0; i < 5; i++ {
		p.Wait(ctx)
	}
	if ctx.Err() == nil {
		t.Fatal("it should have been blocked until the context ended")
	}
}
