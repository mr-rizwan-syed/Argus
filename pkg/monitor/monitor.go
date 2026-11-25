package monitor

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mr-rizwan-syed/argus/pkg/ctlog"
)

// Config wires a monitor: a source of certificates, a source of rules and the outputs.
type Config struct {
	Source ctlog.Source
	Rules  RuleSource
	Sinks  []Sink

	MinScore       int           // default 50
	DailyCap       int           // hits per rule per UTC day, default 500
	DedupeWindow   time.Duration // default 24 h
	DedupeCapacity int           // keys remembered, default 1,000,000
	Workers        int           // matching goroutines, default 2
	Queue          int           // entries waiting for a worker, default 20,000
	ReloadEvery    time.Duration // default 60 s
	StatsInterval  time.Duration // default 60 s
	StatsFile      string
	OnStats        func(Snapshot) // called every interval with the snapshot (the heartbeat to the platform); must not block

	Logf  func(format string, args ...any)
	Stats *Stats
}

// A Lagger is a source that can say how far behind the logs it is.
type Lagger interface{ Lag() time.Duration }

// Monitor reads certificates, matches them against the rules and reports the hits.
type Monitor struct {
	cfg    Config
	engine atomic.Pointer[Engine]
	filter *Filter
	stats  *Stats
}

// New prepares a monitor. Nothing runs until Run.
func New(cfg Config) *Monitor {
	if cfg.MinScore <= 0 {
		cfg.MinScore = 50
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 2
	}
	if cfg.Queue <= 0 {
		cfg.Queue = 20000
	}
	if cfg.ReloadEvery <= 0 {
		cfg.ReloadEvery = time.Minute
	}
	if cfg.StatsInterval <= 0 {
		cfg.StatsInterval = time.Minute
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.Stats == nil {
		cfg.Stats = &Stats{}
	}
	cfg.Stats.Started = time.Now()
	return &Monitor{cfg: cfg, filter: NewFilter(cfg.DedupeWindow, cfg.DailyCap, cfg.DedupeCapacity), stats: cfg.Stats}
}

// Stats returns the live counters.
func (m *Monitor) Stats() *Stats { return m.stats }

// Engine returns the engine currently in use.
func (m *Monitor) Engine() *Engine { return m.engine.Load() }

func (m *Monitor) loadRules(ctx context.Context, first bool) error {
	set, changed, err := m.cfg.Rules.Load(ctx)
	if err != nil {
		return err
	}
	if !changed && !first {
		return nil
	}
	if set == nil {
		return fmt.Errorf("no rules from %s", m.cfg.Rules)
	}
	eng, err := Compile(set, EngineOptions{MinScore: m.cfg.MinScore})
	if err != nil {
		return err
	}
	m.engine.Store(eng)
	m.stats.Rules.Store(int64(eng.NumRules()))
	if !first {
		m.stats.RuleReloads.Add(1)
	}
	m.cfg.Logf("rules %s: %d rules", map[bool]string{true: "loaded", false: "reloaded"}[first], eng.NumRules())
	return nil
}

// Run reads until ctx is cancelled (or the source ends, for a replay), then drains the queues, closes the sinks and returns the source's error.
// Rules that cannot be loaded at the start are an error; a failed reload keeps the last good rules.
func (m *Monitor) Run(ctx context.Context) error {
	if err := m.loadRules(ctx, true); err != nil {
		return fmt.Errorf("rules: %w", err)
	}
	entries := make(chan ctlog.Entry, m.cfg.Queue)
	matches := make(chan Match, 10000)
	var workers, aux sync.WaitGroup
	auxCtx, stopAux := context.WithCancel(context.Background())

	aux.Add(1)
	go func() { // reload the rules
		defer aux.Done()
		t := time.NewTicker(m.cfg.ReloadEvery)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				if err := m.loadRules(auxCtx, false); err != nil {
					var fe *FetchError
					if errors.As(err, &fe) {
						m.stats.RuleFetchErrs.Add(1)
						m.cfg.Logf("rules could not be fetched (keeping the last good set): %v", err)
					} else {
						m.stats.RuleReloadErrs.Add(1)
						m.cfg.Logf("rules REFUSED (keeping the last good set): %v", err)
					}
				}
			case <-auxCtx.Done():
				return
			}
		}
	}()

	aux.Add(1)
	go func() { // statistics
		defer aux.Done()
		t := time.NewTicker(m.cfg.StatsInterval)
		defer t.Stop()
		var prev *Snapshot
		tick := func(now time.Time) {
			m.stats.QueueDepth.Store(int64(len(entries) + len(matches)))
			var lag time.Duration
			if l, ok := m.cfg.Source.(Lagger); ok {
				lag = l.Lag()
			}
			sn := m.stats.snapshot(now, prev, lag)
			prev = &sn
			m.cfg.Logf("%s", sn.Line())
			if m.cfg.OnStats != nil {
				m.cfg.OnStats(sn)
			}
			if m.cfg.StatsFile != "" {
				if err := WriteStatsFile(m.cfg.StatsFile, sn); err != nil {
					m.cfg.Logf("could not write the stats file: %v", err)
				}
			}
		}
		for {
			select {
			case now := <-t.C:
				tick(now)
			case <-auxCtx.Done():
				tick(time.Now())
				return
			}
		}
	}()

	for i := 0; i < m.cfg.Workers; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			var hits []Match
			for en := range entries {
				eng := m.engine.Load()
				m.stats.Entries.Add(1)
				m.stats.Names.Add(int64(len(en.Names)))
				hits = eng.Match(en, hits[:0])
				for i := range hits {
					ok, meta := m.filter.Accept(&hits[i])
					if ok {
						m.stats.count(hits[i].Kind)
						m.push(matches, hits[i])
					} else {
						m.stats.Suppressed.Add(1)
					}
					if meta != nil {
						m.stats.NoisyRules.Add(1)
						m.cfg.Logf("rule %q reached its daily limit of hits", meta.RuleID)
						m.push(matches, *meta)
					}
				}
			}
		}()
	}

	writer := make(chan struct{})
	go func() { // outputs
		defer close(writer)
		var batch []Match
		for first := range matches {
			batch = append(batch[:0], first)
		more:
			for len(batch) < 100 {
				select {
				case x, ok := <-matches:
					if !ok {
						break more
					}
					batch = append(batch, x)
				default:
					break more
				}
			}
			for _, s := range m.cfg.Sinks {
				s.Write(batch)
			}
		}
	}()

	err := m.cfg.Source.Run(ctx, func(en ctlog.Entry) {
		select {
		case entries <- en:
		default:
			m.stats.DroppedEntries.Add(1)
		}
	})
	close(entries)
	workers.Wait()
	close(matches)
	<-writer
	for _, s := range m.cfg.Sinks {
		if cerr := s.Close(); cerr != nil {
			m.cfg.Logf("closing an output: %v", cerr)
		}
	}
	stopAux()
	aux.Wait()
	return err
}

func (m *Monitor) push(ch chan Match, match Match) {
	select {
	case ch <- match:
	default:
		m.stats.DroppedMatches.Add(1)
	}
}
