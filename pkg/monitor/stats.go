package monitor

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

// Stats are the monitor's counters. All fields are safe for concurrent use.
type Stats struct {
	Started time.Time

	Entries        atomic.Int64
	Names          atomic.Int64
	Subdomain      atomic.Int64
	Keyword        atomic.Int64
	Lookalike      atomic.Int64
	Org            atomic.Int64
	Suppressed     atomic.Int64 // matches dropped by the filter (duplicates, daily cap)
	NoisyRules     atomic.Int64
	DroppedEntries atomic.Int64 // the engine could not keep up: a full queue drops, it never blocks the reader
	DroppedMatches atomic.Int64
	Delivered      atomic.Int64 // matches the platform accepted
	Spooled        atomic.Int64 // matches written to the disk spool
	SpoolDropped   atomic.Int64 // matches lost because the spool was full
	Rejected       atomic.Int64 // matches the platform refused for good (a 400, 413 or 422)
	PostFailures   atomic.Int64
	RuleReloads    atomic.Int64
	RuleReloadErrs atomic.Int64 // a rules file arrived and was refused (the previous rules stay)
	RuleFetchErrs  atomic.Int64 // the rules could not be fetched at all (network, bad HTTP status)
	QueueDepth     atomic.Int64
	Rules          atomic.Int64
}

func (s *Stats) count(kind string) {
	switch kind {
	case KindSubdomain:
		s.Subdomain.Add(1)
	case KindKeyword:
		s.Keyword.Add(1)
	case KindLookalike:
		s.Lookalike.Add(1)
	case KindOrg:
		s.Org.Add(1)
	}
}

// Snapshot is the JSON written to -stats-file.
type Snapshot struct {
	Time           time.Time `json:"time"`
	UptimeSeconds  int64     `json:"uptime_seconds"`
	Entries        int64     `json:"entries"`
	Names          int64     `json:"names"`
	EntriesPerSec  float64   `json:"entries_per_sec"`
	NamesPerSec    float64   `json:"names_per_sec"`
	Subdomain      int64     `json:"subdomain"`
	Keyword        int64     `json:"keyword"`
	Lookalike      int64     `json:"lookalike"`
	Org            int64     `json:"org"`
	Suppressed     int64     `json:"suppressed"`
	NoisyRules     int64     `json:"noisy_rules"`
	DroppedEntries int64     `json:"dropped_entries"`
	DroppedMatches int64     `json:"dropped_matches"`
	Delivered      int64     `json:"delivered"`
	Spooled        int64     `json:"spooled"`
	SpoolDropped   int64     `json:"spool_dropped"`
	Rejected       int64     `json:"rejected"`
	PostFailures   int64     `json:"post_failures"`
	RuleReloads    int64     `json:"rule_reloads"`
	RuleReloadErrs int64     `json:"rule_reload_errors"`
	RuleFetchErrs  int64     `json:"rule_fetch_errors"`
	QueueDepth     int64     `json:"queue_depth"`
	Rules          int64     `json:"rules"`
	LagSeconds     float64   `json:"lag_seconds,omitempty"`
}

func (s *Stats) snapshot(now time.Time, prev *Snapshot, lag time.Duration) Snapshot {
	sn := Snapshot{Time: now, UptimeSeconds: int64(now.Sub(s.Started).Seconds()), Entries: s.Entries.Load(), Names: s.Names.Load(),
		Subdomain: s.Subdomain.Load(), Keyword: s.Keyword.Load(), Lookalike: s.Lookalike.Load(), Org: s.Org.Load(), Suppressed: s.Suppressed.Load(),
		NoisyRules: s.NoisyRules.Load(), DroppedEntries: s.DroppedEntries.Load(), DroppedMatches: s.DroppedMatches.Load(), Delivered: s.Delivered.Load(),
		Spooled: s.Spooled.Load(), SpoolDropped: s.SpoolDropped.Load(), Rejected: s.Rejected.Load(), PostFailures: s.PostFailures.Load(),
		RuleReloads: s.RuleReloads.Load(), RuleReloadErrs: s.RuleReloadErrs.Load(), RuleFetchErrs: s.RuleFetchErrs.Load(), QueueDepth: s.QueueDepth.Load(), Rules: s.Rules.Load(),
		LagSeconds: lag.Seconds()}
	if prev != nil {
		if dt := now.Sub(prev.Time).Seconds(); dt > 0 {
			sn.EntriesPerSec = float64(sn.Entries-prev.Entries) / dt
			sn.NamesPerSec = float64(sn.Names-prev.Names) / dt
		}
	}
	return sn
}

// Line is the one-line report written to stderr every interval.
func (sn Snapshot) Line() string {
	line := fmt.Sprintf("monitor: %.0f entries/s %.0f names/s | hits subdomain=%d keyword=%d lookalike=%d org=%d (suppressed %d) | queue %d | delivered %d spooled %d | dropped entries=%d matches=%d spool=%d | rules %d",
		sn.EntriesPerSec, sn.NamesPerSec, sn.Subdomain, sn.Keyword, sn.Lookalike, sn.Org, sn.Suppressed, sn.QueueDepth, sn.Delivered, sn.Spooled,
		sn.DroppedEntries, sn.DroppedMatches, sn.SpoolDropped, sn.Rules)
	if sn.LagSeconds > 0 {
		line += fmt.Sprintf(" | lag %.0fs", sn.LagSeconds)
	}
	if sn.PostFailures > 0 || sn.Rejected > 0 {
		line += fmt.Sprintf(" | post failures %d rejected %d", sn.PostFailures, sn.Rejected)
	}
	return line
}

func writeFileAtomic(path string, data []byte) error {
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".tmp")
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// WriteStatsFile writes the snapshot as JSON, atomically.
func WriteStatsFile(path string, sn Snapshot) error {
	data, err := json.MarshalIndent(sn, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, append(data, '\n'))
}
