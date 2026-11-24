package monitor

import (
	"fmt"
	"sync"
	"time"
)

// Filter is the noise control between the engine and the outputs: the same (rule, domain, kind) is reported once per window, and a rule that
// would report more than DailyCap hits in a UTC day is silenced for the rest of that day after ONE rule_noisy event.
//
// The "seen" memory is a bounded map (Capacity keys, 1M by default, about 30 MB): when it is full the oldest-inserted key is forgotten first
// (FIFO), so a very busy day can report a very old hit again, which is the safe direction.
type Filter struct {
	Window   time.Duration
	DailyCap int

	mu    sync.Mutex
	limit int
	seen  map[uint64]int64 // key hash -> unix seconds of the last report
	ring  []uint64         // insertion order, for eviction
	head  int
	day   string
	count map[string]int
	noisy map[string]bool
	now   func() time.Time
}

// NewFilter makes a filter. window <= 0 means 24 hours, dailyCap <= 0 means 500, capacity <= 0 means 1,000,000.
func NewFilter(window time.Duration, dailyCap, capacity int) *Filter {
	if window <= 0 {
		window = 24 * time.Hour
	}
	if dailyCap <= 0 {
		dailyCap = 500
	}
	if capacity <= 0 {
		capacity = 1_000_000
	}
	return &Filter{Window: window, DailyCap: dailyCap, limit: capacity, seen: make(map[uint64]int64, 1024), count: map[string]int{},
		noisy: map[string]bool{}, now: time.Now}
}

func keyHash(rule, kind, domain string) uint64 {
	h := uint64(14695981039346656037)
	for _, s := range [3]string{rule, kind, domain} {
		for i := 0; i < len(s); i++ {
			h ^= uint64(s[i])
			h *= 1099511628211
		}
		h *= 1099511628211
	}
	return h
}

// Accept decides about one match. accepted is true when it should be reported; meta is a rule_noisy event to report as well (at most once per
// rule per UTC day).
func (f *Filter) Accept(m *Match) (accepted bool, meta *Match) {
	now := f.now().UTC()
	f.mu.Lock()
	defer f.mu.Unlock()
	if day := now.Format("2006-01-02"); day != f.day {
		f.day, f.count, f.noisy = day, map[string]int{}, map[string]bool{}
	}
	key := keyHash(m.RuleID, m.Kind, m.Domain)
	last, known := f.seen[key]
	if known && now.Unix()-last < int64(f.Window.Seconds()) {
		return false, nil
	}
	if f.count[m.RuleID] >= f.DailyCap {
		if !f.noisy[m.RuleID] {
			f.noisy[m.RuleID] = true
			return false, &Match{RuleID: m.RuleID, Kind: KindRuleNoisy, Matched: m.Matched, Seen: now, Reasons: []string{fmt.Sprintf(
				"this rule reached its daily limit of %d hits: nothing more is reported for it until the next UTC day (narrow the keywords)", f.DailyCap)}}
		}
		return false, nil
	}
	f.count[m.RuleID]++
	if !known { // a key that expired stays where it is in the ring
		if len(f.ring) < f.limit {
			f.ring = append(f.ring, key)
		} else {
			delete(f.seen, f.ring[f.head])
			f.ring[f.head] = key
			f.head = (f.head + 1) % len(f.ring)
		}
	}
	f.seen[key] = now.Unix()
	return true, nil
}

// Size is the number of keys remembered.
func (f *Filter) Size() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.seen)
}
