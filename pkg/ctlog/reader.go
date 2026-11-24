package ctlog

// The Reader: reads every selected log until its context ends and hands each entry to emit.
//
//	log list (file or URL, re-read daily)  ->  one goroutine per log  ->  emit(Entry)
//
// Each log goroutine keeps a position (the index of the next entry to read). Where it starts:
//   - no saved position: the log's current tree size minus Options.Backfill (so only NEW certificates are read, plus Backfill older ones);
//   - a saved position (the state file) that is within MaxLag entries of the head: exactly there, so nothing is missed across a restart;
//   - a saved position further behind than MaxLag: jump to the head (minus Backfill). Hours of backlog are not downloaded; the skipped
//     entries are counted in the log's GapEntries and written to the logger;
//   - a saved position beyond the head, or a head that goes backwards while running (the log was reset): restart at the new head.
//
// When it has read everything it polls the head every PollInterval (5 s) with jitter, backing off to MaxPollInterval (30 s) while the log is
// quiet; a log whose certificates only start expiring in the future (its temporal interval begins more than a day ahead) is polled every five
// minutes. While behind it reads without pausing, one request at a time per log (the log's own limits and the shared MaxConcurrentRequests cap
// are the throttle). Errors back off per log; no log can stop another.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Options configures a Reader. Zero values are replaced by the defaults in brackets.
type Options struct {
	LogListURL  string        // where to get the log list (default: Google's v3 list); ignored when LogListFile is set
	LogListFile string        // a local log list (tests, offline)
	ListRefresh time.Duration // how often to re-read the list [24h]

	StatePath string // JSON file with the next index of every log; empty: nothing is saved
	Backfill  uint64 // entries before the head to read when a log has no saved position [0]
	MaxLag    uint64 // a saved position further behind than this is skipped to the head [100,000]

	IncludeOperators, ExcludeOperators []string // by operator name, case-insensitive
	IncludeURLs, ExcludeURLs           []string // by log URL (the monitoring URL of a static log)

	HTTPTimeout           time.Duration // per request [30s]
	UserAgent             string        // [argus-monitor/1.1 (+https://github.com/mr-rizwan-syed/Argus)]
	MaxConcurrentRequests int           // requests in flight over all logs [16]
	PollInterval          time.Duration // [5s]
	MaxPollInterval       time.Duration // [30s]
	PartialWait           time.Duration // how long a partial static tile may wait before it is fetched [10s]
	MaxBatch              int           // most entries asked of an RFC 6962 log per request [1024]

	// Logger receives one-line messages (log list changes, gaps, errors). Nil: silent. LoggerFrom adapts a *log.Logger.
	Logger func(string)

	// Client replaces the HTTP client (tests). Nil: a client with HTTP/2, keep-alive and byte counting.
	Client *http.Client
}

// DefaultLogListURL is the log list Chrome uses.
const DefaultLogListURL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"

// LoggerFrom adapts a *log.Logger to Options.Logger.
func LoggerFrom(l *log.Logger) func(string) {
	return func(s string) { l.Print(s) }
}

func (o *Options) defaults() {
	if o.LogListURL == "" {
		o.LogListURL = DefaultLogListURL
	}
	if o.ListRefresh <= 0 {
		o.ListRefresh = 24 * time.Hour
	}
	if o.MaxLag == 0 {
		o.MaxLag = 100000
	}
	if o.HTTPTimeout <= 0 {
		o.HTTPTimeout = 30 * time.Second
	}
	if o.UserAgent == "" {
		o.UserAgent = defaultUserAgent
	}
	if o.MaxConcurrentRequests <= 0 {
		o.MaxConcurrentRequests = 16
	}
	if o.PollInterval <= 0 {
		o.PollInterval = 5 * time.Second
	}
	if o.MaxPollInterval < o.PollInterval {
		o.MaxPollInterval = max(30*time.Second, o.PollInterval)
	}
	if o.PartialWait <= 0 {
		o.PartialWait = 10 * time.Second
	}
	if o.MaxBatch <= 0 {
		o.MaxBatch = 1024
	}
}

// logStats are the counters of one log. Every field is safe to read while the log runs.
type logStats struct {
	info                                                               LogInfo
	entries, bytes, requests, errors, retries, parseErrors, gapEntries atomic.Uint64
	next, head                                                         atomic.Uint64
	lastEntry                                                          atomic.Int64 // unix nanoseconds of the last emitted entry
	mu                                                                 sync.Mutex
	lastError                                                          string
}

func (s *logStats) setError(err error) {
	s.mu.Lock()
	s.lastError = err.Error()
	s.mu.Unlock()
}

// LogStats is a snapshot of one log's counters.
type LogStats struct {
	Name, Operator, URL, Protocol string
	Next, Head                    uint64 // the next index to read, and the log's tree size as last seen
	Lag                           uint64 // Head - Next when positive
	Entries                       uint64 // entries emitted
	Bytes                         uint64 // decompressed response bytes
	Requests, Errors, Retries     uint64
	ParseErrors                   uint64 // entries that could not be read
	GapEntries                    uint64 // entries skipped because the position was too far behind
	LastEntry                     time.Time
	LastError                     string
}

// Stats is a snapshot of the whole Reader.
type Stats struct {
	Since                                           time.Time
	Logs                                            []LogStats // by name
	Entries, Requests, Errors, Retries, ParseErrors uint64     // sums over the logs
	WireBytes                                       uint64     // bytes received on the connections (compressed, TLS included)
}

type logRun struct {
	st     *logStats
	cancel context.CancelFunc
	done   chan struct{}
}

// Reader implements Source.
type Reader struct {
	opts    Options
	http    *httpClient
	wire    atomic.Uint64
	started time.Time

	mu    sync.Mutex
	runs  map[string]*logRun
	state *stateStore

	skipNoNames atomic.Uint64
}

// New validates the options and builds a Reader. Nothing is fetched until Run.
func New(opts Options) (*Reader, error) {
	opts.defaults()
	if opts.LogListFile == "" && !strings.HasPrefix(opts.LogListURL, "http") {
		return nil, errors.New("ctlog: LogListURL must be an http(s) URL (or set LogListFile)")
	}
	r := &Reader{opts: opts, runs: map[string]*logRun{}, state: newStateStore(opts.StatePath), started: time.Now()}
	r.http = newHTTPClient(&r.opts, &r.wire)
	return r, nil
}

func (r *Reader) logf(format string, a ...any) {
	if r.opts.Logger != nil {
		r.opts.Logger(fmt.Sprintf(format, a...))
	}
}

// Run reads the logs until ctx is cancelled. It returns an error only when the log list cannot be read at the start (after a few retries);
// afterwards a failing refresh keeps the logs it has.
func (r *Reader) Run(ctx context.Context, emit func(Entry)) error {
	var list []LogInfo
	var err error
	for attempt := 0; attempt < 5; attempt++ {
		if list, err = r.loadList(ctx); err == nil {
			break
		}
		r.logf("ctlog: the log list could not be read (%v)", err)
		if serr := sleepCtx(ctx, time.Duration(2<<attempt)*time.Second); serr != nil {
			return nil
		}
	}
	if err != nil {
		return err
	}
	if err := r.state.load(); err != nil {
		r.logf("ctlog: the state file could not be read, starting every log at its head (%v)", err)
	}
	r.sync(ctx, list, emit)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); r.saveLoop(ctx) }()

	refresh := time.NewTicker(r.opts.ListRefresh)
	defer refresh.Stop()
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case <-refresh.C:
			l, err := r.loadList(ctx)
			if err != nil {
				r.logf("ctlog: the log list could not be refreshed, keeping the current logs (%v)", err)
				continue
			}
			r.sync(ctx, l, emit)
		}
	}
	r.stopAll()
	wg.Wait()
	r.saveState()
	return nil
}

// loadList reads and filters the log list.
func (r *Reader) loadList(ctx context.Context) ([]LogInfo, error) {
	var data []byte
	var err error
	if r.opts.LogListFile != "" {
		data, err = os.ReadFile(r.opts.LogListFile)
	} else {
		data, err = r.http.get(ctx, r.opts.LogListURL, 16<<20, nil)
	}
	if err != nil {
		return nil, err
	}
	logs, err := ParseLogList(data)
	if err != nil {
		return nil, err
	}
	return filterLogs(logs, &r.opts), nil
}

// sync starts the logs that are new in the list and stops the ones that left it.
func (r *Reader) sync(ctx context.Context, list []LogInfo, emit func(Entry)) {
	want := map[string]LogInfo{}
	for _, l := range list {
		want[l.URL] = l
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for url, run := range r.runs {
		if _, ok := want[url]; !ok {
			r.logf("ctlog: %s left the log list, no longer read", run.st.info.Name)
			run.cancel()
			delete(r.runs, url)
		}
	}
	started := 0
	for _, l := range list {
		if _, ok := r.runs[l.URL]; ok {
			continue
		}
		st := &logStats{info: l}
		lctx, cancel := context.WithCancel(ctx)
		run := &logRun{st: st, cancel: cancel, done: make(chan struct{})}
		r.runs[l.URL] = run
		go func() {
			defer close(run.done)
			r.runLog(lctx, st, emit)
		}()
		started++
	}
	if started > 0 {
		r.logf("ctlog: reading %d logs (%d new)", len(r.runs), started)
	}
}

func (r *Reader) stopAll() {
	r.mu.Lock()
	runs := make([]*logRun, 0, len(r.runs))
	for _, run := range r.runs {
		run.cancel()
		runs = append(runs, run)
	}
	r.mu.Unlock()
	for _, run := range runs {
		<-run.done
	}
}

// deliver counts an entry and passes it on. Entries with no names and no subject organization have nothing for a monitor to match: they are
// counted (Stats.Entries does not include them) and dropped.
func (r *Reader) deliver(st *logStats, e Entry, emit func(Entry)) {
	if len(e.Names) == 0 && e.SubjectO == "" {
		r.skipNoNames.Add(1)
		return
	}
	st.entries.Add(1)
	st.lastEntry.Store(e.Seen.UnixNano())
	emit(e)
}

// logReader is the protocol-specific half of a log goroutine.
type logReader interface {
	head(ctx context.Context) (uint64, error)
	read(ctx context.Context, from uint64, emit func(Entry)) (int, error)
	// has reports whether the log still holds entry idx (used to tell a reset log from a tree head that is out of date).
	has(ctx context.Context, idx uint64) (bool, error)
}

// runLog is the loop of one log.
func (r *Reader) runLog(ctx context.Context, st *logStats, emit func(Entry)) {
	var c logReader
	if st.info.Protocol == ProtoStatic {
		c = newStaticReader(r, st)
	} else {
		c = newRFCReader(r, st)
	}
	next, ok := r.startPosition(ctx, c, st)
	if !ok {
		return
	}
	base := r.opts.PollInterval
	if !st.info.IntervalStart.IsZero() && time.Until(st.info.IntervalStart) > 24*time.Hour {
		base = 5 * time.Minute // a log for certificates that expire far in the future: nothing to read yet
	}
	idle, failures := base, 0
	for ctx.Err() == nil {
		n, err := c.read(ctx, next, emit)
		switch {
		case err != nil:
			if ctx.Err() != nil {
				return
			}
			st.setError(err)
			failures++
			if sleepCtx(ctx, min(time.Minute, time.Duration(2<<min(failures, 5))*time.Second)) != nil {
				return
			}
		case n > 0:
			failures = 0
			next += uint64(n)
			st.next.Store(next)
			idle = base
		default: // caught up: look at the head, then wait
			failures = 0
			head, err := c.head(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				st.setError(err)
			} else {
				st.head.Store(head)
				if head < next && r.looksReset(ctx, c, next) { // the log was reset
					r.logf("ctlog: %s: the tree size went back from %d to %d, restarting at the new head", st.info.Name, next, head)
					next = head
					st.next.Store(next)
				}
			}
			if sleepCtx(ctx, jitter(idle)) != nil {
				return
			}
			idle = min(idle*3/2, max(r.opts.MaxPollInterval, base))
		}
	}
}

// looksReset decides what a tree head smaller than our position means. A log behind a cache can serve an out-of-date tree head while
// get-entries already returns newer entries (seen on Sectigo's logs: the position passed the head and the old rule "head < next means
// reset" re-read thousands of entries again and again). A log has only been reset when it no longer holds the entry before our position.
// When that cannot be asked (network error) the position is kept.
func (r *Reader) looksReset(ctx context.Context, c logReader, next uint64) bool {
	if next == 0 {
		return false
	}
	ok, err := c.has(ctx, next-1)
	return err == nil && !ok
}

func jitter(d time.Duration) time.Duration {
	return d - d/5 + time.Duration(rand.Int63n(int64(d)/5*2+1))
}

// startPosition decides where a log starts (see the package comment) and records the head. ok is false when ctx ended first.
func (r *Reader) startPosition(ctx context.Context, c logReader, st *logStats) (uint64, bool) {
	var head uint64
	for failures := 0; ; failures++ {
		var err error
		if head, err = c.head(ctx); err == nil {
			break
		}
		if ctx.Err() != nil {
			return 0, false
		}
		st.setError(err)
		r.logf("ctlog: %s: the tree head could not be read yet (%v)", st.info.Name, err)
		if sleepCtx(ctx, min(time.Minute, time.Duration(5<<min(failures, 4))*time.Second)) != nil {
			return 0, false
		}
	}
	st.head.Store(head)
	fresh := uint64(0)
	if head > r.opts.Backfill {
		fresh = head - r.opts.Backfill
	}
	next := fresh
	if saved, ok := r.state.get(st.info.URL); ok {
		switch {
		case saved > head:
			r.logf("ctlog: %s: the saved position %d is beyond the tree size %d (the log was reset), starting at the head", st.info.Name, saved, head)
		case head-saved > r.opts.MaxLag:
			gap := fresh - min(saved, fresh)
			st.gapEntries.Add(gap)
			r.logf("ctlog: %s: %d entries behind the saved position, over the limit of %d: skipping %d entries to the head", st.info.Name, head-saved, r.opts.MaxLag, gap)
		default:
			next = saved
		}
	}
	st.next.Store(next)
	return next, true
}

// Stats returns a snapshot of the counters.
func (r *Reader) Stats() Stats {
	r.mu.Lock()
	runs := make([]*logRun, 0, len(r.runs))
	for _, run := range r.runs {
		runs = append(runs, run)
	}
	r.mu.Unlock()
	out := Stats{Since: r.started, WireBytes: r.wire.Load()}
	for _, run := range runs {
		st := run.st
		ls := LogStats{Name: st.info.Name, Operator: st.info.Operator, URL: st.info.URL, Protocol: st.info.Protocol,
			Next: st.next.Load(), Head: st.head.Load(), Entries: st.entries.Load(), Bytes: st.bytes.Load(), Requests: st.requests.Load(),
			Errors: st.errors.Load(), Retries: st.retries.Load(), ParseErrors: st.parseErrors.Load(), GapEntries: st.gapEntries.Load()}
		if ls.Head > ls.Next {
			ls.Lag = ls.Head - ls.Next
		}
		if t := st.lastEntry.Load(); t != 0 {
			ls.LastEntry = time.Unix(0, t).UTC()
		}
		st.mu.Lock()
		ls.LastError = st.lastError
		st.mu.Unlock()
		out.Logs = append(out.Logs, ls)
		out.Entries += ls.Entries
		out.Requests += ls.Requests
		out.Errors += ls.Errors
		out.Retries += ls.Retries
		out.ParseErrors += ls.ParseErrors
	}
	sort.Slice(out.Logs, func(i, j int) bool { return out.Logs[i].Name < out.Logs[j].Name })
	return out
}

// ---- the state file ----------------------------------------------------------------------------------------------------------

// stateStore keeps the next index of every log in a JSON file: {"version":1,"saved_at":"...","logs":{"<log URL>":{"next":123}}}.
// Positions of logs that are no longer running are kept as they were.
type stateStore struct {
	path string
	mu   sync.Mutex
	logs map[string]uint64
	last string // what was written last (skips identical writes)
}

type stateFile struct {
	Version int                    `json:"version"`
	SavedAt time.Time              `json:"saved_at"`
	Logs    map[string]stateRecord `json:"logs"`
}

type stateRecord struct {
	Next uint64 `json:"next"`
}

func newStateStore(path string) *stateStore {
	return &stateStore{path: path, logs: map[string]uint64{}}
}

func (s *stateStore) load() error {
	if s.path == "" {
		return nil
	}
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var f stateFile
	if err := json.Unmarshal(data, &f); err != nil {
		return err
	}
	s.mu.Lock()
	for url, rec := range f.Logs {
		s.logs[url] = rec.Next
	}
	s.mu.Unlock()
	return nil
}

func (s *stateStore) get(url string) (uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.logs[url]
	return v, ok
}

// saveLoop writes the state every ten seconds until ctx ends.
func (r *Reader) saveLoop(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.saveState()
		}
	}
}

// saveState merges the positions of the running logs into the stored ones and writes the file atomically (temp file, then rename).
func (r *Reader) saveState() {
	s := r.state
	if s.path == "" {
		return
	}
	r.mu.Lock()
	for url, run := range r.runs {
		if n := run.st.next.Load(); n > 0 {
			s.mu.Lock()
			s.logs[url] = n
			s.mu.Unlock()
		}
	}
	r.mu.Unlock()
	s.mu.Lock()
	f := stateFile{Version: 1, SavedAt: time.Now().UTC(), Logs: make(map[string]stateRecord, len(s.logs))}
	for url, n := range s.logs {
		f.Logs[url] = stateRecord{Next: n}
	}
	s.mu.Unlock()
	// skip the write when nothing but the time changed
	f2 := f
	f2.SavedAt = time.Time{}
	sig, _ := json.Marshal(f2)
	if string(sig) == s.last {
		return
	}
	data, err := json.Marshal(f)
	if err != nil {
		return
	}
	tmp := s.path + ".tmp"
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		r.logf("ctlog: the state file could not be written (%v)", err)
		return
	}
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		r.logf("ctlog: the state file could not be written (%v)", err)
		return
	}
	if err := os.Rename(tmp, s.path); err != nil {
		r.logf("ctlog: the state file could not be written (%v)", err)
		return
	}
	s.last = string(sig)
}
