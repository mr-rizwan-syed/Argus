package ctlog

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// writeList writes a log list with the given RFC 6962 and static logs ("usable") plus one retired and one readonly log that must be ignored.
func writeList(t *testing.T, dir string, rfc, static []string) string {
	t.Helper()
	type logT = map[string]any
	var logs, tiled []logT
	for i, u := range rfc {
		logs = append(logs, logT{"description": fmt.Sprintf("Rfc %d", i), "url": u, "state": map[string]any{"usable": map[string]any{"timestamp": "2026-01-01T00:00:00Z"}}})
	}
	for i, u := range static {
		tiled = append(tiled, logT{"description": fmt.Sprintf("Static %d", i), "monitoring_url": u, "submission_url": u + "sub/", "state": map[string]any{"qualified": map[string]any{}}})
	}
	logs = append(logs, logT{"description": "Retired", "url": "https://retired.example/", "state": map[string]any{"retired": map[string]any{}}},
		logT{"description": "Readonly", "url": "https://readonly.example/", "state": map[string]any{"readonly": map[string]any{}}})
	list := map[string]any{"version": "1", "operators": []any{
		map[string]any{"name": "OpA", "logs": logs, "tiled_logs": tiled},
	}}
	b, _ := json.Marshal(list)
	p := filepath.Join(dir, "list.json")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func fastOptions(list, state string) Options {
	return Options{LogListFile: list, StatePath: state, PollInterval: 20 * time.Millisecond, MaxPollInterval: 40 * time.Millisecond, PartialWait: 30 * time.Millisecond}
}

// runReader runs a Reader in the background and returns a stop function that waits for it.
func runReader(t *testing.T, o Options, col *collector) (*Reader, func()) {
	t.Helper()
	r, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	r.http.backoff = time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx, col.emit) }()
	return r, func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Run: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Run did not stop")
		}
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestParseLogListKeepsOnlyLogsThatAcceptCertificates(t *testing.T) {
	data, err := os.ReadFile("testdata/loglist_sample.json")
	if err != nil {
		t.Fatal(err)
	}
	logs, err := ParseLogList(data)
	if err != nil {
		t.Fatal(err)
	}
	var rfc, static int
	for _, l := range logs {
		if l.State != "usable" && l.State != "qualified" {
			t.Errorf("%s is %s", l.Name, l.State)
		}
		if !strings.HasSuffix(l.URL, "/") || l.Operator == "" || l.Name == "" {
			t.Errorf("%+v", l)
		}
		if l.Protocol == ProtoStatic {
			static++
		} else {
			rfc++
		}
	}
	if rfc == 0 || static == 0 {
		t.Errorf("rfc=%d static=%d: the sample has both kinds", rfc, static)
	}
	for _, l := range logs {
		if strings.Contains(l.Name, "Argon2026h2") {
			t.Errorf("a readonly log was kept: %+v", l)
		}
	}
	if _, err := ParseLogList([]byte(`{"operators":[]}`)); err == nil {
		t.Error("an empty list must be an error")
	}
	if _, err := ParseLogList([]byte(`not json`)); err == nil {
		t.Error("garbage must be an error")
	}
}

func TestFilters(t *testing.T) {
	logs := []LogInfo{{Name: "a", Operator: "Google", URL: "https://g.example/a/"}, {Name: "b", Operator: "Sectigo", URL: "https://s.example/b/"}, {Name: "c", Operator: "Let's Encrypt", URL: "https://le.example/c/"}}
	names := func(o Options) string {
		var out []string
		for _, l := range filterLogs(logs, &o) {
			out = append(out, l.Name)
		}
		return strings.Join(out, ",")
	}
	if got := names(Options{}); got != "a,b,c" {
		t.Error(got)
	}
	if got := names(Options{ExcludeOperators: []string{"google"}}); got != "b,c" {
		t.Error(got)
	}
	if got := names(Options{IncludeOperators: []string{"SECTIGO"}}); got != "b" {
		t.Error(got)
	}
	if got := names(Options{ExcludeURLs: []string{"https://le.example/c"}}); got != "a,b" {
		t.Error(got)
	}
	if got := names(Options{IncludeURLs: []string{"https://g.example/a/"}, IncludeOperators: []string{"Sectigo"}}); got != "a,b" {
		t.Error(got)
	}
	if got := names(Options{IncludeOperators: []string{"Google"}, ExcludeURLs: []string{"https://g.example/a/"}}); got != "" {
		t.Error(got)
	}
}

func TestReaderStartsAtTheHeadAndReadsNewEntries(t *testing.T) {
	dir := t.TempDir()
	rfc, static := newFakeRFC(t, 500), newFakeStatic(t, 700)
	list := writeList(t, dir, []string{rfc.url()}, []string{static.url()})
	var col collector
	r, stop := runReader(t, fastOptions(list, filepath.Join(dir, "state.json")), &col)
	defer stop()
	waitFor(t, "both logs positioned", func() bool {
		s := r.Stats()
		return len(s.Logs) == 2 && s.Logs[0].Head == 500 && s.Logs[1].Head == 700
	})
	if n := len(col.all()); n != 0 {
		t.Fatalf("%d old entries were read: only new certificates are wanted", n)
	}
	rfc.add(20)
	static.add(300)
	waitFor(t, "the new entries", func() bool { return len(col.all()) == 320 })
	seen := map[string]int{}
	for _, e := range col.all() {
		seen[e.Log]++
		if e.Index < 500 {
			t.Fatalf("an old entry: %+v", e)
		}
	}
	if seen["Rfc 0"] != 20 || seen["Static 0"] != 300 {
		t.Errorf("%v", seen)
	}
	st := r.Stats()
	if st.Entries != 320 || st.Requests == 0 || st.WireBytes == 0 {
		t.Errorf("stats %+v", st)
	}
	for _, l := range st.Logs {
		if l.Lag != 0 || l.Operator != "OpA" {
			t.Errorf("%+v", l)
		}
	}
}

func TestBackfillReadsSomeOlderEntries(t *testing.T) {
	dir := t.TempDir()
	rfc := newFakeRFC(t, 200)
	o := fastOptions(writeList(t, dir, []string{rfc.url()}, nil), "")
	o.Backfill = 50
	var col collector
	_, stop := runReader(t, o, &col)
	defer stop()
	waitFor(t, "the backfill", func() bool { return len(col.all()) == 50 })
	if col.all()[0].Index != 150 {
		t.Errorf("first index %d", col.all()[0].Index)
	}
}

func TestStateFileIsWrittenAndResumedExactly(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state.json")
	rfc := newFakeRFC(t, 100)
	list := writeList(t, dir, []string{rfc.url()}, nil)
	var col collector
	r, stop := runReader(t, fastOptions(list, state), &col)
	waitFor(t, "positioned at the head", func() bool { return len(r.Stats().Logs) == 1 && r.Stats().Logs[0].Next == 100 })
	rfc.add(30)
	waitFor(t, "30 entries", func() bool { return len(col.all()) == 30 })
	waitFor(t, "position stored", func() bool { return r.Stats().Logs[0].Next == 130 })
	stop() // writes the state on the way out
	data, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	var f stateFile
	if err := json.Unmarshal(data, &f); err != nil || f.Version != 1 || f.Logs[rfc.url()].Next != 130 {
		t.Fatalf("state file: %s (%v)", data, err)
	}
	if _, err := os.Stat(state + ".tmp"); err == nil {
		t.Error("a temp file was left behind")
	}
	// entries logged while the monitor was down are read after the restart, nothing is missed or repeated
	rfc.add(25)
	var col2 collector
	_, stop2 := runReader(t, fastOptions(list, state), &col2)
	defer stop2()
	waitFor(t, "the 25 entries logged during the downtime", func() bool { return len(col2.all()) == 25 })
	if got := col2.all()[0].Index; got != 130 {
		t.Errorf("resumed at %d, want 130", got)
	}
}

func TestSavedPositionTooFarBehindJumpsToTheHead(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state.json")
	rfc := newFakeRFC(t, 1000)
	list := writeList(t, dir, []string{rfc.url()}, nil)
	data, _ := json.Marshal(stateFile{Version: 1, Logs: map[string]stateRecord{rfc.url(): {Next: 100}}})
	os.WriteFile(state, data, 0o600)
	var msgs []string
	var mu sync.Mutex
	o := fastOptions(list, state)
	o.MaxLag = 500
	o.Logger = func(s string) { mu.Lock(); msgs = append(msgs, s); mu.Unlock() }
	var col collector
	r, stop := runReader(t, o, &col)
	defer stop()
	waitFor(t, "positioned", func() bool { return r.Stats().Logs != nil && r.Stats().Logs[0].Next == 1000 })
	time.Sleep(100 * time.Millisecond)
	if len(col.all()) != 0 {
		t.Errorf("%d entries of backlog were downloaded", len(col.all()))
	}
	if got := r.Stats().Logs[0].GapEntries; got != 900 {
		t.Errorf("gap %d, want 900", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(strings.Join(msgs, "\n"), "skipping 900 entries") {
		t.Errorf("the gap was not logged: %v", msgs)
	}
}

func TestSavedPositionWithinTheLagIsKept(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state.json")
	rfc := newFakeRFC(t, 1000)
	list := writeList(t, dir, []string{rfc.url()}, nil)
	data, _ := json.Marshal(stateFile{Version: 1, Logs: map[string]stateRecord{rfc.url(): {Next: 900}}})
	os.WriteFile(state, data, 0o600)
	var col collector
	_, stop := runReader(t, fastOptions(list, state), &col)
	defer stop()
	waitFor(t, "the 100 entries since the saved position", func() bool { return len(col.all()) == 100 })
	if col.all()[0].Index != 900 {
		t.Errorf("first %d", col.all()[0].Index)
	}
}

func TestLogResetRestartsAtTheNewHead(t *testing.T) {
	dir := t.TempDir()
	rfc := newFakeRFC(t, 300)
	var col collector
	var mu sync.Mutex
	var msgs []string
	o := fastOptions(writeList(t, dir, []string{rfc.url()}, nil), "")
	o.Logger = func(s string) { mu.Lock(); msgs = append(msgs, s); mu.Unlock() }
	r, stop := runReader(t, o, &col)
	defer stop()
	waitFor(t, "positioned at 300", func() bool { return r.Stats().Logs != nil && r.Stats().Logs[0].Next == 300 })
	rfc.mu.Lock()
	rfc.leaves = rfc.leaves[:50] // the log shrank: it was reset
	rfc.mu.Unlock()
	waitFor(t, "restart at the new head", func() bool { return r.Stats().Logs[0].Next == 50 })
	rfc.add(5)
	waitFor(t, "entries after the reset", func() bool { return len(col.all()) == 5 })
	if col.all()[0].Index != 50 {
		t.Errorf("first %d", col.all()[0].Index)
	}
	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(strings.Join(msgs, "\n"), "went back") {
		t.Errorf("the reset was not logged: %v", msgs)
	}
}

// A log behind a cache serves an old tree head while get-entries already has newer entries (seen live on Sectigo's logs). The position
// passing the head is not a reset: nothing may be read twice.
func TestOutOfDateTreeHeadIsNotAReset(t *testing.T) {
	dir := t.TempDir()
	rfc := newFakeRFC(t, 300)
	rfc.headSize = 300 // the cached tree head never moves
	var col collector
	r, stop := runReader(t, fastOptions(writeList(t, dir, []string{rfc.url()}, nil), ""), &col)
	defer stop()
	waitFor(t, "positioned at 300", func() bool { return r.Stats().Logs != nil && r.Stats().Logs[0].Next == 300 })
	rfc.add(600)
	waitFor(t, "the 600 new entries", func() bool { return len(col.all()) >= 600 })
	time.Sleep(300 * time.Millisecond) // several polls with head < next
	all := col.all()
	if len(all) != 600 {
		t.Fatalf("%d entries delivered for 600 new ones", len(all))
	}
	seen := map[uint64]bool{}
	for _, e := range all {
		if seen[e.Index] {
			t.Fatalf("index %d delivered twice", e.Index)
		}
		seen[e.Index] = true
	}
	if n := r.Stats().Logs[0].Next; n != 900 {
		t.Errorf("next %d, want 900", n)
	}
}

func TestLogListRefreshAddsAndRemovesLogs(t *testing.T) {
	dir := t.TempDir()
	a, b := newFakeRFC(t, 10), newFakeRFC(t, 10)
	list := writeList(t, dir, []string{a.url()}, nil)
	o := fastOptions(list, "")
	o.ListRefresh = 40 * time.Millisecond
	var col collector
	r, stop := runReader(t, o, &col)
	defer stop()
	waitFor(t, "one log", func() bool { return len(r.Stats().Logs) == 1 })
	writeList(t, dir, []string{b.url()}, nil) // a leaves, b joins
	waitFor(t, "the list change", func() bool { s := r.Stats(); return len(s.Logs) == 1 && s.Logs[0].URL == b.url() })
	waitFor(t, "the new log positioned at its head", func() bool { s := r.Stats(); return len(s.Logs) == 1 && s.Logs[0].Head == 10 && s.Logs[0].Next == 10 })
	b.add(7)
	waitFor(t, "entries from the new log", func() bool { return len(col.all()) == 7 })
	// a broken refresh keeps what is running
	os.WriteFile(list, []byte("not json"), 0o644)
	time.Sleep(150 * time.Millisecond)
	if s := r.Stats(); len(s.Logs) != 1 {
		t.Errorf("a failed refresh changed the logs: %+v", s.Logs)
	}
}

func TestExcludedOperatorsAreNotRead(t *testing.T) {
	dir := t.TempDir()
	a := newFakeRFC(t, 10)
	o := fastOptions(writeList(t, dir, []string{a.url()}, nil), "")
	o.ExcludeOperators = []string{"opa"}
	r, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	list, err := r.loadList(context.Background())
	if err != nil || len(list) != 0 {
		t.Fatalf("%v %v", list, err)
	}
}

func TestAFailingLogDoesNotStopTheOthers(t *testing.T) {
	dir := t.TempDir()
	good := newFakeRFC(t, 10)
	bad := newFakeRFC(t, 10)
	bad.srv.Close() // connection refused from the start
	var col collector
	o := fastOptions(writeList(t, dir, []string{good.url(), bad.url()}, nil), "")
	r, stop := runReader(t, o, &col)
	defer stop()
	waitFor(t, "the good log positioned", func() bool {
		for _, l := range r.Stats().Logs {
			if l.URL == good.url() && l.Head == 10 {
				return true
			}
		}
		return false
	})
	good.add(5)
	waitFor(t, "entries from the good log", func() bool { return len(col.all()) == 5 })
	waitFor(t, "the failing log's error in the stats", func() bool {
		for _, l := range r.Stats().Logs {
			if l.URL == bad.url() && l.LastError != "" {
				return true
			}
		}
		return false
	})
}

func TestNewRejectsBadOptions(t *testing.T) {
	if _, err := New(Options{LogListURL: "ftp://nope"}); err == nil {
		t.Error("a non-http list URL must be rejected")
	}
	if _, err := New(Options{}); err != nil {
		t.Errorf("defaults must be valid: %v", err)
	}
}

func TestEntriesWithNothingToMatchAreDropped(t *testing.T) {
	r, _ := testReader(t, Options{})
	st := newStats("u/", ProtoRFC6962)
	var col collector
	r.deliver(st, Entry{Names: nil}, col.emit)
	r.deliver(st, Entry{SubjectO: "Only Org"}, col.emit)
	r.deliver(st, Entry{Names: []string{"a.example.com"}}, col.emit)
	if len(col.all()) != 2 || st.entries.Load() != 2 {
		t.Errorf("%d delivered", len(col.all()))
	}
}
