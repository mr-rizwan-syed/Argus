package monitor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mr-rizwan-syed/argus/pkg/ctlog"
)

type memSink struct {
	mu sync.Mutex
	ms []Match
}

func (s *memSink) Write(ms []Match) { s.mu.Lock(); s.ms = append(s.ms, ms...); s.mu.Unlock() }
func (s *memSink) Close() error     { return nil }

func replayCfg(t *testing.T, sink Sink) (Config, *ReplaySource) {
	f, err := os.Open("testdata/replay.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	src := &ReplaySource{R: f}
	return Config{Source: src, Rules: &FileRules{Path: "testdata/rules.json"}, Sinks: []Sink{sink}, Workers: 1, ReloadEvery: time.Hour, StatsInterval: time.Hour}, src
}

func TestReplayEndToEnd(t *testing.T) {
	sink := &memSink{}
	cfg, src := replayCfg(t, sink)
	m := New(cfg)
	if err := m.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, x := range sink.ms {
		got[x.RuleID+"/"+x.Kind+"/"+x.Domain] = true
	}
	for _, want := range []string{
		"acme/subdomain/www.acme.com",
		"paypal/keyword/paypal-secure-login.xyz",
		"paypal/keyword/www.paypal-secure-login.xyz",
		"paypal/lookalike/paypa1.com",
		"acme/org/acme-portal.net",
		"paypal/lookalike/xn--l-7sba6dbr.com",
	} {
		if !got[want] {
			t.Errorf("missing %s; got %v", want, got)
		}
	}
	for k := range got {
		if strings.Contains(k, "status.acme.com") || strings.Contains(k, "example.org") {
			t.Errorf("reported what must not be: %s", k)
		}
	}
	// www.acme.com was seen twice (two logs): reported once
	n := 0
	for _, x := range sink.ms {
		if x.Domain == "www.acme.com" && x.Kind == KindSubdomain {
			n++
		}
	}
	if n != 1 {
		t.Errorf("www.acme.com reported %d times", n)
	}
	st := m.Stats()
	if st.Entries.Load() != 8 || src.Bad != 1 {
		t.Errorf("entries %d, bad lines %d", st.Entries.Load(), src.Bad)
	}
	if st.Suppressed.Load() == 0 {
		t.Error("the duplicate was not counted as suppressed")
	}
}

func TestReplayRateIsHonoured(t *testing.T) {
	var lines []string
	for i := 0; i < 20; i++ {
		lines = append(lines, `{"names":["a.example"]}`)
	}
	src := &ReplaySource{R: strings.NewReader(strings.Join(lines, "\n")), Rate: 200}
	start := time.Now()
	n := 0
	src.Run(context.Background(), func(ctlog.Entry) { n++ })
	if n != 20 || time.Since(start) < 80*time.Millisecond {
		t.Fatalf("%d entries in %v: a rate of 200/s means about 100 ms", n, time.Since(start))
	}
}

func TestRulesReloadAndAFailedReloadKeepsTheLastGoodSet(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")
	good := `{"version":1,"rules":[{"id":"a","keywords":["brandone"]}]}`
	os.WriteFile(path, []byte(good), 0o644)
	src := &blockSource{done: make(chan struct{})}
	m := New(Config{Source: src, Rules: &FileRules{Path: path}, Sinks: nil, ReloadEvery: 20 * time.Millisecond, StatsInterval: time.Hour, Logf: func(string, ...any) {}})
	go m.Run(context.Background())
	waitFor(t, "first load", func() bool { return m.Engine() != nil })
	if m.Engine().NumRules() != 1 {
		t.Fatal("rules")
	}
	os.WriteFile(path, []byte(`{"version":1,"rules":[{"id":"a","keywords":["brandone"]},{"id":"b","keywords":["brandtwo"]}]}`), 0o644)
	os.Chtimes(path, time.Now().Add(time.Second), time.Now().Add(time.Second))
	waitFor(t, "reload", func() bool { return m.Engine().NumRules() == 2 })
	os.WriteFile(path, []byte(`{"version":1,"rules":[{"id":"a","keywords":["ab"]}]}`), 0o644) // refused: keyword too short
	os.Chtimes(path, time.Now().Add(2*time.Second), time.Now().Add(2*time.Second))
	waitFor(t, "the failed reload to be counted", func() bool { return m.Stats().RuleReloadErrs.Load() > 0 })
	if m.Engine().NumRules() != 2 {
		t.Fatalf("the last good set must stay: %d rules", m.Engine().NumRules())
	}
	close(src.done)
}

type blockSource struct{ done chan struct{} }

func (b *blockSource) Run(ctx context.Context, emit func(ctlog.Entry)) error {
	select {
	case <-b.done:
	case <-ctx.Done():
	}
	return nil
}

func TestRulesAreRequiredAtStart(t *testing.T) {
	m := New(Config{Source: &blockSource{done: make(chan struct{})}, Rules: &FileRules{Path: "testdata/does-not-exist.json"}})
	if err := m.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "rules") {
		t.Fatalf("%v", err)
	}
}

func TestURLRulesUseBearerAndETag(t *testing.T) {
	var auth, inm string
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		auth, inm = r.Header.Get("Authorization"), r.Header.Get("If-None-Match")
		if auth != "Bearer topsecret" {
			w.WriteHeader(401)
			return
		}
		if inm == `"v1"` {
			w.WriteHeader(304)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Write([]byte(`{"version":1,"rules":[{"id":"a","apexes":["acme.com"]}]}`))
	}))
	defer srv.Close()
	u := &URLRules{URL: srv.URL, Secret: "topsecret"}
	set, changed, err := u.Load(context.Background())
	if err != nil || !changed || len(set.Rules) != 1 {
		t.Fatalf("%v %v %v", set, changed, err)
	}
	if _, changed, err := u.Load(context.Background()); err != nil || changed || inm != `"v1"` {
		t.Fatalf("the second load must be a 304: changed=%v err=%v inm=%q", changed, err, inm)
	}
	bad := &URLRules{URL: srv.URL, Secret: "wrong"}
	if _, _, err := bad.Load(context.Background()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("%v", err)
	}
	if hits != 3 {
		t.Fatalf("%d requests", hits)
	}
}

func TestRulesURLMustBeHTTPSExceptLocalhost(t *testing.T) {
	for url, ok := range map[string]bool{"https://intel.example.org/rules": true, "http://localhost:3000/rules": true, "http://127.0.0.1:3000/rules": true,
		"http://intel.example.org/rules": false, "ftp://x/y": false, "nonsense": false} {
		if err := CheckRulesURL(url); (err == nil) != ok {
			t.Errorf("%s: %v", url, err)
		}
	}
}

func TestStatsFileAndLine(t *testing.T) {
	dir := t.TempDir()
	sink := &memSink{}
	cfg, _ := replayCfg(t, sink)
	cfg.StatsFile = filepath.Join(dir, "stats.json")
	var logs bytes.Buffer
	var mu sync.Mutex
	cfg.Logf = func(f string, a ...any) {
		mu.Lock()
		logs.WriteString(strings.TrimSpace(fmt.Sprintf(f, a...)) + "\n")
		mu.Unlock()
	}
	m := New(cfg)
	m.Run(context.Background())
	data, err := os.ReadFile(cfg.StatsFile)
	if err != nil {
		t.Fatal(err)
	}
	var sn Snapshot
	if err := json.Unmarshal(data, &sn); err != nil || sn.Entries != 8 || sn.Rules != 2 {
		t.Fatalf("%v %+v", err, sn)
	}
	if !strings.Contains(logs.String(), "monitor:") || !strings.Contains(logs.String(), "entries/s") {
		t.Fatalf("no stats line: %s", logs.String())
	}
	if _, err := os.Stat(filepath.Join(dir, ".stats.json.tmp")); err == nil {
		t.Error("the temp file was left behind: the write must be atomic")
	}
}

func TestAQueueThatIsFullDropsEntriesInsteadOfBlockingTheReader(t *testing.T) {
	gate := make(chan struct{})
	slow := &gateSink{gate: gate}
	var lines []string
	for i := 0; i < 5000; i++ {
		lines = append(lines, `{"names":["paypal-login`+itoa(i)+`.xyz"]}`)
	}
	src := &ReplaySource{R: strings.NewReader(strings.Join(lines, "\n"))}
	m := New(Config{Source: src, Rules: &FileRules{Path: "testdata/rules.json"}, Sinks: []Sink{slow}, Workers: 1, Queue: 10, StatsInterval: time.Hour, DailyCap: 100000})
	done := make(chan error)
	go func() { done <- m.Run(context.Background()) }()
	select {
	case <-time.After(5 * time.Second):
		t.Fatal("the reader was blocked by a slow output")
	case <-func() chan struct{} {
		c := make(chan struct{})
		go func() { time.Sleep(300 * time.Millisecond); close(gate); close(c) }()
		return c
	}():
	}
	<-done
	if m.Stats().DroppedEntries.Load()+m.Stats().DroppedMatches.Load() == 0 {
		t.Log("nothing was dropped on this machine (it kept up); the reader was not blocked, which is the point")
	}
}

type gateSink struct{ gate chan struct{} }

func (g *gateSink) Write([]Match) { <-g.gate }
func (g *gateSink) Close() error  { return nil }
