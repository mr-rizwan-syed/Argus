package monitor

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type recv struct {
	mu      sync.Mutex
	batches [][]Match
	fail    int // answer 503 this many times first
	status  int // when set, answer this status for every request
	reqs    int
	badSig  int
	secret  []byte
}

func (r *recv) handler(w http.ResponseWriter, req *http.Request) {
	body, _ := io.ReadAll(req.Body)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reqs++
	ts := req.Header.Get("X-Argus-Timestamp")
	mac := hmac.New(sha256.New, r.secret)
	mac.Write([]byte(ts + "." + string(body)))
	if req.Header.Get("X-Argus-Signature") != "sha256="+hex.EncodeToString(mac.Sum(nil)) {
		r.badSig++
	}
	if _, err := strconv.ParseInt(ts, 10, 64); err != nil {
		r.badSig++
	}
	if r.status != 0 {
		w.WriteHeader(r.status)
		return
	}
	if r.fail > 0 {
		r.fail--
		w.WriteHeader(503)
		return
	}
	var b []Match
	if err := json.Unmarshal(body, &b); err != nil {
		w.WriteHeader(400)
		return
	}
	r.batches = append(r.batches, b)
}

func (r *recv) domains() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, b := range r.batches {
		for _, m := range b {
			out = append(out, m.Domain)
		}
	}
	return out
}

func newMatches(prefix string, n int) []Match {
	out := make([]Match, n)
	for i := range out {
		out[i] = Match{RuleID: "r", Kind: KindKeyword, Domain: prefix + strconv.Itoa(i) + ".example", Score: 70, Seen: time.Now()}
	}
	return out
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 400; i++ {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func postCfg(url string, secret []byte, spool string, st *Stats) PostConfig {
	return PostConfig{URL: url, Secret: secret, SpoolDir: spool, BatchMax: 5, BatchAge: 20 * time.Millisecond, Retries: 2, Backoff: time.Millisecond,
		Drain: 20 * time.Millisecond, Stats: st}
}

func TestPostDeliversSignedBatches(t *testing.T) {
	r := &recv{secret: []byte("s3cret")}
	srv := httptest.NewServer(http.HandlerFunc(r.handler))
	defer srv.Close()
	st := &Stats{}
	p, err := NewPostSink(postCfg(srv.URL, r.secret, t.TempDir(), st))
	if err != nil {
		t.Fatal(err)
	}
	p.Write(newMatches("a", 12))
	waitFor(t, "delivery", func() bool { return len(r.domains()) == 12 })
	p.Close()
	if r.badSig != 0 {
		t.Fatalf("%d requests had a bad signature or timestamp", r.badSig)
	}
	if got := r.domains(); got[0] != "a0.example" || got[11] != "a11.example" {
		t.Fatalf("order: %v", got)
	}
	for _, b := range r.batches {
		if len(b) > 5 {
			t.Fatalf("batch of %d", len(b))
		}
	}
	if st.Delivered.Load() != 12 || st.Spooled.Load() != 0 {
		t.Fatalf("delivered %d spooled %d", st.Delivered.Load(), st.Spooled.Load())
	}
}

func TestAWrongSecretIsDetectedByTheReceiver(t *testing.T) {
	r := &recv{secret: []byte("right")}
	srv := httptest.NewServer(http.HandlerFunc(r.handler))
	defer srv.Close()
	p, _ := NewPostSink(postCfg(srv.URL, []byte("wrong"), t.TempDir(), &Stats{}))
	p.Write(newMatches("a", 1))
	waitFor(t, "a request", func() bool { r.mu.Lock(); defer r.mu.Unlock(); return r.reqs > 0 })
	p.Close()
	if r.badSig == 0 {
		t.Fatal("the signature must depend on the secret")
	}
}

func TestAnOutageSpoolsAndTheBacklogIsResentInOrder(t *testing.T) {
	r := &recv{secret: []byte("k"), status: 503}
	srv := httptest.NewServer(http.HandlerFunc(r.handler))
	defer srv.Close()
	spool := t.TempDir()
	st := &Stats{}
	p, _ := NewPostSink(postCfg(srv.URL, r.secret, spool, st))
	p.Write(newMatches("a", 5))
	waitFor(t, "first batch spooled", func() bool { return p.SpoolLen() == 1 })
	p.Write(newMatches("b", 5))
	p.Write(newMatches("c", 5))
	waitFor(t, "three batches spooled", func() bool { return p.SpoolLen() == 3 })
	if st.Spooled.Load() != 15 || st.PostFailures.Load() == 0 {
		t.Fatalf("spooled %d failures %d", st.Spooled.Load(), st.PostFailures.Load())
	}
	files, _ := os.ReadDir(spool)
	if len(files) != 3 {
		t.Fatalf("%d files on disk", len(files))
	}
	// the platform comes back; a NEW batch written now must not overtake the backlog
	r.mu.Lock()
	r.status = 0
	r.mu.Unlock()
	p.Write(newMatches("d", 5))
	waitFor(t, "everything delivered", func() bool { return len(r.domains()) == 20 && p.SpoolLen() == 0 })
	p.Close()
	got := r.domains()
	var order []string
	for _, d := range got {
		order = append(order, d[:1])
	}
	if strings.Join(order, "") != strings.Repeat("a", 5)+strings.Repeat("b", 5)+strings.Repeat("c", 5)+strings.Repeat("d", 5) {
		t.Fatalf("delivery order: %v", order)
	}
	if files, _ := os.ReadDir(spool); len(files) != 0 {
		t.Fatalf("the spool should be empty, %d files left", len(files))
	}
	if st.Delivered.Load() != 20 {
		t.Fatalf("delivered %d", st.Delivered.Load())
	}
}

func TestTheSpoolSurvivesARestart(t *testing.T) {
	r := &recv{secret: []byte("k"), status: 503}
	srv := httptest.NewServer(http.HandlerFunc(r.handler))
	defer srv.Close()
	spool := t.TempDir()
	p, _ := NewPostSink(postCfg(srv.URL, r.secret, spool, &Stats{}))
	p.Write(newMatches("a", 3))
	waitFor(t, "spooled", func() bool { return p.SpoolLen() == 1 })
	p.Close()
	r.mu.Lock()
	r.status = 0
	r.mu.Unlock()
	st := &Stats{}
	p2, _ := NewPostSink(postCfg(srv.URL, r.secret, spool, st))
	if p2.SpoolLen() != 1 {
		t.Fatalf("the new process did not find the spool: %d", p2.SpoolLen())
	}
	waitFor(t, "resent after the restart", func() bool { return len(r.domains()) == 3 })
	p2.Close()
	if st.Delivered.Load() != 3 {
		t.Fatalf("delivered %d", st.Delivered.Load())
	}
}

func TestACloseWhileTheOutageLastsSpoolsTheRest(t *testing.T) {
	r := &recv{secret: []byte("k"), status: 503}
	srv := httptest.NewServer(http.HandlerFunc(r.handler))
	defer srv.Close()
	spool := t.TempDir()
	cfg := postCfg(srv.URL, r.secret, spool, &Stats{})
	cfg.BatchAge = time.Hour
	cfg.BatchMax = 1000
	p, _ := NewPostSink(cfg)
	p.Write(newMatches("a", 4))
	time.Sleep(30 * time.Millisecond)
	p.Close()
	files, _ := os.ReadDir(spool)
	if len(files) != 1 {
		t.Fatalf("matches queued at shutdown must reach the spool, found %d files", len(files))
	}
}

func TestTheSpoolIsBoundedAndTheOldestIsDroppedAndCounted(t *testing.T) {
	r := &recv{secret: []byte("k"), status: 503}
	srv := httptest.NewServer(http.HandlerFunc(r.handler))
	defer srv.Close()
	st := &Stats{}
	cfg := postCfg(srv.URL, r.secret, t.TempDir(), st)
	cfg.SpoolMax = 2500
	p, _ := NewPostSink(cfg)
	for i := 0; i < 6; i++ {
		p.Write(newMatches("x"+strconv.Itoa(i)+"-", 5))
		time.Sleep(60 * time.Millisecond)
	}
	waitFor(t, "spool overflow", func() bool { return st.SpoolDropped.Load() > 0 })
	p.Close()
	if st.SpoolDropped.Load()%5 != 0 {
		t.Fatalf("dropped %d matches: whole batches only", st.SpoolDropped.Load())
	}
	var size int64
	files, _ := os.ReadDir(cfg.SpoolDir)
	for _, f := range files {
		i, _ := f.Info()
		size += i.Size()
	}
	if size > 2500+1500 { // the newest batch may sit above the limit by its own size
		t.Fatalf("spool is %d bytes", size)
	}
}

func TestARefusalForGoodIsDroppedNotSpooled(t *testing.T) {
	r := &recv{secret: []byte("k"), status: 400}
	srv := httptest.NewServer(http.HandlerFunc(r.handler))
	defer srv.Close()
	st := &Stats{}
	p, _ := NewPostSink(postCfg(srv.URL, r.secret, t.TempDir(), st))
	p.Write(newMatches("a", 5))
	waitFor(t, "rejection", func() bool { return st.Rejected.Load() == 5 })
	p.Close()
	if p.SpoolLen() != 0 || st.Spooled.Load() != 0 {
		t.Fatal("a body the platform will never accept must not be retried for ever")
	}
}

func TestAFullQueueDropsAndNeverBlocks(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-block }))
	defer srv.Close()
	defer close(block)
	st := &Stats{}
	cfg := postCfg(srv.URL, []byte("k"), "", st)
	cfg.Queue = 10
	cfg.BatchMax = 2
	cfg.Client = &http.Client{Timeout: 5 * time.Second}
	p, _ := NewPostSink(cfg)
	done := make(chan bool)
	go func() { p.Write(newMatches("a", 500)); done <- true }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Write blocked")
	}
	if st.DroppedMatches.Load() == 0 {
		t.Fatal("the overflow was not counted")
	}
}

func TestNoSecretOrURLIsRefused(t *testing.T) {
	if _, err := NewPostSink(PostConfig{URL: "http://x"}); err == nil {
		t.Error("no secret")
	}
	if _, err := NewPostSink(PostConfig{Secret: []byte("k")}); err == nil {
		t.Error("no url")
	}
}

func TestFileSinkRotates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.jsonl")
	s, err := NewFileSink(path)
	if err != nil {
		t.Fatal(err)
	}
	s.MaxBytes = 600
	for i := 0; i < 40; i++ {
		s.Write(newMatches("h"+strconv.Itoa(i)+"-", 1))
	}
	s.Close()
	for _, n := range []string{"out.jsonl", "out.jsonl.1", "out.jsonl.2", "out.jsonl.3"} {
		if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
			t.Errorf("missing %s", n)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "out.jsonl.4")); err == nil {
		t.Error("only three rotated files are kept")
	}
	data, _ := os.ReadFile(path)
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var m Match
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("a line is not JSON: %q", line)
		}
	}
	// appends to an existing file
	s2, _ := NewFileSink(path)
	s2.Write(newMatches("z", 1))
	s2.Close()
	after, _ := os.ReadFile(path)
	if len(after) <= len(data) {
		t.Error("did not append")
	}
}
