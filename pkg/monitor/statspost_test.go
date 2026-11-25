package monitor

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestStatsPosterSignsLikeABatchAndSendsTheSnapshot(t *testing.T) {
	secret := []byte("post-secret")
	var got Snapshot
	var sigOK atomic.Bool
	done := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mac := hmac.New(sha256.New, secret)
		mac.Write([]byte(r.Header.Get("X-Argus-Timestamp") + "."))
		mac.Write(body)
		sigOK.Store(r.Header.Get("X-Argus-Signature") == "sha256="+hex.EncodeToString(mac.Sum(nil)))
		_ = json.Unmarshal(body, &got)
		w.WriteHeader(200)
		done <- struct{}{}
	}))
	defer srv.Close()
	p, err := NewStatsPoster(srv.URL, secret, nil)
	if err != nil {
		t.Fatal(err)
	}
	p.Send(Snapshot{Entries: 42, LagSeconds: 3.5, DroppedEntries: 7, Rules: 9})
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("no heartbeat arrived")
	}
	if !sigOK.Load() {
		t.Fatal("the signature does not match HMAC-SHA256(timestamp.body)")
	}
	if got.Entries != 42 || got.LagSeconds != 3.5 || got.DroppedEntries != 7 || got.Rules != 9 {
		t.Fatalf("the snapshot did not arrive intact: %+v", got)
	}
}

func TestStatsPosterNeverBlocksAndLogsAFailureOnce(t *testing.T) {
	release := make(chan struct{})
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		<-release
		w.WriteHeader(500)
	}))
	defer srv.Close()
	var mu sync.Mutex
	var logs []string
	p, _ := NewStatsPoster(srv.URL, []byte("s"), func(f string, a ...any) { mu.Lock(); logs = append(logs, f); mu.Unlock() })
	start := time.Now()
	for i := 0; i < 5; i++ {
		p.Send(Snapshot{}) // the first is in flight and blocked: the others must be skipped, not queued, and none may block
	}
	if time.Since(start) > time.Second {
		t.Fatal("Send blocked the caller")
	}
	time.Sleep(100 * time.Millisecond)
	close(release)
	time.Sleep(300 * time.Millisecond)
	if calls.Load() != 1 {
		t.Fatalf("snapshots while a post is running must be skipped: %d calls", calls.Load())
	}
	p.Send(Snapshot{})
	time.Sleep(300 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	failures := 0
	for _, l := range logs {
		if strings.Contains(l, "failed") {
			failures++
		}
	}
	if failures != 1 {
		t.Fatalf("a failure that goes on is logged once, got %d: %v", failures, logs)
	}
}

func TestStatsPosterRefusesAPlainHTTPAddressThatIsNotLocal(t *testing.T) {
	if _, err := NewStatsPoster("http://platform.example/ct/heartbeat", []byte("s"), nil); err == nil {
		t.Fatal("plain http to a remote host must be refused (the secret would travel in the clear)")
	}
	if _, err := NewStatsPoster("https://platform.example/ct/heartbeat", []byte("s"), nil); err != nil {
		t.Fatalf("https must be accepted: %v", err)
	}
}
