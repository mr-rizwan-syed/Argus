package monitor

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"
)

// StatsPoster sends each statistics snapshot to the platform (a heartbeat: "I am alive, this is how far behind the logs I am, this is what I dropped"), signed like
// a batch of matches (X-Argus-Timestamp, X-Argus-Signature: sha256=<hex HMAC-SHA256 of timestamp + "." + body>). It is best effort and never blocks the monitor: a
// snapshot is skipped while the previous post is still running, and a failure is logged once when it starts and once when it ends, not every minute.
type StatsPoster struct {
	url    string
	secret []byte
	client *http.Client
	logf   func(format string, args ...any)
	busy   atomic.Bool
	failed atomic.Bool
}

// NewStatsPoster prepares a poster. The URL must pass CheckRulesURL (https, or plain http only for localhost).
func NewStatsPoster(url string, secret []byte, logf func(string, ...any)) (*StatsPoster, error) {
	if err := CheckRulesURL(url); err != nil {
		return nil, err
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &StatsPoster{url: url, secret: secret, client: &http.Client{Timeout: 10 * time.Second}, logf: logf}, nil
}

// Send posts the snapshot in the background.
func (p *StatsPoster) Send(sn Snapshot) {
	if !p.busy.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer p.busy.Store(false)
		err := p.post(sn)
		switch {
		case err != nil && p.failed.CompareAndSwap(false, true):
			p.logf("heartbeat to the platform failed (further failures are not logged until it works again): %v", err)
		case err == nil && p.failed.CompareAndSwap(true, false):
			p.logf("heartbeat to the platform works again")
		}
	}()
}

func (p *StatsPoster) post(sn Snapshot) error {
	body, err := json.Marshal(sn)
	if err != nil {
		return err
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, p.secret)
	mac.Write([]byte(ts + "."))
	mac.Write(body)
	req, err := http.NewRequest(http.MethodPost, p.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "argus-monitor/1")
	req.Header.Set("X-Argus-Timestamp", ts)
	req.Header.Set("X-Argus-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &httpStatusError{resp.StatusCode}
	}
	return nil
}

type httpStatusError struct{ code int }

func (e *httpStatusError) Error() string { return "HTTP " + strconv.Itoa(e.code) }
