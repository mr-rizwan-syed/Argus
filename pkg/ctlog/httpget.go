package ctlog

// The one way this package talks to a log: a GET with a timeout, a bounded body, a shared cap on simultaneous requests and polite retries.
//
// Retried (up to maxRetries times, exponential backoff from one second to one minute with jitter): network errors, HTTP 429 and 5xx. A
// Retry-After header (seconds or an HTTP date) replaces the computed wait, up to five minutes. Not retried: any other status (a 400 on a
// get-entries beyond the end of the log is an answer, not a failure) and a body over the limit.
//
// Responses are transparently decompressed (Go's transport asks for gzip and unzips it, which is what the Static CT API expects of clients);
// the size limits apply to the decompressed body. WireBytes counts the bytes actually received on the connections.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"
)

const (
	defaultUserAgent = "argus-monitor/1.1 (+https://github.com/mr-rizwan-syed/Argus)"
	maxRetries       = 6
	maxRetryAfter    = 5 * time.Minute
)

// httpError is a response with a status the caller has to interpret.
type httpError struct {
	Status int
	URL    string
}

func (e *httpError) Error() string { return fmt.Sprintf("HTTP %d from %s", e.Status, e.URL) }

// httpStatus returns the status of an httpError, or 0.
func httpStatus(err error) int {
	var he *httpError
	if errors.As(err, &he) {
		return he.Status
	}
	return 0
}

type httpClient struct {
	c       *http.Client
	ua      string
	timeout time.Duration
	sem     chan struct{}
	wire    *atomic.Uint64
	sleep   func(ctx context.Context, d time.Duration) error
	backoff time.Duration // the first retry wait (one second; tests shorten it)
}

// countingConn counts the bytes received on a connection.
type countingConn struct {
	net.Conn
	n *atomic.Uint64
}

func (c countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.n.Add(uint64(n))
	return n, err
}

func newHTTPClient(o *Options, wire *atomic.Uint64) *httpClient {
	h := &httpClient{ua: o.UserAgent, timeout: o.HTTPTimeout, wire: wire, backoff: time.Second, sleep: sleepCtx,
		sem: make(chan struct{}, o.MaxConcurrentRequests)}
	if o.Client != nil {
		h.c = o.Client
		return h
	}
	dialer := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	h.c = &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return countingConn{conn, wire}, nil
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: time.Second,
	}}
	return h
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// retryAfter reads a Retry-After header: seconds or an HTTP date. Zero when absent or unreadable.
func retryAfter(h http.Header, now time.Time) time.Duration {
	v := h.Get("Retry-After")
	if v == "" {
		return 0
	}
	if s, err := strconv.Atoi(v); err == nil && s >= 0 {
		return min(time.Duration(s)*time.Second, maxRetryAfter)
	}
	if t, err := http.ParseTime(v); err == nil && t.After(now) {
		return min(t.Sub(now), maxRetryAfter)
	}
	return 0
}

// get fetches url and returns the (decompressed) body, at most maxBody bytes. Counts requests, retries and errors on st when it is not nil.
func (h *httpClient) get(ctx context.Context, url string, maxBody int64, st *logStats) ([]byte, error) {
	var lastErr error
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		body, wait, err := h.once(ctx, url, maxBody, st)
		if err == nil {
			return body, nil
		}
		lastErr = err
		if wait < 0 || attempt >= maxRetries || ctx.Err() != nil { // wait < 0: not worth retrying
			if st != nil && ctx.Err() == nil && httpStatus(err) != 400 && httpStatus(err) != 404 {
				st.errors.Add(1)
			}
			return nil, lastErr
		}
		if wait == 0 {
			wait = h.backoff << attempt
			if wait > time.Minute {
				wait = time.Minute
			}
			wait += time.Duration(rand.Int63n(int64(wait)/4 + 1)) // jitter
		}
		if st != nil {
			st.retries.Add(1)
		}
		if err := h.sleep(ctx, wait); err != nil {
			return nil, err
		}
	}
}

// once makes one request. wait is how long to wait before a retry (0: use the default backoff) or -1 when the failure is final.
func (h *httpClient) once(ctx context.Context, url string, maxBody int64, st *logStats) (body []byte, wait time.Duration, err error) {
	h.sem <- struct{}{}
	defer func() { <-h.sem }()
	rctx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, -1, err
	}
	req.Header.Set("User-Agent", h.ua)
	if st != nil {
		st.requests.Add(1)
	}
	resp, err := h.c.Do(req)
	if err != nil {
		return nil, 0, err // network error or timeout: retry
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
		if err != nil {
			return nil, 0, err
		}
		if int64(len(b)) > maxBody {
			return nil, -1, fmt.Errorf("ctlog: the response from %s is over %d bytes", url, maxBody)
		}
		if st != nil {
			st.bytes.Add(uint64(len(b)))
		}
		return b, 0, nil
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	he := &httpError{Status: resp.StatusCode, URL: url}
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		return nil, retryAfter(resp.Header, time.Now()), he
	}
	return nil, -1, he
}
