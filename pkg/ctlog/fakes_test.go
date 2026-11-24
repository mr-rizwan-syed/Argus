package ctlog

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---- building log entries ----------------------------------------------------------------------------------------------

func u24(b []byte) []byte {
	return append([]byte{byte(len(b) >> 16), byte(len(b) >> 8), byte(len(b))}, b...)
}

// testEntry is the DER and kind of entry i: a certificate for host<i>.example.com (organization "Org <i>"); every fifth is a precertificate.
func testEntry(t testing.TB, i int) (der []byte, precert bool) {
	c := makeCert(t, &x509.Certificate{
		Subject:  pkix.Name{CommonName: fmt.Sprintf("host%d.example.com", i), Organization: []string{fmt.Sprintf("Org %d", i)}},
		DNSNames: []string{fmt.Sprintf("host%d.example.com", i), fmt.Sprintf("www.host%d.example.com", i)},
	})
	if i%5 == 4 {
		x, _ := x509.ParseCertificate(c)
		return x.RawTBSCertificate, true
	}
	return c, false
}

func leafInput(ts time.Time, der []byte, precert bool) []byte {
	b := []byte{0, 0}
	b = binary.BigEndian.AppendUint64(b, uint64(ts.UnixMilli()))
	if precert {
		b = binary.BigEndian.AppendUint16(b, entryTypePrecert)
		b = append(b, make([]byte, 32)...)
	} else {
		b = binary.BigEndian.AppendUint16(b, entryTypeX509)
	}
	b = append(b, u24(der)...)
	return append(b, 0, 0) // extensions
}

func tileLeaf(ts time.Time, der []byte, precert bool) []byte {
	b := binary.BigEndian.AppendUint64(nil, uint64(ts.UnixMilli()))
	if precert {
		b = binary.BigEndian.AppendUint16(b, entryTypePrecert)
		b = append(b, make([]byte, 32)...)
		b = append(b, u24(der)...)
		b = append(b, 0, 0)                       // extensions
		b = append(b, u24([]byte("pre-cert"))...) // pre_certificate
	} else {
		b = binary.BigEndian.AppendUint16(b, entryTypeX509)
		b = append(b, u24(der)...)
		b = append(b, 0, 0)
	}
	return append(b, 0, 64, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
		33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64) // 2 fingerprints
}

// ---- a fake RFC 6962 log -----------------------------------------------------------------------------------------------

type fakeRFC struct {
	t        *testing.T
	mu       sync.Mutex
	leaves   [][]byte
	maxBatch int      // entries per get-entries response (0: unlimited)
	headSize int      // tree size reported by get-sth (-1: len(leaves))
	fail     []int    // statuses to answer before the first success of get-entries, in order
	retryHdr string   // Retry-After sent with a 429
	reqs     []string // "sth", "entries:<start>-<end>"
	srv      *httptest.Server
	escape   bool // write "/" as "\/" in the JSON
}

func newFakeRFC(t *testing.T, n int) *fakeRFC {
	f := &fakeRFC{t: t, headSize: -1}
	for i := 0; i < n; i++ {
		der, pre := testEntry(t, i)
		f.leaves = append(f.leaves, leafInput(time.Unix(1_700_000_000+int64(i), 0), der, pre))
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeRFC) url() string { return f.srv.URL + "/" }

func (f *fakeRFC) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.reqs...)
}

func (f *fakeRFC) add(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	base := len(f.leaves)
	for i := 0; i < n; i++ {
		der, pre := testEntry(f.t, base+i)
		f.leaves = append(f.leaves, leafInput(time.Unix(1_700_000_000+int64(base+i), 0), der, pre))
	}
}

func (f *fakeRFC) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.URL.Path {
	case "/ct/v1/get-sth":
		f.reqs = append(f.reqs, "sth")
		size := f.headSize
		if size < 0 {
			size = len(f.leaves)
		}
		fmt.Fprintf(w, `{"tree_size":%d,"timestamp":1,"sha256_root_hash":"AAAA","tree_head_signature":"AAAA"}`, size)
	case "/ct/v1/get-entries":
		start, _ := strconv.Atoi(r.URL.Query().Get("start"))
		end, _ := strconv.Atoi(r.URL.Query().Get("end"))
		f.reqs = append(f.reqs, fmt.Sprintf("entries:%d-%d", start, end))
		if len(f.fail) > 0 {
			s := f.fail[0]
			f.fail = f.fail[1:]
			if s == 429 && f.retryHdr != "" {
				w.Header().Set("Retry-After", f.retryHdr)
			}
			w.WriteHeader(s)
			return
		}
		if start >= len(f.leaves) || end < start {
			w.WriteHeader(400)
			fmt.Fprint(w, `{"error_message":"start must be less than tree_size"}`)
			return
		}
		end = min(end, len(f.leaves)-1)
		if f.maxBatch > 0 {
			end = min(end, start+f.maxBatch-1)
		}
		var sb strings.Builder
		sb.WriteString(`{"entries":[`)
		for i := start; i <= end; i++ {
			if i > start {
				sb.WriteString(",")
			}
			leaf := base64.StdEncoding.EncodeToString(f.leaves[i])
			if f.escape {
				leaf = strings.ReplaceAll(leaf, "/", `\/`)
			}
			fmt.Fprintf(&sb, `{"leaf_input":"%s","extra_data":"%s"}`, leaf, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 3000)))
		}
		sb.WriteString(`]}`)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, sb.String())
	default:
		w.WriteHeader(404)
	}
}

// ---- a fake Static CT API log ------------------------------------------------------------------------------------------

type fakeStatic struct {
	t          *testing.T
	mu         sync.Mutex
	entries    [][]byte // TileLeaf encodings
	gzip       bool
	noPartials bool // partial tiles answer 404 (the log kept only full tiles)
	reqs       []string
	srv        *httptest.Server
}

func newFakeStatic(t *testing.T, n int) *fakeStatic {
	f := &fakeStatic{t: t}
	f.add(n)
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeStatic) url() string { return f.srv.URL + "/" }

func (f *fakeStatic) add(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	base := len(f.entries)
	for i := 0; i < n; i++ {
		der, pre := testEntry(f.t, base+i)
		f.entries = append(f.entries, tileLeaf(time.Unix(1_700_000_000+int64(base+i), 0), der, pre))
	}
}

func (f *fakeStatic) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.reqs...)
}

func (f *fakeStatic) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := r.URL.Path
	f.reqs = append(f.reqs, strings.TrimPrefix(p, "/"))
	if p == "/checkpoint" {
		fmt.Fprintf(w, "example.test/log\n%d\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\n— example.test/log AAAA\n", len(f.entries))
		return
	}
	rest, ok := strings.CutPrefix(p, "/tile/data/")
	if !ok {
		w.WriteHeader(404)
		return
	}
	width := tileWidth
	if i := strings.Index(rest, ".p/"); i >= 0 {
		width, _ = strconv.Atoi(rest[i+3:])
		rest = rest[:i]
		if f.noPartials {
			w.WriteHeader(404)
			return
		}
	}
	var idx uint64
	for _, g := range strings.Split(rest, "/") {
		v, err := strconv.Atoi(strings.TrimPrefix(g, "x"))
		if err != nil {
			w.WriteHeader(404)
			return
		}
		idx = idx*1000 + uint64(v)
	}
	lo, hi := int(idx)*tileWidth, int(idx)*tileWidth+width
	if hi > len(f.entries) {
		w.WriteHeader(404)
		return
	}
	body := bytes.Join(f.entries[lo:hi], nil)
	w.Header().Set("Content-Type", "application/octet-stream")
	if f.gzip {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		zw.Write(body)
		zw.Close()
		w.Header().Set("Content-Encoding", "gzip")
		body = buf.Bytes()
	}
	w.Write(body)
}

// ---- helpers ------------------------------------------------------------------------------------------------------------

// testReader builds a Reader whose retries do not wait (the waits are recorded).
func testReader(t *testing.T, o Options) (*Reader, *[]time.Duration) {
	t.Helper()
	if o.LogListFile == "" {
		o.LogListFile = "unused"
	}
	r, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	waits := &[]time.Duration{}
	r.http.sleep = func(ctx_ context.Context, d time.Duration) error {
		mu.Lock()
		*waits = append(*waits, d)
		mu.Unlock()
		return ctx_.Err()
	}
	r.http.backoff = time.Millisecond
	return r, waits
}

func newStats(url, proto string) *logStats {
	return &logStats{info: LogInfo{Name: "Test " + proto, Operator: "TestOp", URL: url, Protocol: proto, State: "usable"}}
}

type collector struct {
	mu      sync.Mutex
	entries []Entry
}

func (c *collector) emit(e Entry) {
	c.mu.Lock()
	c.entries = append(c.entries, e)
	c.mu.Unlock()
}

func (c *collector) all() []Entry {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Entry(nil), c.entries...)
}
