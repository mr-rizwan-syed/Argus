package ctlog

import (
	"context"
	"net/http"
	"strconv"
	"testing"
	"time"
)

func TestExtractLeafInputs(t *testing.T) {
	body := []byte(` {"entries": [ {"extra_data":"QUJD","leaf_input" : "AAEC"}, {"leaf_input":"AwQ\/","extra_data":"x"}, {"leaf_input":"!!notbase64!!"}, {"leaf_input":"BQY="} ] } `)
	got, bad := extractLeafInputs(body, nil)
	if bad != 1 || len(got) != 4 {
		t.Fatalf("got %d leaves, %d bad", len(got), bad)
	}
	if string(got[0]) != "\x00\x01\x02" || string(got[1]) != "\x03\x04\x3f" || got[2] != nil || string(got[3]) != "\x05\x06" {
		t.Errorf("%q", got)
	}
	// truncated and empty bodies never panic and return what was complete
	if g, _ := extractLeafInputs([]byte(`{"entries":[{"leaf_input":"AAEC`), nil); len(g) != 0 {
		t.Errorf("truncated: %v", g)
	}
	if g, _ := extractLeafInputs([]byte(`{"entries":[]}`), nil); len(g) != 0 {
		t.Errorf("empty: %v", g)
	}
	if g, _ := extractLeafInputs(nil, nil); len(g) != 0 {
		t.Errorf("nil: %v", g)
	}
}

func TestParseLeaf(t *testing.T) {
	der, _ := testEntry(t, 1)
	var e Entry
	if err := parseLeaf(leafInput(time.Unix(1_700_000_123, 0), der, false), &e); err != nil {
		t.Fatal(err)
	}
	if e.Precert || len(e.Names) != 2 || e.Names[0] != "host1.example.com" || e.Logged.Unix() != 1_700_000_123 {
		t.Errorf("%+v", e)
	}
	tbs, pre := testEntry(t, 4)
	if !pre {
		t.Fatal("entry 4 should be a precert")
	}
	e = Entry{}
	if err := parseLeaf(leafInput(time.Unix(1, 0), tbs, true), &e); err != nil || !e.Precert || e.Names[0] != "host4.example.com" {
		t.Errorf("precert: %v %+v", err, e)
	}
	for _, bad := range [][]byte{nil, {0}, {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7}, leafInput(time.Now(), der, false)[:30], leafInput(time.Now(), tbs, true)[:20]} {
		if err := parseLeaf(bad, &Entry{}); err == nil {
			t.Errorf("accepted %x", bad)
		}
	}
}

func rfcFixture(t *testing.T, n int, o Options) (*fakeRFC, *Reader, *rfcReader, *[]time.Duration) {
	f := newFakeRFC(t, n)
	r, waits := testReader(t, o)
	st := newStats(f.url(), ProtoRFC6962)
	st.head.Store(uint64(n))
	return f, r, newRFCReader(r, st), waits
}

func TestRFCReadsInBatchesWithTheLogsOwnCap(t *testing.T) {
	f, _, c, _ := rfcFixture(t, 400, Options{})
	f.maxBatch = 37
	var col collector
	next := uint64(0)
	for next < 400 {
		n, err := c.read(context.Background(), next, col.emit)
		if err != nil || n == 0 {
			t.Fatalf("at %d: n=%d err=%v", next, n, err)
		}
		next += uint64(n)
	}
	got := col.all()
	if len(got) != 400 {
		t.Fatalf("%d entries", len(got))
	}
	for i, e := range got {
		if e.Index != uint64(i) || e.Names[0] != "host"+itoa(i)+".example.com" || e.Operator != "TestOp" || e.Seen.IsZero() {
			t.Fatalf("entry %d: %+v", i, e)
		}
		if (i%5 == 4) != e.Precert {
			t.Fatalf("entry %d precert=%v", i, e.Precert)
		}
	}
	// after the first full-size request the reader asks for what the log allows
	reqs := f.requests()
	if len(reqs) > 20 {
		t.Errorf("%d requests for 400 entries with a cap of 37: %v", len(reqs), reqs[:6])
	}
}

func itoa(i int) string { return strconv.Itoa(i) }

func TestRFCEscapedSlashesInJSON(t *testing.T) {
	f, _, c, _ := rfcFixture(t, 30, Options{})
	f.escape = true
	var col collector
	n, err := c.read(context.Background(), 0, col.emit)
	if err != nil || n != 30 || len(col.all()) != 30 {
		t.Fatalf("n=%d err=%v entries=%d", n, err, len(col.all()))
	}
}

func TestRFCBeyondTheEndIsCaughtUp(t *testing.T) {
	_, _, c, _ := rfcFixture(t, 10, Options{})
	var col collector
	n, err := c.read(context.Background(), 10, col.emit)
	if n != 0 || err != nil {
		t.Fatalf("n=%d err=%v", n, err)
	}
	// a cached tree head that is ahead of the log's own view: the entry is not there, so this is still "caught up"
	c.st.head.Store(1000)
	if n, err := c.read(context.Background(), 500, col.emit); n != 0 || err != nil {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

func TestRFCBadRequestForAnExistingEntryIsAnError(t *testing.T) {
	f, _, c, _ := rfcFixture(t, 600, Options{})
	f.fail = []int{400} // the batch is refused, but the entry itself is there
	c.st.head.Store(600)
	var col collector
	if _, err := c.read(context.Background(), 500, col.emit); err == nil {
		t.Fatal("a 400 for a range that starts at an existing entry must be an error")
	}
}

func TestRFCReadsPastAStaleCachedHead(t *testing.T) {
	f, _, c, _ := rfcFixture(t, 25, Options{})
	f.headSize = 10 // a cache serves an old tree head
	c.st.head.Store(10)
	var col collector
	n, err := c.read(context.Background(), 10, col.emit)
	if err != nil || n != 15 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	head, err := c.head(context.Background())
	if err != nil || head != 10 {
		t.Fatalf("head %d %v", head, err)
	}
}

func TestRFCRateLimitHonoursRetryAfter(t *testing.T) {
	f, _, c, waits := rfcFixture(t, 20, Options{})
	f.fail = []int{429}
	f.retryHdr = "7"
	var col collector
	n, err := c.read(context.Background(), 0, col.emit)
	if err != nil || n != 20 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if len(*waits) != 1 || (*waits)[0] != 7*time.Second {
		t.Errorf("waits %v, want exactly the 7 s the log asked for", *waits)
	}
	if c.st.retries.Load() != 1 || c.st.errors.Load() != 0 {
		t.Errorf("retries %d errors %d", c.st.retries.Load(), c.st.errors.Load())
	}
}

func TestRFCRetryAfterIsCapped(t *testing.T) {
	f, _, c, waits := rfcFixture(t, 5, Options{})
	f.fail = []int{429}
	f.retryHdr = "86400"
	var col collector
	if _, err := c.read(context.Background(), 0, col.emit); err != nil {
		t.Fatal(err)
	}
	if (*waits)[0] != maxRetryAfter {
		t.Errorf("waited %v", (*waits)[0])
	}
}

func TestRFCServerErrorsAreRetriedWithGrowingWaits(t *testing.T) {
	f, _, c, waits := rfcFixture(t, 20, Options{})
	f.fail = []int{500, 502, 503}
	var col collector
	n, err := c.read(context.Background(), 0, col.emit)
	if err != nil || n != 20 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if len(*waits) != 3 || !((*waits)[0] < (*waits)[1] && (*waits)[1] < (*waits)[2]) {
		t.Errorf("waits %v should grow", *waits)
	}
}

func TestRFCGivesUpAfterTheRetryLimit(t *testing.T) {
	f, _, c, waits := rfcFixture(t, 20, Options{})
	f.fail = []int{500, 500, 500, 500, 500, 500, 500, 500, 500}
	var col collector
	_, err := c.read(context.Background(), 0, col.emit)
	if err == nil || httpStatus(err) != 500 {
		t.Fatalf("err=%v", err)
	}
	if len(*waits) != maxRetries {
		t.Errorf("%d waits, want %d", len(*waits), maxRetries)
	}
	if c.st.errors.Load() != 1 {
		t.Errorf("errors %d", c.st.errors.Load())
	}
}

func TestRFCDoesNotRetryOtherClientErrors(t *testing.T) {
	f, _, c, waits := rfcFixture(t, 20, Options{})
	f.fail = []int{403}
	var col collector
	if _, err := c.read(context.Background(), 0, col.emit); httpStatus(err) != 403 {
		t.Fatalf("err=%v", err)
	}
	if len(*waits) != 0 {
		t.Errorf("waited %v", *waits)
	}
}

func TestRFCSendsAnIdentifyingUserAgent(t *testing.T) {
	var ua string
	f, r, c, _ := rfcFixture(t, 3, Options{})
	_ = f
	r.http.c.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		ua = req.Header.Get("User-Agent")
		return http.DefaultTransport.RoundTrip(req)
	})
	if _, err := c.head(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ua != "argus-monitor/1.1 (+https://github.com/mr-rizwan-syed/Argus)" {
		t.Errorf("User-Agent %q", ua)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
