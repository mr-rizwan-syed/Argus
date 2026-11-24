package ctlog

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestTilePath(t *testing.T) {
	for n, want := range map[uint64]string{0: "000", 5: "005", 67: "067", 999: "999", 1000: "x001/000", 1234067: "x001/x234/067", 1000000: "x001/x000/000", 12345678: "x012/x345/678"} {
		if got := tilePath(n); got != want {
			t.Errorf("tilePath(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestParseCheckpoint(t *testing.T) {
	origin, size, err := parseCheckpoint([]byte("log.example/2026h2\n1066983110\nKsJ/1WsZCZg=\n\n— log.example/2026h2 BbZy7Wi8\n"))
	if err != nil || origin != "log.example/2026h2" || size != 1066983110 {
		t.Fatalf("%q %d %v", origin, size, err)
	}
	for _, bad := range []string{"", "origin\n", "origin\nabc\nhash\n", "\n5\nx\n", "origin\n-5\nx\n"} {
		if _, _, err := parseCheckpoint([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestTileEntryWalk(t *testing.T) {
	der1, _ := testEntry(t, 1)
	tbs, _ := testEntry(t, 4)
	tile := append(tileLeaf(time.Unix(10, 0), der1, false), tileLeaf(time.Unix(11, 0), tbs, true)...)
	te, rest, err := nextTileEntry(tile)
	if err != nil || te.precert || te.ts != 10_000 || len(te.der) != len(der1) {
		t.Fatalf("first: %+v %v", te, err)
	}
	te, rest, err = nextTileEntry(rest)
	if err != nil || !te.precert || te.ts != 11_000 || len(te.der) != len(tbs) || len(rest) != 0 {
		t.Fatalf("second: %+v rest=%d %v", te, len(rest), err)
	}
	for n := 0; n < len(tile)/2; n++ { // truncation anywhere in the first entry is an error, never a panic
		if _, _, err := nextTileEntry(tile[:n]); err == nil && n < len(tileLeaf(time.Unix(10, 0), der1, false)) {
			t.Fatalf("accepted a tile truncated to %d bytes", n)
		}
	}
}

// readSettled reads once, and once more after the partial-tile wait (the first call over a partial tile only starts the wait).
func readSettled(c *staticReader, from uint64, emit func(Entry)) (int, error) {
	n, err := c.read(context.Background(), from, emit)
	if n == 0 && err == nil {
		time.Sleep(5 * time.Millisecond)
		return c.read(context.Background(), from, emit)
	}
	return n, err
}

func staticFixture(t *testing.T, n int, o Options) (*fakeStatic, *Reader, *staticReader) {
	f := newFakeStatic(t, n)
	o.PartialWait = time.Millisecond
	r, _ := testReader(t, o)
	return f, r, newStaticReader(r, newStats(f.url(), ProtoStatic))
}

// readAll reads until the reader reports nothing new, returning every entry.
func readAll(t *testing.T, c *staticReader, from uint64) ([]Entry, uint64) {
	t.Helper()
	var col collector
	next := from
	for i := 0; i < 1000; i++ {
		n, err := c.read(context.Background(), next, col.emit)
		if err != nil {
			t.Fatalf("at %d: %v", next, err)
		}
		if n == 0 {
			time.Sleep(2 * time.Millisecond) // lets a partial tile's wait pass
			if n2, _ := c.read(context.Background(), next, col.emit); n2 == 0 {
				break
			} else {
				next += uint64(n2)
			}
			continue
		}
		next += uint64(n)
	}
	return col.all(), next
}

func TestStaticReadsFullAndPartialTiles(t *testing.T) {
	f, _, c := staticFixture(t, 600, Options{}) // 2 full tiles + a partial of 88
	got, next := readAll(t, c, 0)
	if next != 600 || len(got) != 600 {
		t.Fatalf("next=%d entries=%d", next, len(got))
	}
	for i, e := range got {
		if e.Index != uint64(i) || e.Names[0] != "host"+itoa(i)+".example.com" || (i%5 == 4) != e.Precert || e.Logged.Unix() != 1_700_000_000+int64(i) {
			t.Fatalf("entry %d: %+v", i, e)
		}
	}
	var sawPartial, sawFull bool
	for _, r := range f.requests() {
		sawPartial = sawPartial || r == "tile/data/002.p/88"
		sawFull = sawFull || r == "tile/data/001"
	}
	if !sawPartial || !sawFull {
		t.Errorf("requests %v", f.requests())
	}
}

func TestStaticStartsInTheMiddleOfATile(t *testing.T) {
	_, _, c := staticFixture(t, 300, Options{})
	got, next := readAll(t, c, 100)
	if next != 300 || len(got) != 200 || got[0].Index != 100 {
		t.Fatalf("next=%d entries=%d first=%v", next, len(got), got[0].Index)
	}
}

func TestStaticGzipTiles(t *testing.T) {
	f, _, c := staticFixture(t, 300, Options{})
	f.gzip = true
	got, _ := readAll(t, c, 0)
	if len(got) != 300 {
		t.Fatalf("%d entries from gzip tiles", len(got))
	}
}

func TestStaticWaitsBeforeFetchingAPartialTile(t *testing.T) {
	f := newFakeStatic(t, 40)
	r, _ := testReader(t, Options{PartialWait: time.Hour})
	c := newStaticReader(r, newStats(f.url(), ProtoStatic))
	var col collector
	n, err := c.read(context.Background(), 0, col.emit)
	if err != nil || n != 0 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	for _, req := range f.requests() {
		if strings.Contains(req, "tile/") {
			t.Errorf("fetched %s while waiting for the tile to fill", req)
		}
	}
	// the tile fills: it is fetched at once (full tiles do not wait)
	f.add(216)
	c.headAt = time.Time{}
	if _, err := c.head(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n, err = c.read(context.Background(), 0, col.emit); err != nil || n != 256 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

func TestStaticPartialGoneFallsBackToTheFullTile(t *testing.T) {
	f, _, c := staticFixture(t, 100, Options{})
	f.noPartials = true
	c.headSize = 100
	c.headAt = time.Now()
	f.add(156) // the tile is full now, but our cached head says 100
	var col collector
	n, err := readSettled(c, 0, col.emit)
	if err != nil || n != 256 {
		t.Fatalf("n=%d err=%v (the partial tile 404s; the full one exists)", n, err)
	}
}

func TestStaticMissingTileIsAnError(t *testing.T) {
	f, _, c := staticFixture(t, 300, Options{})
	f.noPartials = true
	c.headSize, c.headAt = 300, time.Now()
	var col collector
	if _, err := readSettled(c, 256, col.emit); err == nil {
		t.Fatal("expected an error: the partial tile is gone and the full one does not exist")
	}
}

func TestStaticTruncatedTileIsAnErrorNotAPanic(t *testing.T) {
	f, _, c := staticFixture(t, 256, Options{})
	f.mu.Lock()
	f.entries[200] = f.entries[200][:20]
	f.mu.Unlock()
	var col collector
	if _, err := c.read(context.Background(), 0, col.emit); err == nil {
		t.Fatal("a corrupt tile must be reported")
	}
	if c.st.parseErrors.Load() == 0 {
		t.Error("the corrupt tile is not counted")
	}
}
