package ctlog

// Static CT API logs (https://c2sp.org/static-ct-api): the log is a set of static files under its monitoring URL.
//
//	<monitoring>/checkpoint                    a signed note: line 1 the origin, line 2 the tree size, line 3 the root hash
//	<monitoring>/tile/data/<N>                 the N-th data tile: 256 consecutive entries
//	<monitoring>/tile/data/<N>.p/<W>           a partial data tile of the first W entries (the rightmost tile while it fills)
//
// <N> is written in groups of three digits, every group but the last prefixed with "x": 1234067 is "x001/x234/067", 5 is "005".
// Data tiles are usually gzip-compressed on the wire; the HTTP client unzips them.
//
// A data tile is a sequence of TileLeaf structures, one per entry:
//
//	timestamp(8)  entry_type(2)
//	  x509_entry(0):    certificate<24-bit length>
//	  precert_entry(1): issuer_key_hash(32)  tbs_certificate<24-bit length>
//	extensions<16-bit length>
//	  precert only:     pre_certificate<24-bit length>            (the whole precertificate; not needed here)
//	certificate_chain<16-bit length>                              (SHA-256 fingerprints of the issuers; not needed here)
//
// The monitor does not verify the checkpoint signature or the tiles' hashes: it is a name finder, not an auditor (a log that lied could only
// feed it wrong names). For precertificate entries the names come from the TBS in the signed entry.
//
// The spec says a client that tails a log SHOULD avoid partial data tiles. So while only a partial tile is available the reader waits
// PartialWait (10 s by default) and then fetches it; every full tile is fetched once.

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const tileWidth = 256

var errTile = errors.New("ctlog: malformed data tile")

// tilePath encodes a tile index as the path elements of the spec: 1234067 -> "x001/x234/067".
func tilePath(n uint64) string {
	if n < 1000 {
		return fmt.Sprintf("%03d", n)
	}
	var parts []string
	for n >= 1000 {
		parts = append(parts, fmt.Sprintf("%03d", n%1000))
		n /= 1000
	}
	parts = append(parts, fmt.Sprintf("%03d", n))
	// parts are least significant first: reverse, prefix all but the last with "x"
	out := make([]string, len(parts))
	for i := range parts {
		p := parts[len(parts)-1-i]
		if i < len(parts)-1 {
			p = "x" + p
		}
		out[i] = p
	}
	return strings.Join(out, "/")
}

// parseCheckpoint returns the origin and the tree size of a checkpoint. Signatures are not checked.
func parseCheckpoint(b []byte) (origin string, size uint64, err error) {
	lines := strings.SplitN(string(b), "\n", 4)
	if len(lines) < 3 || lines[0] == "" {
		return "", 0, errors.New("ctlog: malformed checkpoint")
	}
	size, err = strconv.ParseUint(strings.TrimSpace(lines[1]), 10, 64)
	if err != nil {
		return "", 0, fmt.Errorf("ctlog: malformed checkpoint size: %w", err)
	}
	return lines[0], size, nil
}

// tileEntry is one entry of a data tile, still undecoded.
type tileEntry struct {
	ts      uint64
	precert bool
	der     []byte // the certificate (x509) or the TBSCertificate (precert)
	preCert []byte // precert only: the whole precertificate (kept for tests; the monitor does not read it)
}

// nextTileEntry reads one TileLeaf from b and returns it with the rest.
func nextTileEntry(b []byte) (te tileEntry, rest []byte, err error) {
	if len(b) < 10 {
		return te, nil, errTile
	}
	te.ts = binary.BigEndian.Uint64(b[0:8])
	typ := binary.BigEndian.Uint16(b[8:10])
	b = b[10:]
	var ok bool
	switch typ {
	case entryTypeX509:
		if te.der, b, ok = readU24(b); !ok {
			return te, nil, errTile
		}
	case entryTypePrecert:
		if len(b) < 32 {
			return te, nil, errTile
		}
		te.precert = true
		if te.der, b, ok = readU24(b[32:]); !ok {
			return te, nil, errTile
		}
	default:
		return te, nil, errTile
	}
	// extensions<16-bit>
	if b, ok = skipU16(b); !ok {
		return te, nil, errTile
	}
	if te.precert { // pre_certificate<24-bit>
		if te.preCert, b, ok = readU24(b); !ok {
			return te, nil, errTile
		}
	}
	// certificate_chain<16-bit>
	if b, ok = skipU16(b); !ok {
		return te, nil, errTile
	}
	return te, b, nil
}

func skipU16(b []byte) ([]byte, bool) {
	if len(b) < 2 {
		return nil, false
	}
	n := int(binary.BigEndian.Uint16(b))
	if len(b)-2 < n {
		return nil, false
	}
	return b[2+n:], true
}

// staticReader reads one Static CT API log.
type staticReader struct {
	r            *Reader
	st           *logStats
	headSize     uint64
	headAt       time.Time
	partialSince time.Time
}

func newStaticReader(r *Reader, st *logStats) *staticReader { return &staticReader{r: r, st: st} }

// head returns the tree size from the checkpoint (cached for a second, so the poll loop does not ask twice).
func (c *staticReader) head(ctx context.Context) (uint64, error) {
	if !c.headAt.IsZero() && time.Since(c.headAt) < time.Second {
		return c.headSize, nil
	}
	body, err := c.r.http.get(ctx, c.st.info.URL+"checkpoint", maxSmallBody, c.st)
	if err != nil {
		return 0, err
	}
	_, size, err := parseCheckpoint(body)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", c.st.info.Name, err)
	}
	c.headSize, c.headAt = size, time.Now()
	return size, nil
}

// has reports whether the checkpoint covers entry idx (a checkpoint is always current: a log whose tree shrank has been reset).
func (c *staticReader) has(ctx context.Context, idx uint64) (bool, error) {
	c.headAt = time.Time{}
	h, err := c.head(ctx)
	if err != nil {
		return false, err
	}
	return idx < h, nil
}

// read emits the entries of the tile that holds `from`, from `from` on, and returns how many it consumed (0: nothing new yet).
func (c *staticReader) read(ctx context.Context, from uint64, emit func(Entry)) (int, error) {
	if from >= c.headSize {
		h, err := c.head(ctx)
		if err != nil {
			return 0, err
		}
		c.st.head.Store(h)
		if from >= h {
			return 0, nil
		}
	}
	tile := from / tileWidth
	offset := int(from % tileWidth)
	width := tileWidth
	if end := (tile + 1) * tileWidth; end > c.headSize {
		width = int(c.headSize - tile*tileWidth)
	}
	if width < tileWidth { // partial: wait for it to fill, unless it has been waiting long enough
		if c.partialSince.IsZero() {
			c.partialSince = time.Now()
		}
		if time.Since(c.partialSince) < c.r.opts.PartialWait {
			return 0, nil
		}
	}
	body, width, err := c.fetchTile(ctx, tile, width)
	if err != nil {
		return 0, err
	}
	rest := body
	now := time.Now().UTC()
	for i := 0; i < width; i++ {
		var te tileEntry
		if te, rest, err = nextTileEntry(rest); err != nil {
			c.st.parseErrors.Add(1)
			return 0, fmt.Errorf("%s: tile %d entry %d: %w", c.st.info.Name, tile, i, err)
		}
		if i < offset {
			continue
		}
		e := Entry{Log: c.st.info.Name, Operator: c.st.info.Operator, Index: tile*tileWidth + uint64(i), Seen: now,
			Logged: time.UnixMilli(int64(te.ts)).UTC()}
		var perr error
		if te.precert {
			perr = entryFromTBS(te.der, &e)
		} else {
			perr = entryFromCertificate(te.der, &e)
		}
		if perr != nil {
			c.st.parseErrors.Add(1)
			continue
		}
		c.r.deliver(c.st, e, emit)
	}
	if width < tileWidth {
		c.partialSince = time.Time{}
	}
	return width - offset, nil
}

// fetchTile gets a data tile: the full tile, or the partial one of the given width. A partial tile that has gone (the log keeps only full
// tiles once they exist) is answered by a fresh checkpoint and the full tile. Returns the tile and its width (a full tile fetched in place of
// a partial one is 256 wide).
func (c *staticReader) fetchTile(ctx context.Context, tile uint64, width int) ([]byte, int, error) {
	url := c.st.info.URL + "tile/data/" + tilePath(tile)
	if width < tileWidth {
		body, err := c.r.http.get(ctx, url+".p/"+strconv.Itoa(width), maxEntriesBody, c.st)
		if err == nil || httpStatus(err) != 404 {
			return body, width, err
		}
		// the full tile may exist now
		c.headAt = time.Time{}
		if h, herr := c.head(ctx); herr == nil && h >= (tile+1)*tileWidth {
			body, err = c.r.http.get(ctx, url, maxEntriesBody, c.st)
			return body, tileWidth, err
		}
		return nil, width, err
	}
	body, err := c.r.http.get(ctx, url, maxEntriesBody, c.st)
	return body, width, err
}
