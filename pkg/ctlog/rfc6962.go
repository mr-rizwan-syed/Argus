package ctlog

// RFC 6962 logs: GET <log>/ct/v1/get-sth gives the tree size, GET <log>/ct/v1/get-entries?start=S&end=E gives entries as JSON
//
//	{"entries":[{"leaf_input":"<base64 MerkleTreeLeaf>","extra_data":"<base64 chain>"}, ...]}
//
// A log may return fewer entries than asked (it has its own maximum per request, often 32 to 1000, and sometimes less): the reader advances by
// what came back. The chain in extra_data is several KB per entry and the monitor does not need it, so the JSON is NOT decoded: leaf_input
// values are located in the raw body and only those are base64-decoded.
//
// MerkleTreeLeaf (RFC 6962 section 3.4):
//
//	version(1)=0  leaf_type(1)=0  timestamp(8)  entry_type(2)  then
//	  x509_entry(0):    certificate<24-bit length>
//	  precert_entry(1): issuer_key_hash(32)  tbs_certificate<24-bit length>
//	then extensions<16-bit length>.

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const (
	entryTypeX509    = 0
	entryTypePrecert = 1

	maxEntriesBody = 96 << 20 // get-entries responses can be large (chains included)
	maxSmallBody   = 1 << 20
)

var errLeaf = errors.New("ctlog: malformed MerkleTreeLeaf")

// parseLeaf fills e (names, subject, issuer, validity, fingerprint, logged time, precert flag) from a MerkleTreeLeaf.
func parseLeaf(leaf []byte, e *Entry) error {
	if len(leaf) < 12 || leaf[0] != 0 || leaf[1] != 0 {
		return errLeaf
	}
	ts := binary.BigEndian.Uint64(leaf[2:10])
	e.Logged = time.UnixMilli(int64(ts)).UTC()
	rest := leaf[12:]
	switch binary.BigEndian.Uint16(leaf[10:12]) {
	case entryTypeX509:
		der, _, ok := readU24(rest)
		if !ok {
			return errLeaf
		}
		return entryFromCertificate(der, e)
	case entryTypePrecert:
		if len(rest) < 32 {
			return errLeaf
		}
		tbs, _, ok := readU24(rest[32:])
		if !ok {
			return errLeaf
		}
		return entryFromTBS(tbs, e)
	}
	return errLeaf
}

// readU24 reads a 24-bit length-prefixed value.
func readU24(b []byte) (val, rest []byte, ok bool) {
	if len(b) < 3 {
		return nil, nil, false
	}
	n := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
	if len(b)-3 < n {
		return nil, nil, false
	}
	return b[3 : 3+n], b[3+n:], true
}

// extractLeafInputs returns the decoded leaf_input of every entry in a get-entries body, appended to dst. It scans for the key instead of
// decoding the document: base64 has no quotes, so the key cannot occur inside another string, and extra_data is never touched. A value that
// is not valid base64 becomes a nil element (so the entries after it keep their positions) and is counted in bad.
func extractLeafInputs(body []byte, dst [][]byte) (leaves [][]byte, bad int) {
	const key = `"leaf_input"`
	i := 0
	for {
		j := indexOf(body[i:], key)
		if j < 0 {
			return dst, bad
		}
		i += j + len(key)
		for i < len(body) && (body[i] == ' ' || body[i] == '\t' || body[i] == '\n' || body[i] == '\r') {
			i++
		}
		if i >= len(body) || body[i] != ':' {
			continue
		}
		i++
		for i < len(body) && (body[i] == ' ' || body[i] == '\t' || body[i] == '\n' || body[i] == '\r') {
			i++
		}
		if i >= len(body) || body[i] != '"' {
			continue
		}
		i++
		end := i
		escaped := false
		for end < len(body) && body[end] != '"' {
			if body[end] == '\\' {
				escaped = true
			}
			end++
		}
		if end >= len(body) {
			return dst, bad // truncated body
		}
		raw := body[i:end]
		i = end + 1
		if escaped { // some servers write "\/" for "/"
			cleaned := make([]byte, 0, len(raw))
			for k := 0; k < len(raw); k++ {
				if raw[k] == '\\' && k+1 < len(raw) && raw[k+1] == '/' {
					continue
				}
				cleaned = append(cleaned, raw[k])
			}
			raw = cleaned
		}
		out := make([]byte, base64.StdEncoding.DecodedLen(len(raw)))
		n, err := base64.StdEncoding.Decode(out, raw)
		if err != nil {
			bad++
			dst = append(dst, nil) // keeps the positions of the entries after it
			continue
		}
		dst = append(dst, out[:n])
	}
}

// indexOf is bytes.Index for a string key without importing bytes for one use.
func indexOf(b []byte, key string) int {
	n := len(key)
	if n == 0 {
		return 0
	}
	for i := 0; i+n <= len(b); i++ {
		if b[i] == key[0] && string(b[i:i+n]) == key {
			return i
		}
	}
	return -1
}

// rfcReader reads one RFC 6962 log.
type rfcReader struct {
	r       *Reader
	st      *logStats
	cap     int // the most entries the log has been seen to return for a request that could be filled (0: not known yet)
	nextAsk int
	leafBuf [][]byte
}

func newRFCReader(r *Reader, st *logStats) *rfcReader {
	return &rfcReader{r: r, st: st, nextAsk: 256}
}

// head returns the tree size from get-sth. (Logs behind a cache can serve an hour-old tree head: read() does not depend on it.)
func (c *rfcReader) head(ctx context.Context) (uint64, error) {
	body, err := c.r.http.get(ctx, c.st.info.URL+"ct/v1/get-sth", maxSmallBody, c.st)
	if err != nil {
		return 0, err
	}
	var sth struct {
		TreeSize uint64 `json:"tree_size"`
	}
	if err := json.Unmarshal(body, &sth); err != nil {
		return 0, fmt.Errorf("ctlog: get-sth of %s: %w", c.st.info.Name, err)
	}
	return sth.TreeSize, nil
}

// has asks for the single entry idx.
func (c *rfcReader) has(ctx context.Context, idx uint64) (bool, error) {
	body, err := c.r.http.get(ctx, fmt.Sprintf("%sct/v1/get-entries?start=%d&end=%d", c.st.info.URL, idx, idx), maxEntriesBody, c.st)
	if err != nil {
		if s := httpStatus(err); s == 400 || s == 404 {
			return false, nil
		}
		return false, err
	}
	leaves, _ := extractLeafInputs(body, nil)
	return len(leaves) > 0, nil
}

// read fetches the entries from `from` and emits them. It does not look at the tree head: asked for entries beyond the end, a log answers 400
// or with fewer entries, and that is "caught up" (0, nil). This also reads past an out-of-date cached tree head.
func (c *rfcReader) read(ctx context.Context, from uint64, emit func(Entry)) (int, error) {
	ask := c.nextAsk
	if c.cap > 0 && c.cap < ask {
		ask = c.cap
	}
	url := fmt.Sprintf("%sct/v1/get-entries?start=%d&end=%d", c.st.info.URL, from, from+uint64(ask)-1)
	body, err := c.r.http.get(ctx, url, maxEntriesBody, c.st)
	if err != nil {
		if s := httpStatus(err); s == 400 || s == 404 {
			if from >= c.st.head.Load() {
				return 0, nil // beyond the end of the log
			}
			// The cached tree head can be newer than the log's own view (a log behind several caches): ask for the one entry.
			if ok, herr := c.has(ctx, from); herr == nil && !ok {
				return 0, nil
			}
		}
		return 0, err
	}
	var bad int
	c.leafBuf, bad = extractLeafInputs(body, c.leafBuf[:0])
	n := len(c.leafBuf)
	now := time.Now().UTC()
	for i, leaf := range c.leafBuf {
		if leaf == nil {
			continue // not base64: counted below
		}
		e := Entry{Log: c.st.info.Name, Operator: c.st.info.Operator, Index: from + uint64(i), Seen: now}
		if err := parseLeaf(leaf, &e); err != nil {
			c.st.parseErrors.Add(1)
			continue
		}
		c.r.deliver(c.st, e, emit)
	}
	if bad > 0 {
		c.st.parseErrors.Add(uint64(bad))
	}
	// Learn the log's own limit: a request that could have been filled (it lies inside the tree) and was not tells us the cap.
	switch {
	case n >= ask:
		c.nextAsk = min(c.nextAsk*2, c.r.opts.MaxBatch)
		if c.cap > 0 {
			c.cap = min(c.cap*2, c.r.opts.MaxBatch) // the log filled the request: perhaps it allows more now
		}
	case n > 0 && from+uint64(ask) <= c.st.head.Load():
		c.cap = n
		c.nextAsk = max(n, 16)
	}
	return n, nil
}
