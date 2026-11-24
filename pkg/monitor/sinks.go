package monitor

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// A Sink receives the reported matches. Write must not block for long.
type Sink interface {
	Write(ms []Match)
	Close() error
}

// ---- JSON lines to a writer (stdout) ---------------------------------------------------------------------------------------------------------

type lineSink struct {
	mu sync.Mutex
	w  io.Writer
}

// NewStdoutSink writes one JSON object per line to w.
func NewStdoutSink(w io.Writer) Sink { return &lineSink{w: w} }

func (s *lineSink) Write(ms []Match) {
	var buf bytes.Buffer
	for i := range ms {
		b, err := json.Marshal(&ms[i])
		if err == nil {
			buf.Write(b)
			buf.WriteByte('\n')
		}
	}
	s.mu.Lock()
	s.w.Write(buf.Bytes())
	s.mu.Unlock()
}

func (s *lineSink) Close() error { return nil }

// ---- JSON lines to a file, rotated -----------------------------------------------------------------------------------------------------------

// FileSink appends JSON lines to a file; at MaxBytes (100 MB by default) the file becomes path.1, path.1 becomes path.2 and so on, Keep files in all.
type FileSink struct {
	Path     string
	MaxBytes int64
	Keep     int

	mu   sync.Mutex
	f    *os.File
	size int64
}

// NewFileSink opens (appending to) path.
func NewFileSink(path string) (*FileSink, error) {
	s := &FileSink{Path: path, MaxBytes: 100 << 20, Keep: 3}
	if err := s.open(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *FileSink) open() error {
	if dir := filepath.Dir(s.Path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(s.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	s.f, s.size = f, st.Size()
	return nil
}

func (s *FileSink) rotate() error {
	s.f.Close()
	keep := s.Keep
	if keep < 1 {
		keep = 1
	}
	os.Remove(fmt.Sprintf("%s.%d", s.Path, keep))
	for i := keep - 1; i >= 1; i-- {
		os.Rename(fmt.Sprintf("%s.%d", s.Path, i), fmt.Sprintf("%s.%d", s.Path, i+1))
	}
	os.Rename(s.Path, s.Path+".1")
	return s.open()
}

func (s *FileSink) Write(ms []Match) {
	var buf bytes.Buffer
	for i := range ms {
		b, err := json.Marshal(&ms[i])
		if err == nil {
			buf.Write(b)
			buf.WriteByte('\n')
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return
	}
	if s.MaxBytes > 0 && s.size > 0 && s.size+int64(buf.Len()) > s.MaxBytes {
		if err := s.rotate(); err != nil {
			return
		}
	}
	n, _ := s.f.Write(buf.Bytes())
	s.size += int64(n)
}

func (s *FileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return nil
	}
	err := s.f.Close()
	s.f = nil
	return err
}

// ---- signed delivery to the platform, with a disk spool ---------------------------------------------------------------------------------------

// PostConfig configures delivery to the platform.
type PostConfig struct {
	URL      string
	Secret   []byte
	SpoolDir string // where batches wait while the platform cannot be reached
	SpoolMax int64  // bytes; the oldest batch is dropped (and counted) beyond it. Default 100 MB
	BatchMax int    // matches per request. Default 100
	BatchAge time.Duration
	Queue    int // matches waiting to be batched. Default 20,000
	Client   *http.Client
	Retries  int           // attempts for a live batch before it goes to the spool. Default 3
	Backoff  time.Duration // first retry delay, doubled each time. Default 1 s
	Drain    time.Duration // how often the spool is retried at first. Default 5 s (doubled while the platform stays down, up to 60 s)
	Stats    *Stats
	Logf     func(format string, args ...any)
	Now      func() time.Time
}

type spoolFile struct {
	name string
	size int64
	n    int
}

// PostSink batches matches and POSTs them as a JSON array with X-Argus-Timestamp and X-Argus-Signature: sha256=<hex HMAC-SHA256 of
// timestamp + "." + body>. A batch that cannot be delivered after a few retries is written to the spool and re-sent, in order, once the platform
// answers again; a full queue or spool drops (and counts), it never blocks the reader.
type PostSink struct {
	cfg   PostConfig
	in    chan Match
	done  chan struct{}
	stop  chan struct{}
	wg    sync.WaitGroup
	mu    sync.Mutex  // guards files and bytes (the delivery goroutine writes them, SpoolLen reads them)
	files []spoolFile // the spool, oldest first
	bytes int64
	seq   int
	// drain schedule
	nextDrain time.Time
	drainWait time.Duration
}

var errPermanent = errors.New("rejected by the platform")

// NewPostSink starts the delivery goroutine.
func NewPostSink(cfg PostConfig) (*PostSink, error) {
	if cfg.URL == "" {
		return nil, errors.New("no URL to deliver to")
	}
	if len(cfg.Secret) == 0 {
		return nil, errors.New("no secret to sign with")
	}
	if cfg.SpoolMax <= 0 {
		cfg.SpoolMax = 100 << 20
	}
	if cfg.BatchMax <= 0 {
		cfg.BatchMax = 100
	}
	if cfg.BatchAge <= 0 {
		cfg.BatchAge = 3 * time.Second
	}
	if cfg.Queue <= 0 {
		cfg.Queue = 20000
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 15 * time.Second}
	}
	if cfg.Retries <= 0 {
		cfg.Retries = 3
	}
	if cfg.Backoff <= 0 {
		cfg.Backoff = time.Second
	}
	if cfg.Drain <= 0 {
		cfg.Drain = 5 * time.Second
	}
	if cfg.Stats == nil {
		cfg.Stats = &Stats{}
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	p := &PostSink{cfg: cfg, in: make(chan Match, cfg.Queue), done: make(chan struct{}), stop: make(chan struct{}), drainWait: cfg.Drain}
	if cfg.SpoolDir != "" {
		if err := os.MkdirAll(cfg.SpoolDir, 0o755); err != nil {
			return nil, err
		}
		p.scanSpool()
	}
	p.wg.Add(1)
	go p.run()
	return p, nil
}

// Write queues the matches; a full queue drops them (counted).
func (p *PostSink) Write(ms []Match) {
	for i := range ms {
		select {
		case p.in <- ms[i]:
		default:
			p.cfg.Stats.DroppedMatches.Add(1)
		}
	}
}

// Close stops accepting, makes a last attempt to deliver what is queued (the rest goes to the spool) and returns.
func (p *PostSink) Close() error {
	close(p.stop)
	p.wg.Wait()
	return nil
}

func (p *PostSink) run() {
	defer p.wg.Done()
	var batch []Match
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	armed := false
	tickEvery := p.cfg.Drain / 2
	if tickEvery > time.Second {
		tickEvery = time.Second
	}
	if tickEvery < 5*time.Millisecond {
		tickEvery = 5 * time.Millisecond
	}
	drainTick := time.NewTicker(tickEvery)
	defer drainTick.Stop()
	flush := func(final bool) {
		if len(batch) > 0 {
			p.deliver(batch, final)
			batch = nil
		}
		if armed && !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		armed = false
	}
	for {
		select {
		case m := <-p.in:
			batch = append(batch, m)
			if !armed {
				timer.Reset(p.cfg.BatchAge)
				armed = true
			}
			if len(batch) >= p.cfg.BatchMax {
				flush(false)
			}
		case <-timer.C:
			armed = false
			flush(false)
		case <-drainTick.C:
			p.drain()
		case <-p.stop:
			for { // take what is already queued
				select {
				case m := <-p.in:
					batch = append(batch, m)
					if len(batch) >= p.cfg.BatchMax {
						flush(true)
					}
					continue
				default:
				}
				break
			}
			flush(true)
			return
		}
	}
}

// deliver sends a batch, or spools it. While the spool holds older batches a new one is spooled too, so the platform sees them in order.
func (p *PostSink) deliver(batch []Match, final bool) {
	body, err := json.Marshal(batch)
	if err != nil {
		p.cfg.Stats.DroppedMatches.Add(int64(len(batch)))
		return
	}
	if p.SpoolLen() == 0 {
		attempts := p.cfg.Retries
		if final {
			attempts = 1
		}
		wait := p.cfg.Backoff
		for a := 1; a <= attempts; a++ {
			err = p.send(body)
			if err == nil {
				p.cfg.Stats.Delivered.Add(int64(len(batch)))
				return
			}
			if errors.Is(err, errPermanent) {
				p.cfg.Logf("the platform refused a batch of %d matches for good: %v", len(batch), err)
				p.cfg.Stats.Rejected.Add(int64(len(batch)))
				return
			}
			p.cfg.Stats.PostFailures.Add(1)
			if a < attempts {
				select {
				case <-time.After(wait):
				case <-p.stop:
					a = attempts
				}
				wait *= 2
			}
		}
		p.cfg.Logf("could not deliver %d matches (%v): spooled", len(batch), err)
	}
	p.spoolWrite(body, len(batch))
}

// send makes one signed POST. 2xx is success; 400, 413 and 422 mean this body will never be accepted (errPermanent); anything else is retried.
func (p *PostSink) send(body []byte) error {
	ts := strconv.FormatInt(p.cfg.Now().Unix(), 10)
	mac := hmac.New(sha256.New, p.cfg.Secret)
	mac.Write([]byte(ts + "."))
	mac.Write(body)
	req, err := http.NewRequest(http.MethodPost, p.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%w: %v", errPermanent, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "argus-monitor/1")
	req.Header.Set("X-Argus-Timestamp", ts)
	req.Header.Set("X-Argus-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	resp, err := p.cfg.Client.Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	resp.Body.Close()
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == 400 || resp.StatusCode == 413 || resp.StatusCode == 422:
		return fmt.Errorf("%w: HTTP %d", errPermanent, resp.StatusCode)
	}
	return fmt.Errorf("HTTP %d", resp.StatusCode)
}

// ---- the spool ------------------------------------------------------------------------------------------------------------------------------

func (p *PostSink) scanSpool() {
	p.mu.Lock()
	defer p.mu.Unlock()
	entries, err := os.ReadDir(p.cfg.SpoolDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		parts := strings.Split(strings.TrimSuffix(e.Name(), ".json"), "-")
		n := 1
		if len(parts) == 3 {
			if v, err := strconv.Atoi(parts[2]); err == nil {
				n = v
			}
		}
		p.files = append(p.files, spoolFile{name: e.Name(), size: info.Size(), n: n})
		p.bytes += info.Size()
	}
	sort.Slice(p.files, func(i, j int) bool { return p.files[i].name < p.files[j].name })
}

func (p *PostSink) spoolWrite(body []byte, n int) {
	if p.cfg.SpoolDir == "" {
		p.cfg.Stats.SpoolDropped.Add(int64(n))
		p.cfg.Logf("no spool directory: %d matches lost", n)
		return
	}
	p.seq++
	name := fmt.Sprintf("%020d-%06d-%d.json", p.cfg.Now().UnixNano(), p.seq, n)
	if err := writeFileAtomic(filepath.Join(p.cfg.SpoolDir, name), body); err != nil {
		p.cfg.Stats.SpoolDropped.Add(int64(n))
		p.cfg.Logf("could not write the spool: %v (%d matches lost)", err, n)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.files = append(p.files, spoolFile{name: name, size: int64(len(body)), n: n})
	p.bytes += int64(len(body))
	p.cfg.Stats.Spooled.Add(int64(n))
	for p.bytes > p.cfg.SpoolMax && len(p.files) > 1 { // the oldest goes first
		old := p.files[0]
		p.files = p.files[1:]
		p.bytes -= old.size
		os.Remove(filepath.Join(p.cfg.SpoolDir, old.name))
		p.cfg.Stats.SpoolDropped.Add(int64(old.n))
		p.cfg.Logf("the spool is full: dropped the oldest batch (%d matches)", old.n)
	}
}

// drain re-sends spooled batches, oldest first, while the platform answers; it backs off (5 s doubling up to 60 s) while it does not.
func (p *PostSink) drain() {
	if p.SpoolLen() == 0 {
		return
	}
	now := p.cfg.Now()
	if now.Before(p.nextDrain) {
		return
	}
	for p.SpoolLen() > 0 {
		p.mu.Lock()
		f := p.files[0]
		p.mu.Unlock()
		body, err := os.ReadFile(filepath.Join(p.cfg.SpoolDir, f.name))
		if err == nil {
			err = p.send(body)
		}
		switch {
		case err == nil:
			p.cfg.Stats.Delivered.Add(int64(f.n))
		case errors.Is(err, errPermanent) || os.IsNotExist(err):
			p.cfg.Logf("dropping a spooled batch of %d matches: %v", f.n, err)
			p.cfg.Stats.Rejected.Add(int64(f.n))
		default:
			p.cfg.Stats.PostFailures.Add(1)
			p.drainWait *= 2
			if p.drainWait > time.Minute {
				p.drainWait = time.Minute
			}
			p.nextDrain = now.Add(p.drainWait)
			return
		}
		os.Remove(filepath.Join(p.cfg.SpoolDir, f.name))
		p.mu.Lock()
		p.files = p.files[1:]
		p.bytes -= f.size
		p.mu.Unlock()
		p.drainWait = p.cfg.Drain
	}
	p.nextDrain = time.Time{}
}

// SpoolLen is the number of batches waiting in the spool.
func (p *PostSink) SpoolLen() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.files)
}
