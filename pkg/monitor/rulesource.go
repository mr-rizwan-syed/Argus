package monitor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// A RuleSource loads the rules. changed is false when nothing is new since the last successful call (the caller keeps what it has).
type RuleSource interface {
	Load(ctx context.Context) (set *RuleSet, changed bool, err error)
	String() string
}

const maxRulesBytes = 32 << 20

// FileRules reads a rules file; an unchanged file (same size and modification time) is not parsed again.
type FileRules struct {
	Path string
	size int64
	mod  time.Time
}

func (f *FileRules) String() string { return f.Path }

func (f *FileRules) Load(ctx context.Context) (*RuleSet, bool, error) {
	st, err := os.Stat(f.Path)
	if err != nil {
		return nil, false, err
	}
	if st.Size() == f.size && st.ModTime().Equal(f.mod) {
		return nil, false, nil
	}
	if st.Size() > maxRulesBytes {
		return nil, false, fmt.Errorf("the rules file is %d bytes: at most %d", st.Size(), maxRulesBytes)
	}
	data, err := os.ReadFile(f.Path)
	if err != nil {
		return nil, false, err
	}
	set, err := ParseRules(data)
	if err != nil {
		return nil, false, err
	}
	f.size, f.mod = st.Size(), st.ModTime()
	return set, true, nil
}

// URLRules fetches rules over HTTPS (plain HTTP only for localhost) with a bearer secret and ETag revalidation.
type URLRules struct {
	URL    string
	Secret string
	Client *http.Client
	etag   string
}

func (u *URLRules) String() string { return u.URL }

// CheckRulesURL refuses an address that would send the secret in the clear.
func CheckRulesURL(raw string) error {
	pu, err := url.Parse(raw)
	if err != nil || pu.Host == "" {
		return fmt.Errorf("%q is not a URL", raw)
	}
	if pu.Scheme == "https" {
		return nil
	}
	host := pu.Hostname()
	if pu.Scheme == "http" && (host == "localhost" || net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()) {
		return nil
	}
	return errors.New("the rules URL must be https (plain http is only accepted for localhost): the secret travels with every request")
}

// FetchError marks a failure to GET the rules (no connection, a bad HTTP status, a cut-off body), as opposed to a file that arrived and was refused. The first is the
// network's or the platform's trouble and heals by itself; the second means somebody's rules are wrong. They are counted apart (Stats.RuleFetchErrs, RuleReloadErrs).
type FetchError struct{ Err error }

func (e *FetchError) Error() string { return e.Err.Error() }
func (e *FetchError) Unwrap() error { return e.Err }

func (u *URLRules) Load(ctx context.Context) (*RuleSet, bool, error) {
	client := u.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.URL, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "argus-monitor/1")
	if u.Secret != "" {
		req.Header.Set("Authorization", "Bearer "+u.Secret)
	}
	if u.etag != "" {
		req.Header.Set("If-None-Match", u.etag)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, false, &FetchError{err}
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return nil, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, &FetchError{fmt.Errorf("the rules server answered HTTP %d", resp.StatusCode)}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxRulesBytes+1))
	if err != nil {
		return nil, false, &FetchError{err}
	}
	if len(data) > maxRulesBytes {
		return nil, false, fmt.Errorf("the rules document is longer than %d bytes", maxRulesBytes)
	}
	set, err := ParseRules(data)
	if err != nil {
		return nil, false, err
	}
	u.etag = strings.TrimSpace(resp.Header.Get("ETag"))
	return set, true, nil
}
