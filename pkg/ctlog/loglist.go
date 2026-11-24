package ctlog

// The log list: which logs exist, who runs them and whether they still accept certificates. The list Chrome uses is published by Google at
// https://www.gstatic.com/ct/log_list/v3/log_list.json (JSON schema version 3). Operators have `logs` (RFC 6962: one URL serves both
// submission and reading) and `tiled_logs` (Static CT API: a submission URL and a separate monitoring URL).
//
// Only logs whose state is "usable" or "qualified" are monitored: those are the ones that accept new certificates. "readonly", "retired",
// "rejected" and "pending" logs hold history, not news.

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Protocol of a log.
const (
	ProtoRFC6962 = "rfc6962"
	ProtoStatic  = "static"
)

// LogInfo is one monitorable log, reduced from the log list.
type LogInfo struct {
	Name     string // the description in the list, e.g. "Sectigo Statue2027h1"
	Operator string // e.g. "Sectigo"
	URL      string // RFC 6962: the log URL; static: the monitoring URL; always ends with "/"
	Protocol string // ProtoRFC6962 or ProtoStatic
	State    string // "usable" or "qualified"

	// Interval during which the certificates logged here expire (the "temporal interval"); zero when the list gives none. A log whose interval
	// starts far in the future gets little or no traffic yet.
	IntervalStart, IntervalEnd time.Time
}

type logListFile struct {
	Operators []struct {
		Name string `json:"name"`
		Logs []struct {
			Description string                     `json:"description"`
			URL         string                     `json:"url"`
			State       map[string]json.RawMessage `json:"state"`
			Temporal    *temporalInterval          `json:"temporal_interval"`
		} `json:"logs"`
		TiledLogs []struct {
			Description   string                     `json:"description"`
			MonitoringURL string                     `json:"monitoring_url"`
			State         map[string]json.RawMessage `json:"state"`
			Temporal      *temporalInterval          `json:"temporal_interval"`
		} `json:"tiled_logs"`
	} `json:"operators"`
}

type temporalInterval struct {
	Start string `json:"start_inclusive"`
	End   string `json:"end_exclusive"`
}

// ParseLogList reads a log list (schema v3) and returns the logs that accept new certificates, in the order of the list.
func ParseLogList(data []byte) ([]LogInfo, error) {
	var f logListFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("ctlog: reading the log list: %w", err)
	}
	if len(f.Operators) == 0 {
		return nil, fmt.Errorf("ctlog: the log list has no operators")
	}
	var out []LogInfo
	add := func(operator, desc, url, proto string, state map[string]json.RawMessage, t *temporalInterval) {
		st := logState(state)
		if (st != "usable" && st != "qualified") || url == "" {
			return
		}
		if !strings.HasSuffix(url, "/") {
			url += "/"
		}
		l := LogInfo{Name: desc, Operator: operator, URL: url, Protocol: proto, State: st}
		if t != nil {
			l.IntervalStart, _ = time.Parse(time.RFC3339, t.Start)
			l.IntervalEnd, _ = time.Parse(time.RFC3339, t.End)
		}
		out = append(out, l)
	}
	for _, op := range f.Operators {
		for _, l := range op.Logs {
			add(op.Name, l.Description, l.URL, ProtoRFC6962, l.State, l.Temporal)
		}
		for _, l := range op.TiledLogs {
			add(op.Name, l.Description, l.MonitoringURL, ProtoStatic, l.State, l.Temporal)
		}
	}
	return out, nil
}

// logState is the one key of a log's state object ("usable", "readonly", ...), or "" when there is none.
func logState(state map[string]json.RawMessage) string {
	for k := range state {
		return k
	}
	return ""
}

// filter applies the include and exclude options. A log is kept when there are no include filters or it matches one, and it matches no exclude.
func filterLogs(logs []LogInfo, o *Options) []LogInfo {
	norm := func(list []string) []string {
		out := make([]string, 0, len(list))
		for _, s := range list {
			s = strings.ToLower(strings.TrimSpace(s))
			if s != "" {
				out = append(out, strings.TrimSuffix(s, "/"))
			}
		}
		return out
	}
	incOp, excOp, incURL, excURL := norm(o.IncludeOperators), norm(o.ExcludeOperators), norm(o.IncludeURLs), norm(o.ExcludeURLs)
	has := func(list []string, s string) bool {
		for _, x := range list {
			if x == s {
				return true
			}
		}
		return false
	}
	var out []LogInfo
	for _, l := range logs {
		op, url := strings.ToLower(l.Operator), strings.TrimSuffix(strings.ToLower(l.URL), "/")
		if len(incOp)+len(incURL) > 0 && !has(incOp, op) && !has(incURL, url) {
			continue
		}
		if has(excOp, op) || has(excURL, url) {
			continue
		}
		out = append(out, l)
	}
	return out
}
