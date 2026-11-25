//go:build !nomonitor

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/mr-rizwan-syed/argus/pkg/ctlog"
	"github.com/mr-rizwan-syed/argus/pkg/monitor"
)

const monitorUsage = `argus monitor: read Certificate Transparency logs and report the certificates that match your rules.

  argus monitor -rules rules.json -out matches.jsonl
  argus monitor -rules-url https://platform/api/ct/rules -rules-secret-file /etc/argus/rules.secret \
                -post-url https://platform/api/ct/matches -post-secret-file /etc/argus/post.secret -spool-dir /var/lib/argus/spool \
                -log-state /var/lib/argus/ct-state.json -stats-file /var/lib/argus/ct-stats.json

Flags:
`

// lagSource wraps the CT reader so the monitor can report how far behind the logs it is: the age of the newest log timestamp seen.
type lagSource struct {
	ctlog.Source
	newest atomic.Int64 // unix nanoseconds of the newest log timestamp seen
}

func (l *lagSource) Run(ctx context.Context, emit func(ctlog.Entry)) error {
	return l.Source.Run(ctx, func(e ctlog.Entry) {
		if !e.Logged.IsZero() {
			if t := e.Logged.UnixNano(); t > l.newest.Load() {
				l.newest.Store(t)
			}
		}
		emit(e)
	})
}

func (l *lagSource) Lag() time.Duration {
	t := l.newest.Load()
	if t == 0 {
		return 0
	}
	if d := time.Since(time.Unix(0, t)); d > 0 {
		return d
	}
	return 0
}

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, strings.Split(v, ",")...); return nil }

func readSecret(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s := strings.TrimSpace(string(data))
	if s == "" {
		return nil, fmt.Errorf("%s is empty", path)
	}
	return []byte(s), nil
}

// runMonitor is `argus monitor ...`. It returns the process exit code.
func runMonitor(args []string) int {
	fs := flag.NewFlagSet("monitor", flag.ContinueOnError)
	var (
		source        = fs.String("source", "ctlog", "Where certificates come from: ctlog (the public logs) or replay (a JSONL file of entries)")
		replay        = fs.String("replay", "", "replay: the JSONL file of entries (- for stdin)")
		replayRate    = fs.Int("replay-rate", 0, "replay: entries per second (0 = as fast as possible)")
		rulesFile     = fs.String("rules", "", "Rules file (JSON); re-read when it changes")
		rulesURL      = fs.String("rules-url", "", "Rules over HTTPS (plain HTTP only for localhost); re-read every minute with ETag")
		rulesSecret   = fs.String("rules-secret-file", "", "File holding the bearer secret for -rules-url")
		minScore      = fs.Int("min-score", 50, "Drop hits scoring less than this (0-100)")
		dailyCap      = fs.Int("daily-cap", 500, "Most hits per rule per UTC day (then one rule_noisy event)")
		dedupeWindow  = fs.Duration("dedupe-window", 24*time.Hour, "The same hit (rule, kind, name) is reported once per window")
		out           = fs.String("out", "", "Append matches as JSON lines to this file (rotated at 100 MB, 3 kept)")
		stdout        = fs.Bool("stdout", false, "Print matches as JSON lines to stdout")
		postURL       = fs.String("post-url", "", "POST batches of matches (signed) to this URL")
		postSecret    = fs.String("post-secret-file", "", "File holding the secret that signs the posts")
		spoolDir      = fs.String("spool-dir", "", "Where undelivered batches wait (default: a folder next to -out or in the temp directory)")
		spoolMaxMB    = fs.Int("spool-max-mb", 100, "Disk the spool may use; the oldest batch is dropped beyond it")
		statsFile     = fs.String("stats-file", "", "Write the statistics here (JSON, atomic) every interval")
		statsPost     = fs.String("stats-post-url", "", "POST the statistics (a heartbeat: rate, lag, drops) to this URL every interval, signed like the matches (needs -post-secret-file)")
		statsInterval = fs.Duration("stats-interval", time.Minute, "How often statistics are logged and written")
		workers       = fs.Int("workers", 2, "Matching goroutines")
		queue         = fs.Int("queue", 20000, "Entries waiting for a worker")
		logState      = fs.String("log-state", "", "File that remembers the position in every log, so a restart continues where it stopped")
		backfill      = fs.Uint64("backfill", 0, "Entries before the head to read in a log with no saved position")
		logListFile   = fs.String("loglist-file", "", "A local CT log list instead of Google's")
		include       listFlag
		exclude       listFlag
	)
	fs.Var(&include, "include-operator", "Only logs of these operators (repeatable or comma separated)")
	fs.Var(&exclude, "exclude-operator", "Skip logs of these operators (repeatable or comma separated)")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), monitorUsage)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	logger := log.New(os.Stderr, "", log.LstdFlags|log.LUTC)
	logf := func(format string, a ...any) { logger.Printf(format, a...) }
	fail := func(format string, a ...any) int {
		fmt.Fprintf(os.Stderr, "argus monitor: "+format+"\n", a...)
		return 2
	}

	// rules
	var rules monitor.RuleSource
	switch {
	case *rulesFile != "" && *rulesURL != "":
		return fail("use -rules or -rules-url, not both")
	case *rulesFile != "":
		rules = &monitor.FileRules{Path: *rulesFile}
	case *rulesURL != "":
		if err := monitor.CheckRulesURL(*rulesURL); err != nil {
			return fail("%v", err)
		}
		u := &monitor.URLRules{URL: *rulesURL}
		if *rulesSecret != "" {
			s, err := readSecret(*rulesSecret)
			if err != nil {
				return fail("-rules-secret-file: %v", err)
			}
			u.Secret = string(s)
		}
		rules = u
	default:
		return fail("give the rules: -rules <file> or -rules-url <url>")
	}

	// source
	var src ctlog.Source
	switch *source {
	case "ctlog":
		r, err := ctlog.New(ctlog.Options{
			LogListFile: *logListFile, StatePath: *logState, Backfill: *backfill,
			IncludeOperators: include, ExcludeOperators: exclude, Logger: ctlog.LoggerFrom(logger),
		})
		if err != nil {
			return fail("%v", err)
		}
		src = &lagSource{Source: r}
	case "replay":
		if *replay == "" {
			return fail("-source replay needs -replay <file>")
		}
		f := os.Stdin
		if *replay != "-" {
			var err error
			if f, err = os.Open(*replay); err != nil {
				return fail("%v", err)
			}
			defer f.Close()
		}
		src = &monitor.ReplaySource{R: f, Rate: *replayRate}
	default:
		return fail("-source must be ctlog or replay")
	}

	// outputs
	stats := &monitor.Stats{}
	var sinks []monitor.Sink
	if *stdout {
		sinks = append(sinks, monitor.NewStdoutSink(os.Stdout))
	}
	if *out != "" {
		s, err := monitor.NewFileSink(*out)
		if err != nil {
			return fail("-out: %v", err)
		}
		sinks = append(sinks, s)
	}
	if *postURL != "" {
		if *postSecret == "" {
			return fail("-post-url needs -post-secret-file")
		}
		secret, err := readSecret(*postSecret)
		if err != nil {
			return fail("-post-secret-file: %v", err)
		}
		spool := *spoolDir
		if spool == "" {
			spool = os.TempDir() + "/argus-spool"
		}
		if err := os.MkdirAll(spool, 0o700); err != nil {
			return fail("-spool-dir: %v", err)
		}
		p, err := monitor.NewPostSink(monitor.PostConfig{URL: *postURL, Secret: secret, SpoolDir: spool, SpoolMax: int64(*spoolMaxMB) << 20, Stats: stats, Logf: logf})
		if err != nil {
			return fail("-post-url: %v", err)
		}
		sinks = append(sinks, p)
	}
	if len(sinks) == 0 {
		return fail("no output: give -out, -stdout or -post-url")
	}

	var onStats func(monitor.Snapshot)
	if *statsPost != "" {
		if *postSecret == "" {
			return fail("-stats-post-url needs -post-secret-file")
		}
		secret, err := readSecret(*postSecret)
		if err != nil {
			return fail("-post-secret-file: %v", err)
		}
		poster, err := monitor.NewStatsPoster(*statsPost, secret, logf)
		if err != nil {
			return fail("-stats-post-url: %v", err)
		}
		onStats = poster.Send
	}
	m := monitor.New(monitor.Config{
		Source: src, Rules: rules, Sinks: sinks, MinScore: *minScore, DailyCap: *dailyCap, DedupeWindow: *dedupeWindow,
		Workers: *workers, Queue: *queue, StatsInterval: *statsInterval, StatsFile: *statsFile, OnStats: onStats, Logf: logf, Stats: stats,
	})
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	logf("argus monitor starting (source %s)", *source)
	if err := m.Run(ctx); err != nil && ctx.Err() == nil {
		fmt.Fprintf(os.Stderr, "argus monitor: %v\n", err)
		return 1
	}
	logf("argus monitor stopped")
	return 0
}
