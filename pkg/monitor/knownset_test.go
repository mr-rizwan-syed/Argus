package monitor

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/mr-rizwan-syed/argus/pkg/ctlog"
)

// The platform computes the same hash (Ingester/test/scopeWatch.test.js has the same vector): sha256("<salt>\n<name>")[:16] as hex.
func TestKnownHashVector(t *testing.T) {
	if got, want := KnownHash("rule-1", "WWW.Example.com"), KnownHash("rule-1", "www.example.com"); got != want {
		t.Fatalf("the name is lower-cased before hashing: %s vs %s", got, want)
	}
	// computed independently in Python: sha256(b"rule-1\nwww.example.com").hexdigest()[:32]
	if got := KnownHash("rule-1", "www.example.com"); got != "eda62df81ff0da542b8ece007b006ee3" {
		t.Fatalf("the hash changed: %s (the platform must compute the same value)", got)
	}
	if got := KnownHash("salt", "a.example.com"); len(got) != 32 {
		t.Fatalf("want 32 hex characters, got %q", got)
	}
	if KnownHash("salt-a", "a.example.com") == KnownHash("salt-b", "a.example.com") {
		t.Fatal("two salts must give two hashes for the same host")
	}
}

func setFile(t *testing.T, rules []Rule, salt string, known ...string) *RuleSet {
	t.Helper()
	hashes := make([]string, 0, len(known))
	for _, k := range known {
		hashes = append(hashes, KnownHash(salt, k))
	}
	raw, err := json.Marshal(RuleFile{Version: 1, Rules: rules, Sets: map[string]KnownSet{"s1": {Salt: salt, Hashes: hashes}}})
	if err != nil {
		t.Fatal(err)
	}
	set, err := ParseRules(raw)
	if err != nil {
		t.Fatalf("ParseRules: %v", err)
	}
	return set
}

func hitsFor(t *testing.T, set *RuleSet, en ctlog.Entry) []Match {
	t.Helper()
	e, err := Compile(set, EngineOptions{MinScore: 50})
	if err != nil {
		t.Fatal(err)
	}
	en.Seen = time.Now()
	return e.Match(en, nil)
}

func TestKnownSetDropsKnownHostsAndKeepsNewOnes(t *testing.T) {
	set := setFile(t, []Rule{{ID: "r1", Apexes: []string{"example.com"}, KnownSet: "s1"}}, "r1", "www.example.com", "api.example.com", "legacy.example.com")
	hits := hitsFor(t, set, ctlog.Entry{Names: []string{"www.example.com", "new.example.com", "api.example.com"}})
	if len(hits) != 1 || hits[0].Domain != "new.example.com" {
		t.Fatalf("only the host that is not in the set may be reported, got %+v", hits)
	}
}

func TestKnownSetCoversSubdomainsOfAKnownHostAndWildcards(t *testing.T) {
	set := setFile(t, []Rule{{ID: "r1", Apexes: []string{"example.com"}, KnownSet: "s1"}}, "r1", "corp.example.com")
	hits := hitsFor(t, set, ctlog.Entry{Names: []string{"a.b.corp.example.com", "*.corp.example.com", "corp.example.com", "other.example.com"}})
	if len(hits) != 1 || hits[0].Domain != "other.example.com" {
		t.Fatalf("everything under a known host is known, got %+v", hits)
	}
}

func TestKnownSetAppliesToEveryKindOfHit(t *testing.T) {
	set := setFile(t, []Rule{{ID: "r1", Apexes: []string{"example.com"}, Keywords: []string{"example"}, Orgs: []string{"Example Corp"}, KnownSet: "s1"}}, "r1",
		"example-mirror.net", "login.partner.example")
	// a brand word inside a name the user already knows (their own other domain)
	if hits := hitsFor(t, set, ctlog.Entry{Names: []string{"example-mirror.net"}}); len(hits) != 0 {
		t.Fatalf("a keyword hit on a known host must be dropped: %+v", hits)
	}
	if hits := hitsFor(t, set, ctlog.Entry{Names: []string{"example-evil.net"}}); len(hits) == 0 {
		t.Fatal("a keyword hit on an unknown host must stay")
	}
	// an organization hit names the foreign host; known hosts are dropped, others stay
	hits := hitsFor(t, set, ctlog.Entry{Names: []string{"login.partner.example", "new.partner.example"}, SubjectO: "Example Corp"})
	for _, h := range hits {
		if h.Domain == "login.partner.example" {
			t.Fatalf("an organization hit on a known host must be dropped: %+v", h)
		}
	}
	found := false
	for _, h := range hits {
		if h.Domain == "new.partner.example" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the unknown host must still be reported: %+v", hits)
	}
}

func TestKnownSetIsPerRuleAndSaltedPerSet(t *testing.T) {
	// the set is salted for r1: a rule that uses it with another salt would not match, and a rule without the set is unaffected
	set := setFile(t, []Rule{{ID: "r1", Apexes: []string{"example.com"}, KnownSet: "s1"}, {ID: "r2", Apexes: []string{"example.com"}}}, "r1", "www.example.com")
	hits := hitsFor(t, set, ctlog.Entry{Names: []string{"www.example.com"}})
	if len(hits) != 1 || hits[0].RuleID != "r2" {
		t.Fatalf("only the rule WITHOUT the set reports its known host: %+v", hits)
	}
}

func TestKnownSetsAreValidated(t *testing.T) {
	good := KnownHash("s", "a.example.com")
	cases := map[string]string{
		"a rule naming a set that does not exist": `{"version":1,"rules":[{"id":"r","apexes":["example.com"],"known_set":"nope"}]}`,
		"a hash of the wrong length":              `{"version":1,"rules":[{"id":"r","apexes":["example.com"],"known_set":"s"}],"sets":{"s":{"salt":"s","hashes":["abcd"]}}}`,
		"a hash that is not hex":                  `{"version":1,"rules":[{"id":"r","apexes":["example.com"],"known_set":"s"}],"sets":{"s":{"salt":"s","hashes":["` + strings.Repeat("z", 32) + `"]}}}`,
		"a set without a salt":                    `{"version":1,"rules":[{"id":"r","apexes":["example.com"],"known_set":"s"}],"sets":{"s":{"salt":"","hashes":["` + good + `"]}}}`,
		"a bad set name":                          `{"version":1,"rules":[{"id":"r","apexes":["example.com"]}],"sets":{"bad name":{"salt":"s","hashes":[]}}}`,
	}
	for name, raw := range cases {
		if _, err := ParseRules([]byte(raw)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	ok := `{"version":1,"rules":[{"id":"r","apexes":["example.com"],"known_set":"s"}],"sets":{"s":{"salt":"s","hashes":["` + good + `"]}}}`
	if _, err := ParseRules([]byte(ok)); err != nil {
		t.Fatalf("a good file was refused: %v", err)
	}
}

// The reason for the design: known hosts must not use the daily cap up. 600 distinct known hosts, then one new host: the new one must still be reported.
func TestKnownHostsDoNotUseTheDailyCapUp(t *testing.T) {
	known := make([]string, 0, 600)
	for i := 0; i < 600; i++ {
		known = append(known, fmt.Sprintf("h%d.example.com", i))
	}
	set := setFile(t, []Rule{{ID: "r1", Apexes: []string{"example.com"}, KnownSet: "s1"}}, "r1", known...)
	e, err := Compile(set, EngineOptions{MinScore: 50})
	if err != nil {
		t.Fatal(err)
	}
	f := NewFilter(time.Hour, 500, 0)
	var reported []Match
	feed := func(name string) {
		for _, m := range e.Match(ctlog.Entry{Names: []string{name}, Seen: time.Now()}, nil) {
			m := m
			ok, meta := f.Accept(&m)
			if ok {
				reported = append(reported, m)
			}
			if meta != nil {
				reported = append(reported, *meta)
			}
		}
	}
	for _, k := range known {
		feed(k)
	}
	feed("brand-new.example.com")
	if len(reported) != 1 || reported[0].Domain != "brand-new.example.com" {
		t.Fatalf("600 known hosts must cost nothing and the new host must be reported, got %d: %+v", len(reported), reported)
	}
}

func BenchmarkKnownSetCovers(b *testing.B) {
	hashes := make([]string, 0, 100000)
	for i := 0; i < 100000; i++ {
		hashes = append(hashes, KnownHash("s", fmt.Sprintf("h%d.example.com", i)))
	}
	hs, _ := newHashSet("s", KnownSet{Salt: "s", Hashes: hashes})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hs.Covers("a.b.unknown.example.org")
	}
}
