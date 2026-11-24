package monitor

import (
	"strings"
	"testing"
	"time"

	"github.com/mr-rizwan-syed/argus/pkg/ctlog"
)

func mustSet(t testing.TB, json string) *RuleSet {
	t.Helper()
	set, err := ParseRules([]byte(json))
	if err != nil {
		t.Fatalf("rules: %v", err)
	}
	return set
}

func mustEngine(t testing.TB, json string, minScore int) *Engine {
	t.Helper()
	e, err := Compile(mustSet(t, json), EngineOptions{MinScore: minScore})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

const testRules = `{"version":1,"rules":[
 {"id":"acme","name":"Acme","apexes":["acme.com"],"keywords":["acme"],"orgs":["Acme Corp"],"known":["status.acme.com"]},
 {"id":"paypal","apexes":["paypal.com"],"keywords":["paypal"]},
 {"id":"orange","keywords":["orange-farm"],"apexes":["orangefarmland.com"]},
 {"id":"megacorp","apexes":["megacorporation.com"],"keywords":["megacorporation"],"orgs":["MegaCorporation Holdings"]}
]}`

func entry(o string, names ...string) ctlog.Entry {
	return ctlog.Entry{Log: "Test Log", Operator: "Test", Index: 7, Seen: time.Unix(1_700_000_000, 0), Names: names, SubjectO: o, IssuerCN: "R3", Fingerprint: "ab12"}
}

type want struct {
	rule, kind, domain string
	score              int
}

func kinds(ms []Match) []want {
	var out []want
	for _, m := range ms {
		out = append(out, want{m.RuleID, m.Kind, m.Domain, m.Score})
	}
	return out
}

func find(ms []Match, rule, kind string) *Match {
	for i := range ms {
		if ms[i].RuleID == rule && ms[i].Kind == kind {
			return &ms[i]
		}
	}
	return nil
}

func TestSubdomainKind(t *testing.T) {
	e := mustEngine(t, testRules, 50)
	cases := []struct {
		name     string
		names    []string
		score    int
		wildcard bool
	}{
		{"a subdomain of the watched domain", []string{"support.acme.com"}, 90, false},
		{"a deep subdomain", []string{"a.b.c.acme.com"}, 90, false},
		{"the watched domain itself", []string{"acme.com"}, 80, false},
		{"a wildcard for the watched domain", []string{"*.acme.com"}, 85, true},
		{"a wildcard below it", []string{"*.eu.acme.com"}, 85, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ms := e.Match(entry("", c.names...), nil)
			m := find(ms, "acme", KindSubdomain)
			if m == nil {
				t.Fatalf("no subdomain hit: %v", kinds(ms))
			}
			if m.Score != c.score || m.Wildcard != c.wildcard || m.Matched != "acme.com" || m.NewDomain {
				t.Fatalf("score %d wildcard %v matched %q new_domain %v", m.Score, m.Wildcard, m.Matched, m.NewDomain)
			}
			if len(m.Reasons) == 0 || !strings.Contains(m.Reasons[0], "acme.com") {
				t.Fatalf("reason: %v", m.Reasons)
			}
		})
	}
}

func TestKnownHostsAreNeverReported(t *testing.T) {
	e := mustEngine(t, testRules, 50)
	for _, n := range []string{"status.acme.com", "eu.status.acme.com", "*.status.acme.com"} {
		if ms := e.Match(entry("", n), nil); len(ms) != 0 {
			t.Errorf("%s is known but reported: %v", n, kinds(ms))
		}
	}
	if ms := e.Match(entry("", "www.acme.com"), nil); find(ms, "acme", KindSubdomain) == nil {
		t.Error("a host that is not known must still be reported")
	}
}

func TestKeywordKind(t *testing.T) {
	e := mustEngine(t, testRules, 50)
	cases := []struct {
		name  string
		host  string
		score int // 0 = no keyword hit
	}{
		{"brand next to a risk word", "paypal-secure-login.xyz", 90},
		{"risk word first", "login-paypal.net", 90},
		{"a risk word in another label", "paypal.verify.evil.xyz", 90},
		{"brand as a word", "paypal-shop.net", 70},
		{"brand in a subdomain label (the classic trick)", "paypal.com.evil.xyz", 70},
		{"brand glued to a risk word is a substring", "paypalsecure.com", 50},
		{"brand glued at the end", "mypaypal.com", 50},
		{"brand buried in a long label is NOT reported", "burningorange-farmlandsandmore.com", 0},
		{"not the brand", "paypalish.com", 50},
		{"nothing", "example.org", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ms := e.Match(entry("", c.host), nil)
			rule := "paypal"
			if strings.Contains(c.host, "orange") {
				rule = "orange"
			}
			m := find(ms, rule, KindKeyword)
			if c.score == 0 {
				if m != nil {
					t.Fatalf("unexpected keyword hit: %+v", *m)
				}
				return
			}
			if m == nil {
				t.Fatalf("no keyword hit for %s: %v", c.host, kinds(ms))
			}
			if m.Score != c.score || !m.NewDomain {
				t.Fatalf("score %d (want %d) new_domain %v", m.Score, c.score, m.NewDomain)
			}
		})
	}
}

// A keyword shorter than five characters only counts as a whole word: "acme" must not fire inside notacme.com or pacmegroup.com.
func TestShortKeywordsAreWholeWordsOnly(t *testing.T) {
	e := mustEngine(t, testRules, 50)
	for _, h := range []string{"notacme.com", "pacmegroup.com", "acmeville.net", "macmeow.org"} {
		if ms := e.Match(entry("", h), nil); find(ms, "acme", KindKeyword) != nil {
			t.Errorf("%s: a four letter keyword matched inside a word", h)
		}
	}
	for _, h := range []string{"acme-login.net", "login.acme.evil.xyz", "my-acme.site"} {
		if ms := e.Match(entry("", h), nil); find(ms, "acme", KindKeyword) == nil {
			t.Errorf("%s: the whole word acme was not found", h)
		}
	}
	// and under the watched domain it is the subdomain kind, never brand abuse
	if ms := e.Match(entry("", "login.acme.com"), nil); find(ms, "acme", KindKeyword) != nil {
		t.Error("the organization's own domain is not brand abuse")
	}
}

func TestLookalikeKind(t *testing.T) {
	e := mustEngine(t, testRules, 50)
	cases := []struct {
		name  string
		host  string
		score int
		text  string
	}{
		{"digit for a letter", "paypa1.com", 85, "look-alike"},
		{"i for l", "paypai.com", 85, "look-alike"},
		{"two digits", "paypa1.net", 85, ""},
		{"4 for a", "payp4l.com", 85, ""},
		{"rn for m (megacorporation)", "rnegacorporation.com", 85, ""},
		{"Cyrillic lookalike, punycode form", "xn--l-7sba6dbr.com", 90, "internationalised"},
		{"mixed script, punycode form", "xn--pypal-4ve.com", 90, ""},
		{"Cyrillic as sent in raw characters", "раураl.com", 85, ""},
		{"fullwidth letters", "ｐａｙｐａｌ.com", 85, ""},
		{"a hyphen added", "pay-pal.com", 80, "hyphen"},
		{"another TLD", "paypal.net", 60, "instead of"},
		{"the TLD glued in", "paypal-com.xyz", 80, "glued"},
		{"one letter more", "paypall.com", 80, "one character"},
		{"one letter less", "paypa.com", 80, "one character"},
		{"two letters swapped", "paypla.com", 80, "one character"},
		{"one letter changed", "paypsl.com", 80, "one character"},
		{"in a subdomain label", "paypa1.com.evil.xyz", 85, ""},
		{"a token of a hyphenated name", "paypa1-support.xyz", 85, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ms := e.Match(entry("", c.host), nil)
			rule := "paypal"
			if strings.Contains(c.host, "negacorp") {
				rule = "megacorp"
			}
			m := find(ms, rule, KindLookalike)
			if m == nil {
				t.Fatalf("no look-alike hit for %s: %v", c.host, kinds(ms))
			}
			if m.Score != c.score {
				t.Fatalf("score %d, want %d (%v)", m.Score, c.score, m.Reasons)
			}
			if c.text != "" && !strings.Contains(m.Reasons[0], c.text) {
				t.Fatalf("reason %q lacks %q", m.Reasons[0], c.text)
			}
			if !m.NewDomain {
				t.Fatal("a look-alike is a new domain")
			}
		})
	}
}

func TestLookalikeNegatives(t *testing.T) {
	e := mustEngine(t, testRules, 50)
	for _, h := range []string{"paypal.com", "www.paypal.com", "example.com", "pay.com", "payment.net", "pypl.com", "pall.com", "payroll.com"} {
		ms := e.Match(entry("", h), nil)
		if m := find(ms, "paypal", KindLookalike); m != nil {
			// pypl and pall are two edits away from paypal: only long labels (9+) get two edits
			t.Errorf("%s reported as a look-alike: %+v", h, *m)
		}
	}
	// the exact apex is the subdomain kind, never a look-alike
	if ms := e.Match(entry("", "paypal.com"), nil); find(ms, "paypal", KindSubdomain) == nil || find(ms, "paypal", KindLookalike) != nil {
		t.Error("the apex itself")
	}
}

func TestTwoEditsOnlyForLongLabels(t *testing.T) {
	e := mustEngine(t, testRules, 50)
	// megacorporation is 15 letters: two edits count; paypal (6) allows one
	if m := find(e.Match(entry("", "megacorporatoin.com"), nil), "megacorp", KindLookalike); m == nil || m.Score != 80 {
		t.Errorf("a swap of two letters in a long label: %+v", m)
	}
	if m := find(e.Match(entry("", "mgacorporatin.com"), nil), "megacorp", KindLookalike); m == nil || m.Score != 65 {
		t.Errorf("two deletions in a long label: %+v", m)
	}
	if m := find(e.Match(entry("", "pyapl.com"), nil), "paypal", KindLookalike); m != nil {
		t.Errorf("two edits in a short label must not match: %+v", *m)
	}
}

func TestTLDSwapUsesRegistrableDomains(t *testing.T) {
	e := mustEngine(t, `{"version":1,"rules":[{"id":"acme","apexes":["acme.com"]}]}`, 50)
	m := find(e.Match(entry("", "acme.co.uk"), nil), "acme", KindLookalike)
	if m == nil || m.Score != 60 || !strings.Contains(m.Reasons[0], "co.uk") {
		t.Fatalf("acme.co.uk: %+v", m)
	}
	if find(e.Match(entry("", "shop.acme.net"), nil), "acme", KindLookalike) == nil {
		t.Error("a subdomain of another TLD is still the same name on another TLD")
	}
}

func TestOrgKind(t *testing.T) {
	e := mustEngine(t, testRules, 50)
	cases := []struct {
		o     string
		names []string
		score int
	}{
		{"ACME, Inc.", []string{"acme-portal.net"}, 95},
		{"Acme Incorporated", []string{"acme-portal.net"}, 95},
		{"acme corp", []string{"intranet.example.org"}, 95},
		{"The Acme Group Holdings Ltd", []string{"acme-group.example"}, 60},
		{"Acmeville Corp", []string{"acmeville.example"}, 0},
		{"Acme Corp", []string{"www.acme.com", "mail.acme.com"}, 0}, // all names are the organization's own: the subdomain kind's business
		{"Acme Corp", []string{"www.acme.com", "new-site.example.net"}, 95},
		{"Somebody Else", []string{"x.example.net"}, 0},
	}
	for _, c := range cases {
		t.Run(c.o, func(t *testing.T) {
			ms := e.Match(entry(c.o, c.names...), nil)
			m := find(ms, "acme", KindOrg)
			if c.score == 0 {
				if m != nil {
					t.Fatalf("unexpected: %+v", *m)
				}
				return
			}
			if m == nil || m.Score != c.score {
				t.Fatalf("got %v, want score %d", kinds(ms), c.score)
			}
			if !m.NewDomain || m.Domain == "" || strings.HasSuffix(m.Domain, "acme.com") {
				t.Fatalf("the org hit must name the foreign host, got %q", m.Domain)
			}
		})
	}
}

func TestMinScoreFilters(t *testing.T) {
	loose := mustEngine(t, testRules, 40)
	strict := mustEngine(t, testRules, 60)
	if find(loose.Match(entry("", "paypalsecure.com"), nil), "paypal", KindKeyword) == nil {
		t.Error("score 50 must pass a threshold of 40")
	}
	if find(strict.Match(entry("", "paypalsecure.com"), nil), "paypal", KindKeyword) != nil {
		t.Error("score 50 must not pass a threshold of 60")
	}
	if find(strict.Match(entry("", "paypal-secure-login.xyz"), nil), "paypal", KindKeyword) == nil {
		t.Error("score 90 must pass")
	}
}

func TestMatchRecordCarriesTheCertificateFacts(t *testing.T) {
	e := mustEngine(t, testRules, 50)
	en := entry("Some Org", "paypal-login.example", "a.example", "b.example")
	en.NotBefore, en.NotAfter = time.Unix(1_700_000_000, 0), time.Unix(1_707_000_000, 0)
	en.Logged = time.Unix(1_699_999_990, 0)
	ms := e.Match(en, nil)
	m := find(ms, "paypal", KindKeyword)
	if m == nil {
		t.Fatal("no hit")
	}
	if m.Log != "Test Log" || m.Operator != "Test" || m.Index != 7 || m.Fingerprint != "ab12" || m.IssuerCN != "R3" || m.SubjectO != "Some Org" ||
		m.NotBefore == nil || m.NotAfter == nil || m.Logged == nil || len(m.Names) != 3 || m.Seen.Unix() != 1_700_000_000 {
		t.Fatalf("%+v", *m)
	}
	many := make([]string, 60)
	for i := range many {
		many[i] = "n" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + ".example"
	}
	many[0] = "paypal-login.example"
	if ms := e.Match(entry("", many...), nil); len(ms) == 0 || len(ms[0].Names) != 20 {
		t.Fatalf("names are capped at 20: %d", len(ms[0].Names))
	}
}

func TestSeveralRulesOnOneName(t *testing.T) {
	e := mustEngine(t, `{"version":1,"rules":[
	 {"id":"a","keywords":["brandone"]},{"id":"b","keywords":["brandtwo"]},{"id":"c","keywords":["brandone"],"apexes":["brandone.org"]}]}`, 50)
	ms := e.Match(entry("", "brandone-brandtwo-login.xyz"), nil)
	got := map[string]bool{}
	for _, m := range ms {
		got[m.RuleID+"/"+m.Kind] = true
	}
	for _, k := range []string{"a/keyword", "b/keyword", "c/keyword"} {
		if !got[k] {
			t.Errorf("missing %s in %v", k, got)
		}
	}
	// rule c watches brandone.org: its own subdomain is not brand abuse for c, but is for a
	ms = e.Match(entry("", "brandone.org"), nil)
	if find(ms, "c", KindKeyword) != nil || find(ms, "c", KindSubdomain) == nil {
		t.Errorf("c: %v", kinds(ms))
	}
}

func TestEmptyAndOddInput(t *testing.T) {
	e := mustEngine(t, testRules, 50)
	odd := entry("", "", "*", "*.", "a", ".", "..", "x..y", strings.Repeat("a", 70)+".com", "*.*.acme.com", "UPPER.CASE.COM")
	_ = e.Match(odd, nil) // must not panic
	empty, _ := Compile(&RuleSet{}, EngineOptions{})
	if ms := empty.Match(entry("Acme", "acme.com"), nil); len(ms) != 0 {
		t.Error("an engine without rules reports nothing")
	}
}

func TestEngineIsSafeForConcurrentUse(t *testing.T) {
	e := mustEngine(t, testRules, 50)
	done := make(chan bool)
	for g := 0; g < 8; g++ {
		go func() {
			for i := 0; i < 2000; i++ {
				e.Match(entry("Acme Corp", "paypal-secure.xyz", "paypa1.com", "acme-portal.net"), nil)
			}
			done <- true
		}()
	}
	for g := 0; g < 8; g++ {
		<-done
	}
}
