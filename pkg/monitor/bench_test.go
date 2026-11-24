package monitor

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/mr-rizwan-syed/argus/pkg/ctlog"
)

// benchWorld builds nRules rules (brand names like "voltaris", their apex, one keyword, an organization) and a stream of realistic entries:
// mostly unrelated names (random labels on common TLDs, 1-3 names per certificate, a few wildcard and long ones), a few percent with an organization,
// and a few hits of every kind.
func benchWorld(nRules, nEntries int) (*Engine, []ctlog.Entry) {
	rng := rand.New(rand.NewSource(1))
	syll := []string{"vo", "lta", "ris", "ne", "xus", "mar", "tel", "qua", "dro", "zen", "bri", "col", "fa", "gen", "hy", "ion", "ja", "kor", "lum", "mon", "nov", "ora", "pex", "ryn", "sol", "tri", "uni", "vel", "wyn", "xen", "yor", "zor"}
	word := func(minSyl, maxSyl int) string {
		n := minSyl + rng.Intn(maxSyl-minSyl+1)
		var b strings.Builder
		for i := 0; i < n; i++ {
			b.WriteString(syll[rng.Intn(len(syll))])
		}
		return b.String()
	}
	var rules strings.Builder
	rules.WriteString(`{"version":1,"rules":[`)
	brands := make([]string, nRules)
	for i := 0; i < nRules; i++ {
		b := word(2, 4)
		brands[i] = b
		if i > 0 {
			rules.WriteString(",")
		}
		fmt.Fprintf(&rules, `{"id":"r%d","apexes":["%s.com","%s-group.net"],"keywords":["%s"],"orgs":["%s Holdings"]}`, i, b, b, b, strings.ToUpper(b[:1])+b[1:])
	}
	rules.WriteString("]}")
	set, err := ParseRules([]byte(rules.String()))
	if err != nil {
		panic(err)
	}
	e, err := Compile(set, EngineOptions{})
	if err != nil {
		panic(err)
	}
	tlds := []string{"com", "net", "org", "io", "co.uk", "de", "fr", "app", "xyz", "info", "com.br", "nl"}
	subs := []string{"www", "mail", "api", "dev", "shop", "cdn", "login", "vpn", "m"}
	entries := make([]ctlog.Entry, nEntries)
	for i := range entries {
		var names []string
		for k := 0; k < 1+rng.Intn(3); k++ {
			base := randLabel(rng) + "." + tlds[rng.Intn(len(tlds))]
			n := base
			if rng.Intn(2) == 0 {
				n = subs[rng.Intn(len(subs))] + "." + base
			}
			if rng.Intn(10) == 0 {
				n = "*." + base
			}
			names = append(names, n)
		}
		en := ctlog.Entry{Names: names, Seen: time.Unix(1_700_000_000, 0), Fingerprint: "ab"}
		if rng.Intn(14) == 0 {
			en.SubjectO = strings.Title(randLabel(rng)) + " Ltd"
		}
		switch rng.Intn(400) { // a few real hits
		case 0:
			en.Names = append(en.Names, "www."+brands[rng.Intn(nRules)]+".com")
		case 1:
			en.Names = append(en.Names, brands[rng.Intn(nRules)]+"-secure-login.xyz")
		case 2:
			b := brands[rng.Intn(nRules)]
			en.Names = append(en.Names, b[:len(b)-1]+".com.evil.xyz")
		}
		entries[i] = en
	}
	return e, entries
}

// randLabel is a realistic registrable label: 5 to 14 random letters and digits, sometimes with a hyphen (most real names are unrelated to any brand).
func randLabel(rng *rand.Rand) string {
	const alpha = "abcdefghijklmnopqrstuvwxyz0123456789"
	n := 5 + rng.Intn(10)
	b := make([]byte, n)
	for i := range b {
		b[i] = alpha[rng.Intn(len(alpha))]
	}
	if n > 8 && rng.Intn(4) == 0 {
		b[n/2] = '-'
	}
	return string(b)
}

func BenchmarkMatch1000Rules(b *testing.B) {
	e, entries := benchWorld(1000, 20000)
	var out []Match
	hits := 0
	b.ReportAllocs()
	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		out = e.Match(entries[i%len(entries)], out[:0])
		hits += len(out)
	}
	b.ReportMetric(float64(b.N)/time.Since(start).Seconds(), "entries/s")
	b.ReportMetric(float64(hits)/float64(b.N)*100, "hits/100entries")
}

func BenchmarkMatch5000Rules(b *testing.B) {
	e, entries := benchWorld(5000, 20000)
	var out []Match
	b.ReportAllocs()
	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		out = e.Match(entries[i%len(entries)], out[:0])
	}
	b.ReportMetric(float64(b.N)/time.Since(start).Seconds(), "entries/s")
}

func BenchmarkCompile5000Rules(b *testing.B) {
	for i := 0; i < b.N; i++ {
		benchWorld(5000, 1)
	}
}

func TestCompileHandlesFiveThousandRulesQuickly(t *testing.T) {
	start := time.Now()
	e, entries := benchWorld(5000, 200)
	if e.NumRules() != 5000 || len(entries) != 200 {
		t.Fatal("world")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("5,000 rules took %v to compile", d)
	}
}
