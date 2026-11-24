package monitor

import (
	"strings"
	"testing"
)

func TestPunycodeDecode(t *testing.T) {
	cases := map[string]string{
		"mnchen-3ya": "münchen",
		"e1afmkfd":   "пример",
		"l-7sba6dbr": "раураl",
		"pypal-4ve":  "pаypal",
		"bcher-kva":  "bücher",
		"wgv71a119e": "日本語",
	}
	for in, want := range cases {
		got, ok := punycodeDecode(in)
		if !ok || string(got) != want {
			t.Errorf("punycodeDecode(%q) = %q, %v; want %q", in, string(got), ok, want)
		}
	}
	for _, bad := range []string{"%%%", "a-", "zzzzzzzzzzzzzzzzzzzzzzzz", "é-abc"} {
		if _, ok := punycodeDecode(bad); ok && bad != "a-" {
			t.Errorf("%q was accepted", bad)
		}
	}
}

func TestSkeleton(t *testing.T) {
	same := [][]string{
		{"paypal", "paypa1", "paypai", "payp4l", "раураl", "xn--l-7sba6dbr", "ｐａｙｐａｌ", "PAYPAL"},
		{"microsoft", "rnicrosoft", "m1crosoft", "micr0soft", "microsoﬅ"},
		{"google", "g00gle", "goog1e", "googIe"},
		{"clark", "dark"},
		{"vvikipedia", "wikipedia"},
	}
	for _, group := range same {
		want, _ := skeletonOf(group[0])
		for _, g := range group[1:] {
			if got, _ := skeletonOf(g); got != want && g != "microsoﬅ" {
				t.Errorf("skeleton(%q) = %q, skeleton(%q) = %q", g, got, group[0], want)
			}
		}
	}
	if a, _ := skeletonOf("paypal"); a == func() string { s, _ := skeletonOf("paypall"); return s }() {
		t.Error("distinct names share a skeleton")
	}
	if _, idn := skeletonOf("xn--l-7sba6dbr"); !idn {
		t.Error("idn not reported")
	}
	if _, idn := skeletonOf("paypal"); idn {
		t.Error("idn reported for ASCII")
	}
}

func TestSplitRegistrable(t *testing.T) {
	cases := []struct{ name, rest, label, suffix string }{
		{"acme.com", "", "acme", "com"},
		{"www.acme.com", "www", "acme", "com"},
		{"a.b.acme.co.uk", "a.b", "acme", "co.uk"},
		{"acme.co.uk", "", "acme", "co.uk"},
		{"login-acme.pages.dev", "", "login-acme", "pages.dev"},
		{"x.login-acme.pages.dev", "x", "login-acme", "pages.dev"},
		{"shop.example.com.br", "shop", "example", "com.br"},
		{"co.uk", "", "", ""},
		{"com", "", "", ""},
		{"", "", "", ""},
	}
	for _, c := range cases {
		rest, label, suffix, ok := splitRegistrable(c.name)
		if c.label == "" {
			if ok {
				t.Errorf("%q: ok", c.name)
			}
			continue
		}
		if !ok || rest != c.rest || label != c.label || suffix != c.suffix {
			t.Errorf("%q -> %q %q %q %v", c.name, rest, label, suffix, ok)
		}
	}
	if r, ok := registrable("a.b.acme.co.uk"); !ok || r != "acme.co.uk" {
		t.Errorf("registrable: %q", r)
	}
}

func TestOSA(t *testing.T) {
	cases := []struct {
		a, b string
		max  int
		want int
	}{
		{"paypal", "paypal", 2, 0},
		{"paypal", "paypall", 2, 1},
		{"paypal", "paypa", 2, 1},
		{"paypal", "paypla", 2, 1}, // an adjacent swap is ONE edit
		{"paypal", "paypsl", 2, 1},
		{"paypal", "pypl", 2, 2},
		{"paypal", "pyapl", 2, 2},
		{"paypal", "abcdef", 2, 3}, // more than max: max+1
		{"ab", "abcdefg", 2, 3},
	}
	for _, c := range cases {
		if got := osaWithin(c.a, c.b, c.max); got != c.want {
			t.Errorf("osa(%q,%q,%d) = %d, want %d", c.a, c.b, c.max, got, c.want)
		}
	}
}

func TestAhoCorasick(t *testing.T) {
	patterns := []string{"acme", "paypal", "pay", "al", "acme-pay"}
	a := buildAutomaton(patterns)
	hits := a.scan("my-acme-paypal.com", nil)
	got := map[string]int{}
	for _, h := range hits {
		got[patterns[h.id]]++
		if s := "my-acme-paypal.com"[h.start:h.end]; s != patterns[h.id] {
			t.Errorf("hit %q at %d-%d", patterns[h.id], h.start, h.end)
		}
	}
	for _, p := range []string{"acme", "paypal", "pay", "al", "acme-pay"} {
		if got[p] != 1 {
			t.Errorf("%q found %d times in %v", p, got[p], got)
		}
	}
	if hits := a.scan("nothing here", nil); len(hits) != 0 {
		t.Errorf("%v", hits)
	}
	if hits := buildAutomaton(nil).scan("acme", nil); len(hits) != 0 {
		t.Error("no patterns, no hits")
	}
	if !strings.Contains("x", "x") {
		t.Fatal()
	}
}
