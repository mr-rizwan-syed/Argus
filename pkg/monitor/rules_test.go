package monitor

import (
	"strings"
	"testing"
)

func TestRulesAreNormalised(t *testing.T) {
	set, err := ParseRules([]byte(`{"version":1,"rules":[{"id":"r1","name":" Acme ","apexes":["ACME.com.","Acme.COM"],"keywords":["ACME-Pay","acme-pay"],"orgs":["ACME, Inc."],"known":["WWW.Acme.com"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	r := set.Rules[0]
	if r.Name != "Acme" || len(r.Apexes) != 1 || r.Apexes[0] != "acme.com" || len(r.Keywords) != 1 || r.Keywords[0] != "acme-pay" || r.Known[0] != "www.acme.com" {
		t.Fatalf("%+v", r)
	}
}

func TestTheLoaderRefusesWithAClearMessage(t *testing.T) {
	cases := []struct{ name, rule, want string }{
		{"keyword too short", `{"id":"r1","keywords":["abc"]}`, "too short"},
		{"keyword too common", `{"id":"r1","keywords":["login"]}`, "too common"},
		{"another common word", `{"id":"r1","keywords":["Cloud"]}`, "too common"},
		{"keyword with a space", `{"id":"r1","keywords":["my brand"]}`, "letters a-z"},
		{"keyword with an accent", `{"id":"r1","keywords":["café-brand"]}`, "letters a-z"},
		{"apex is a URL", `{"id":"r1","apexes":["https://acme.com/login"]}`, "plain domain"},
		{"apex has a port", `{"id":"r1","apexes":["acme.com:8443"]}`, "plain domain"},
		{"apex is a wildcard", `{"id":"r1","apexes":["*.acme.com"]}`, "plain domain"},
		{"apex is one label", `{"id":"r1","apexes":["localhost"]}`, "two labels"},
		{"apex is not ASCII", `{"id":"r1","apexes":["bücher.de"]}`, "xn--"},
		{"apex has a bad label", `{"id":"r1","apexes":["-acme.com"]}`, "invalid label"},
		{"too many apexes", `{"id":"r1","apexes":["a1.com","a2.com","a3.com","a4.com","a5.com","a6.com"]}`, "at most 5"},
		{"too many keywords", `{"id":"r1","keywords":["brand1","brand2","brand3","brand4","brand5","brand6"]}`, "at most 5"},
		{"too many orgs", `{"id":"r1","orgs":["Org One","Org Two","Org Three","Org Four","Org Five","Org Six"]}`, "at most 5"},
		{"org is only legal words", `{"id":"r1","orgs":["Inc LLC"]}`, "legal words"},
		{"org is too short", `{"id":"r1","orgs":["AB"]}`, "3 to 100"},
		{"nothing to watch", `{"id":"r1","name":"x"}`, "at least one"},
		{"bad id", `{"id":"has space","apexes":["acme.com"]}`, "id"},
		{"no id", `{"apexes":["acme.com"]}`, "id"},
		{"long name", `{"id":"r1","name":"` + strings.Repeat("n", 101) + `","apexes":["acme.com"]}`, "name"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseRules([]byte(`{"version":1,"rules":[` + c.rule + `]}`))
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q lacks %q", err, c.want)
			}
		})
	}
}

func TestErrorsNameTheRuleAndTheField(t *testing.T) {
	_, err := ParseRules([]byte(`{"version":1,"rules":[{"id":"fine","apexes":["acme.com"]},{"id":"bad","keywords":["ab"]}]}`))
	if err == nil || !strings.Contains(err.Error(), `rule "bad" (#2), field keywords`) {
		t.Fatalf("%v", err)
	}
}

func TestDuplicateIDsAndFileLevelRefusals(t *testing.T) {
	if _, err := ParseRules([]byte(`{"version":1,"rules":[{"id":"x","apexes":["a.com"]},{"id":"x","apexes":["b.com"]}]}`)); err == nil || !strings.Contains(err.Error(), "already used by rule #1") {
		t.Errorf("duplicate id: %v", err)
	}
	for name, doc := range map[string]string{
		"version 2":     `{"version":2,"rules":[]}`,
		"no version":    `{"rules":[]}`,
		"unknown field": `{"version":1,"rules":[{"id":"x","apexes":["a.com"],"email":"a@b.c"}]}`,
		"not json":      `rules: []`,
	} {
		if _, err := ParseRules([]byte(doc)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// an unknown field matters: rules carry no personal data, so a file with an email in it is refused, not ignored
}

func TestEveryProblemIsReportedUpToTwenty(t *testing.T) {
	var rules []string
	for i := 0; i < 30; i++ {
		rules = append(rules, `{"id":"r`+string(rune('a'+i%26))+string(rune('a'+i/26))+`","keywords":["ab"]}`)
	}
	_, err := ParseRules([]byte(`{"version":1,"rules":[` + strings.Join(rules, ",") + `]}`))
	if n := strings.Count(err.Error(), "\n") + 1; err == nil || n != 20 {
		t.Fatalf("%d lines: %v", n, err)
	}
}

func TestNormalizeOrg(t *testing.T) {
	cases := map[string]string{
		"ACME, Inc.":                  "acme",
		"Acme Incorporated":           "acme",
		"The Acme Group Holdings Ltd": "acme group holdings",
		"Müller & Söhne GmbH":         "müller söhne",
		"  Acme   Corp  ":             "acme",
		"Acme (Europe) B.V.":          "acme europe",
		"Inc":                         "",
		"Wikimedia Foundation, Inc.":  "wikimedia foundation",
		"Société Générale S.A.":       "société générale",
		"Google LLC":                  "google",
	}
	for in, want := range cases {
		if got := NormalizeOrg(in); got != want {
			t.Errorf("NormalizeOrg(%q) = %q, want %q", in, got, want)
		}
	}
}
