package monitor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mr-rizwan-syed/argus/pkg/ctlog"
)

// An apex that is itself a public suffix (github.io, co.uk, pages.dev) has no registrable label. It used to make Compile fail, which refused the whole file and so
// every other rule too. Now only that value is skipped, with a log line.
func TestAnApexThatIsAPublicSuffixIsSkippedNotFatal(t *testing.T) {
	set, err := ParseRules([]byte(`{"version":1,"rules":[
		{"id":"bad","apexes":["github.io","co.uk","pages.dev"]},
		{"id":"mixed","apexes":["vercel.app","example.com"]},
		{"id":"good","apexes":["acme.com"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	var logged []string
	e, err := Compile(set, EngineOptions{MinScore: 50, Logf: func(f string, a ...any) { logged = append(logged, f) }})
	if err != nil {
		t.Fatalf("a suffix apex must not refuse the whole set: %v", err)
	}
	if len(logged) != 4 {
		t.Fatalf("each skipped value is logged, got %d: %v", len(logged), logged)
	}
	if e.NumRules() != 3 {
		t.Fatalf("rules: %d", e.NumRules())
	}
	en := func(name string) []Match { return e.Match(ctlog.Entry{Names: []string{name}, Seen: time.Now()}, nil) }
	if h := en("new.acme.com"); len(h) != 1 || h[0].RuleID != "good" {
		t.Fatalf("the other rules must stay live: %+v", h)
	}
	if h := en("new.example.com"); len(h) != 1 || h[0].RuleID != "mixed" {
		t.Fatalf("the good apex of a rule that also has a suffix apex stays live: %+v", h)
	}
	// a look-alike of the surviving apex still resolves to the right apex entry (indexes were shifted by the skipped one)
	set2, _ := ParseRules([]byte(`{"version":1,"rules":[{"id":"m","apexes":["github.io","acmecorp.com"]}]}`))
	e2, err := Compile(set2, EngineOptions{MinScore: 50})
	if err != nil {
		t.Fatal(err)
	}
	if h := e2.Match(ctlog.Entry{Names: []string{"acmecorp.xyz"}, Seen: time.Now()}, nil); len(h) == 0 {
		t.Fatal("the look-alike index must point at the apex that was kept")
	}
}

// A document that parsed but could not be used must not leave its ETag behind (the server's fix would answer 304 for ever).
func TestARefusedCompileForgetsTheETag(t *testing.T) {
	reqs := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqs++
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(304)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Write([]byte(`{"version":1,"rules":[{"id":"a","apexes":["acme.com"]}]}`))
	}))
	defer srv.Close()
	u := &URLRules{URL: srv.URL}
	if _, _, err := u.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	u.Forget()
	if _, changed, err := u.Load(context.Background()); err != nil || !changed {
		t.Fatalf("after Forget the document must be fetched again: changed=%v err=%v", changed, err)
	}
	if reqs != 2 {
		t.Fatalf("%d requests", reqs)
	}
}

// A hit built on the first name that is not the rule's own used to be dropped when that name was known although a later name was new.
func TestAnOrgHitIsBuiltOnTheFirstNameThatIsNeitherOwnNorKnown(t *testing.T) {
	set := setFile(t, []Rule{{ID: "r1", Orgs: []string{"Acme Inc"}, KnownSet: "s1"}}, "r1", "acme.com")
	hits := hitsFor(t, set, ctlog.Entry{Names: []string{"www.acme.com", "shop.acme-store.net"}, SubjectO: "Acme Inc"})
	if len(hits) != 1 || hits[0].Domain != "shop.acme-store.net" || hits[0].Kind != KindOrg {
		t.Fatalf("the new host must be reported, got %+v", hits)
	}
	// everything known: nothing
	if hits := hitsFor(t, set, ctlog.Entry{Names: []string{"www.acme.com", "mail.acme.com"}, SubjectO: "Acme Inc"}); len(hits) != 0 {
		t.Fatalf("%+v", hits)
	}
}

func TestAnOrgHitOnAWildcardNameCarriesTheWildcardFlag(t *testing.T) {
	set, err := ParseRules([]byte(`{"version":1,"rules":[{"id":"r1","orgs":["Acme Inc"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	hits := hitsFor(t, set, ctlog.Entry{Names: []string{"*.shop.acme-store.net"}, SubjectO: "Acme Inc"})
	if len(hits) != 1 || !hits[0].Wildcard {
		t.Fatalf("the wildcard flag must come from the raw name: %+v", hits)
	}
}

// A redirect is a failure: a POST sent on to a login page that answers 200 must not count as delivered.
func TestARedirectIsNotADelivery(t *testing.T) {
	login := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer login.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, login.URL, http.StatusFound) }))
	defer srv.Close()
	p, err := NewPostSink(PostConfig{URL: srv.URL, Secret: []byte("k")})
	if err != nil {
		t.Fatal(err)
	}
	err = p.send([]byte(`[]`))
	if err == nil || !strings.Contains(err.Error(), "302") {
		t.Fatalf("a redirect must be an error, got %v", err)
	}
}

// Two edits count for labels of 9+ letters: with only long labels watched, a candidate two letters shorter than the shortest one is still looked at.
func TestTwoEditTyposAreFoundWhenOnlyLongLabelsAreWatched(t *testing.T) {
	set, err := ParseRules([]byte(`{"version":1,"rules":[{"id":"r1","apexes":["abcdefghijk.com"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	// 11-letter label, candidate of 9 letters (two deleted): two edits away
	hits := hitsFor(t, set, ctlog.Entry{Names: []string{"abcdefghi.com"}})
	found := false
	for _, h := range hits {
		if h.Kind == KindLookalike {
			found = true
		}
	}
	if !found {
		t.Fatalf("a two-letter-shorter candidate must be compared: %+v", hits)
	}
}
