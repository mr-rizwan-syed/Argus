package monitor

import (
	"time"

	"github.com/mr-rizwan-syed/argus/pkg/ctlog"
)

// Kinds of hit.
const (
	KindSubdomain = "subdomain" // a name under a watched domain: a new asset of what you watch
	KindKeyword   = "keyword"   // the brand word inside someone else's domain: phishing, brand abuse
	KindLookalike = "lookalike" // a domain label that imitates a watched domain's label
	KindOrg       = "org"       // the certificate's subject names the organization
	KindRuleNoisy = "rule_noisy"
)

// Match is one reported hit. Times are pointers so that an unknown time is left out of the JSON.
type Match struct {
	RuleID      string     `json:"rule_id"`
	Kind        string     `json:"kind"`
	Domain      string     `json:"domain"`            // the name that matched
	Matched     string     `json:"matched"`           // the apex, keyword or organization it matched
	Score       int        `json:"score"`             // 0-100
	Reasons     []string   `json:"reasons,omitempty"` // in plain words
	Names       []string   `json:"names,omitempty"`   // all names of the certificate, at most 20
	Wildcard    bool       `json:"wildcard,omitempty"`
	NewDomain   bool       `json:"new_domain"` // the registrable domain of Domain is not one of the rule's domains
	IssuerCN    string     `json:"issuer_cn,omitempty"`
	IssuerO     string     `json:"issuer_o,omitempty"`
	SubjectO    string     `json:"subject_o,omitempty"`
	NotBefore   *time.Time `json:"not_before,omitempty"`
	NotAfter    *time.Time `json:"not_after,omitempty"`
	Fingerprint string     `json:"fingerprint,omitempty"`
	Log         string     `json:"log,omitempty"`
	Operator    string     `json:"operator,omitempty"`
	Index       uint64     `json:"index,omitempty"`
	Seen        time.Time  `json:"seen"`
	Logged      *time.Time `json:"logged,omitempty"`
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func newMatch(en *ctlog.Entry, rule *compiledRule, kind, domain, matched string, score int, reason string, wildcard bool) Match {
	m := Match{RuleID: rule.id, Kind: kind, Domain: domain, Matched: matched, Score: score, Reasons: []string{reason}, Wildcard: wildcard,
		IssuerCN: en.IssuerCN, IssuerO: en.IssuerO, SubjectO: en.SubjectO, NotBefore: timePtr(en.NotBefore), NotAfter: timePtr(en.NotAfter),
		Fingerprint: en.Fingerprint, Log: en.Log, Operator: en.Operator, Index: en.Index, Seen: en.Seen, Logged: timePtr(en.Logged)}
	n := len(en.Names)
	if n > 20 {
		n = 20
	}
	m.Names = append([]string(nil), en.Names[:n]...)
	if reg, ok := registrable(domain); ok {
		m.NewDomain = !rule.hasApex[reg]
	} else {
		m.NewDomain = true
	}
	return m
}
