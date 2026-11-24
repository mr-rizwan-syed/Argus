// Package monitor turns certificates read from Certificate Transparency logs into alerts for what people watch: new assets of a domain, brand
// abuse and phishing look-alikes, and certificates that name an organization.
//
// A Rule is ONE ORGANIZATION: its apex domains, brand keywords, certificate organization names and hosts that are known to be its own. Rules carry
// no personal data (never an email address or a user id): the platform keeps who owns a rule, this package only sees the rule.
package monitor

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Limits of a rule and of a rule set.
const (
	MaxRules       = 50000
	MaxApexes      = 5
	MaxKeywords    = 5
	MaxOrgs        = 5
	MaxKnown       = 50
	MaxKnownSets   = 20000  // sets in one file
	MaxKnownHashes = 500000 // hashes in one set
	MinKeywordLen  = 4
	MaxKeywordLen  = 40
	MinOrgLen      = 3
	MaxOrgLen      = 100
	MaxRuleNameLen = 100
)

// Rule is one organization to watch.
type Rule struct {
	ID       string   `json:"id"`
	Name     string   `json:"name,omitempty"`
	Apexes   []string `json:"apexes,omitempty"`   // domains: new certificates for them and everything under them are new assets
	Keywords []string `json:"keywords,omitempty"` // brand words looked for inside other people's domains
	Orgs     []string `json:"orgs,omitempty"`     // organization names looked for in certificate subjects
	Known    []string `json:"known,omitempty"`    // hosts or domains that are the organization's own: never reported, under them nothing is reported either
	// KnownSet names a set (RuleFile.Sets) of hashed hosts that are also known: a LARGE list (thousands of hosts) that stays private because only hashes are
	// held. It is looked up only for a hit, never for every certificate: a hit whose name, or a parent of it, is in the set is dropped before it is counted.
	KnownSet string `json:"known_set,omitempty"`
}

// KnownSet is a set of hashed hosts. A host is hashed as KnownHash(Salt, name); the hashes are lower-case hex.
type KnownSet struct {
	Salt   string   `json:"salt"`
	Hashes []string `json:"hashes"`
}

// RuleFile is the JSON document a rules source serves.
type RuleFile struct {
	Version int                 `json:"version"`
	Rules   []Rule              `json:"rules"`
	Sets    map[string]KnownSet `json:"sets,omitempty"`
}

// RuleError says which rule and which field was refused, and why.
type RuleError struct {
	Index int // position in the file, from 1
	ID    string
	Field string
	Msg   string
}

func (e RuleError) Error() string {
	where := fmt.Sprintf("rule #%d", e.Index)
	if e.ID != "" {
		where = fmt.Sprintf("rule %q (#%d)", e.ID, e.Index)
	}
	if e.Field == "" {
		return fmt.Sprintf("%s: %s", where, e.Msg)
	}
	return fmt.Sprintf("%s, field %s: %s", where, e.Field, e.Msg)
}

// RuleErrors is what a refused file returns: every problem found (at most 20), one per line.
type RuleErrors []RuleError

func (es RuleErrors) Error() string {
	lines := make([]string, 0, len(es))
	for _, e := range es {
		lines = append(lines, e.Error())
	}
	return strings.Join(lines, "\n")
}

// commonWords are refused as keywords on their own: they would match a large part of the internet.
var commonWords = toSet(`app apps cloud mail email web shop store online login secure bank net tech group global service services support news home media free live
data info site host hosting party game games club blog pay money trade work team love world city star blue red green black white gold smart best
top new now one two first prime pro plus max mega super ultra digital system systems solutions solution business company office portal account
accounts access center centre direct express fast quick easy simple secure safe trust travel hotel hotels video music photo photos shop shopping
market sales tools tool studio design agency network networks internet mobile phone wireless energy health medical care life family kids school
university college education learning academy bank banks finance capital credit insurance loan loans cash fund invest trading crypto coin coins`)

func toSet(words string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(words) {
		m[w] = true
	}
	return m
}

var (
	idPattern    = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,64}$`)
	labelPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	wordPattern  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
)

// NormalizeDomain lowercases a domain and checks it is a plain host name in ASCII (an internationalised name must be given in its xn-- form).
func NormalizeDomain(s string) (string, error) {
	d := strings.ToLower(strings.TrimSpace(s))
	d = strings.TrimSuffix(d, ".")
	if d == "" {
		return "", fmt.Errorf("empty")
	}
	if strings.ContainsAny(d, "/:@ \t*?#") {
		return "", fmt.Errorf("%q is not a plain domain (no scheme, path, port, wildcard or spaces)", s)
	}
	for i := 0; i < len(d); i++ {
		if d[i] >= 0x80 {
			return "", fmt.Errorf("%q has non-ASCII characters: give the xn-- form", s)
		}
	}
	if len(d) > 253 {
		return "", fmt.Errorf("%q is longer than 253 characters", s)
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("%q needs at least two labels, like example.com", s)
	}
	for _, l := range labels {
		if !labelPattern.MatchString(l) {
			return "", fmt.Errorf("%q has an invalid label %q", s, l)
		}
	}
	return d, nil
}

// legal suffixes dropped from organization names before they are compared.
var legalWords = toSet(`inc incorporated llc ltd limited gmbh corp corporation sa plc co company ag bv nv srl pty sarl spa oy ab as kk lp llp pllc pc the`)

// NormalizeOrg lowercases an organization name, turns punctuation into spaces, drops legal suffix words (inc, llc, gmbh, ...) and joins the rest
// with single spaces: "ACME, Inc." and "Acme Incorporated" both become "acme".
func NormalizeOrg(s string) string {
	var words []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			w := cur.String()
			cur.Reset()
			if !legalWords[w] {
				words = append(words, w)
			}
		}
	}
	for _, r := range strings.ToLower(s) {
		switch {
		case r == '.' || r == '\'' || r == 0x2019: // "B.V." is "bv", "S.A." is "sa", "Women's" is "womens": they join, they do not split
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r >= 0x80 && !isPunctRune(r):
			cur.WriteRune(r)
		default:
			flush()
		}
	}
	flush()
	return strings.Join(words, " ")
}

func isPunctRune(r rune) bool {
	switch r {
	case 0x2018, 0x2019, 0x201c, 0x201d, 0x2013, 0x2014, 0x00b7, 0x2022, 0x00ae, 0x2122, 0x00a9:
		return true
	}
	return false
}

// Validate checks one rule and returns it normalised (lowercase domains and keywords, trimmed text). The first problem is returned.
func (r Rule) Validate(index int) (Rule, *RuleError) {
	bad := func(field, format string, args ...any) (Rule, *RuleError) {
		return Rule{}, &RuleError{Index: index, ID: r.ID, Field: field, Msg: fmt.Sprintf(format, args...)}
	}
	out := Rule{ID: strings.TrimSpace(r.ID), Name: strings.TrimSpace(r.Name), KnownSet: strings.TrimSpace(r.KnownSet)}
	if out.KnownSet != "" && !idPattern.MatchString(out.KnownSet) {
		return bad("known_set", "a set name is 1 to 64 characters from letters, digits and . _ : - (got %q)", r.KnownSet)
	}
	if !idPattern.MatchString(out.ID) {
		return bad("id", "an id is 1 to 64 characters from letters, digits and . _ : - (got %q)", r.ID)
	}
	if len(out.Name) > MaxRuleNameLen {
		return bad("name", "a name is at most %d characters", MaxRuleNameLen)
	}
	if len(r.Apexes) > MaxApexes {
		return bad("apexes", "at most %d domains per rule (got %d)", MaxApexes, len(r.Apexes))
	}
	if len(r.Keywords) > MaxKeywords {
		return bad("keywords", "at most %d keywords per rule (got %d)", MaxKeywords, len(r.Keywords))
	}
	if len(r.Orgs) > MaxOrgs {
		return bad("orgs", "at most %d organization names per rule (got %d)", MaxOrgs, len(r.Orgs))
	}
	if len(r.Known) > MaxKnown {
		return bad("known", "at most %d known hosts per rule (got %d)", MaxKnown, len(r.Known))
	}
	seen := map[string]bool{}
	for _, a := range r.Apexes {
		d, err := NormalizeDomain(a)
		if err != nil {
			return bad("apexes", "%v", err)
		}
		if !seen[d] {
			seen[d] = true
			out.Apexes = append(out.Apexes, d)
		}
	}
	seen = map[string]bool{}
	for _, k := range r.Known {
		d, err := NormalizeDomain(k)
		if err != nil {
			return bad("known", "%v", err)
		}
		if !seen[d] {
			seen[d] = true
			out.Known = append(out.Known, d)
		}
	}
	seen = map[string]bool{}
	for _, k := range r.Keywords {
		w := strings.ToLower(strings.TrimSpace(k))
		switch {
		case len(w) < MinKeywordLen:
			return bad("keywords", "keyword %q is too short: at least %d characters (shorter words match too much)", k, MinKeywordLen)
		case len(w) > MaxKeywordLen:
			return bad("keywords", "keyword %q is longer than %d characters", k, MaxKeywordLen)
		case !wordPattern.MatchString(w):
			return bad("keywords", "keyword %q may only use letters a-z, digits and hyphens inside (no spaces or accents)", k)
		case commonWords[w]:
			return bad("keywords", "keyword %q is too common to watch on its own: it would match a large part of the internet; use your brand name", k)
		}
		if !seen[w] {
			seen[w] = true
			out.Keywords = append(out.Keywords, w)
		}
	}
	seen = map[string]bool{}
	for _, o := range r.Orgs {
		t := strings.TrimSpace(o)
		if len(t) < MinOrgLen || len(t) > MaxOrgLen {
			return bad("orgs", "organization name %q must be %d to %d characters", o, MinOrgLen, MaxOrgLen)
		}
		for _, c := range t {
			if c < 0x20 || c == 0x7f {
				return bad("orgs", "organization name %q has a control character", o)
			}
		}
		n := NormalizeOrg(t)
		if len(n) < MinOrgLen {
			return bad("orgs", "organization name %q is nothing but legal words (inc, ltd, ...) once they are dropped", o)
		}
		if !seen[n] {
			seen[n] = true
			out.Orgs = append(out.Orgs, t)
		}
	}
	if len(out.Apexes) == 0 && len(out.Keywords) == 0 && len(out.Orgs) == 0 {
		return bad("", "a rule needs at least one domain, keyword or organization name to watch")
	}
	return out, nil
}

// RuleSet is a validated, normalised set of rules.
type RuleSet struct {
	Rules []Rule
	Sets  map[string]*HashSet
}

// ParseRules reads a rules document ({"version":1,"rules":[...]}). Every rule is validated; the file is refused as a whole when any rule is bad,
// so a rule set that loads is always consistent.
func ParseRules(data []byte) (*RuleSet, error) {
	var f RuleFile
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("the rules file is not valid: %w", err)
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("the rules file has version %d: this build reads version 1", f.Version)
	}
	if len(f.Rules) > MaxRules {
		return nil, fmt.Errorf("the rules file has %d rules: at most %d", len(f.Rules), MaxRules)
	}
	set := &RuleSet{Rules: make([]Rule, 0, len(f.Rules))}
	ids := map[string]int{}
	var errs RuleErrors
	if len(f.Sets) > MaxKnownSets {
		return nil, fmt.Errorf("the rules file has %d known sets: at most %d", len(f.Sets), MaxKnownSets)
	}
	for name, ks := range f.Sets {
		hs, err := newHashSet(name, ks)
		if err != nil {
			return nil, err
		}
		if set.Sets == nil {
			set.Sets = map[string]*HashSet{}
		}
		set.Sets[name] = hs
	}
	for i, r := range f.Rules {
		n, e := r.Validate(i + 1)
		if e != nil {
			if len(errs) < 20 {
				errs = append(errs, *e)
			}
			continue
		}
		if first, dup := ids[n.ID]; dup {
			if len(errs) < 20 {
				errs = append(errs, RuleError{Index: i + 1, ID: n.ID, Field: "id", Msg: fmt.Sprintf("already used by rule #%d", first)})
			}
			continue
		}
		if n.KnownSet != "" && set.Sets[n.KnownSet] == nil {
			if len(errs) < 20 {
				errs = append(errs, RuleError{Index: i + 1, ID: n.ID, Field: "known_set", Msg: fmt.Sprintf("there is no set named %q in \"sets\"", n.KnownSet)})
			}
			continue
		}
		ids[n.ID] = i + 1
		set.Rules = append(set.Rules, n)
	}
	if len(errs) > 0 {
		return nil, errs
	}
	return set, nil
}
