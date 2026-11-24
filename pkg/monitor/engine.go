package monitor

import (
	"fmt"
	"strings"
	"sync"

	"github.com/mr-rizwan-syed/argus/pkg/ctlog"
)

// Scores (0-100). They are fixed so that a threshold means the same thing for everyone.
const (
	scoreOrgExact      = 95
	scoreOrgContains   = 60
	scoreSubdomain     = 90
	scoreWildcard      = 85
	scoreApexItself    = 80
	scoreKeywordRisk   = 90
	scoreKeywordToken  = 70
	scoreKeywordSubstr = 50
	scoreHomoglyph     = 85
	scoreHomoglyphIDN  = 90
	scoreDistance1     = 80
	scoreDistance2     = 65
	scoreHyphen        = 80
	scoreGluedTLD      = 80
	scoreTLDSwap       = 60
	maxNamesPerEntry   = 100
	minLookalikeLabel  = 4
	minDistanceLabel   = 5 // distance-1 matching only for apex labels this long: on 4 letters nearly every word is one edit away from some brand
	longLabel          = 9 // from this length two edits count
	prefixLen          = 7 // typo candidates are found through the first 7 letters (SymSpell prefix trick) and verified on the whole label
	maxCandidateLabels = 8
)

// riskWords next to a brand word make a phishing domain far more likely.
var riskWords = toSet(`login signin secure verify verification account support update billing pay wallet auth service helpdesk recover recovery unlock id my portal
confirm security alert suspended suspend validate password reset customer online`)

// EngineOptions tune matching.
type EngineOptions struct {
	MinScore int // hits scoring less are dropped (default 50)
}

type apexInfo struct {
	name, label, suffix string
}

type compiledRule struct {
	id      string
	apexes  []apexInfo
	known   []string
	hasApex map[string]bool // the registrable domains of the apexes
	orgs    []string        // normalised
}

type kwRef struct {
	rule int32
	kw   string
}

type lookRef struct {
	rule int32
	apex int16
}

type orgRef struct{ rule int32 }

// Engine is a compiled rule set. It is immutable, so any number of goroutines may call Match at once.
type Engine struct {
	rules    []compiledRule
	apex     map[string][]int32
	known    map[string][]int32
	ac       *automaton
	kwRefs   [][]kwRef
	label    map[string][]lookRef // an apex label exactly (for the same name on another TLD)
	skel     map[string][]lookRef
	hyph     map[string][]lookRef
	glued    map[string][]lookRef
	d1, d2   map[string][]lookRef
	minLab   int
	maxLab   int
	maxLong  int
	bloomD   *bloom // keys of d1 and d2
	bloomX   *bloom // keys of label, skel, hyph and glued
	orgs     map[string][]int32
	orgWords int
	minScore int
	pool     sync.Pool
}

// Compile indexes a rule set: from here on, matching never loops over the rules.
func Compile(set *RuleSet, opts EngineOptions) (*Engine, error) {
	if opts.MinScore <= 0 {
		opts.MinScore = 50
	}
	e := &Engine{apex: map[string][]int32{}, known: map[string][]int32{}, label: map[string][]lookRef{}, skel: map[string][]lookRef{},
		hyph: map[string][]lookRef{}, glued: map[string][]lookRef{}, d1: map[string][]lookRef{}, d2: map[string][]lookRef{}, orgs: map[string][]int32{},
		minLab: 1 << 30, minScore: opts.MinScore}
	e.pool.New = func() any { return &scratch{} }
	kwIndex := map[string]int32{}
	var patterns []string
	for ri, r := range set.Rules {
		idx := int32(ri)
		cr := compiledRule{id: r.ID, hasApex: map[string]bool{}, known: r.Known}
		for ai, a := range r.Apexes {
			_, label, suffix, ok := splitRegistrable(a)
			if !ok {
				return nil, fmt.Errorf("rule %q: %q has no registrable domain", r.ID, a)
			}
			cr.apexes = append(cr.apexes, apexInfo{name: a, label: label, suffix: suffix})
			cr.hasApex[label+"."+suffix] = true
			e.apex[a] = append(e.apex[a], idx)
			e.indexLabel(lookRef{rule: idx, apex: int16(ai)}, label, suffix)
		}
		for _, k := range r.Known {
			e.known[k] = append(e.known[k], idx)
		}
		for _, k := range r.Keywords {
			id, ok := kwIndex[k]
			if !ok {
				id = int32(len(patterns))
				kwIndex[k] = id
				patterns = append(patterns, k)
				e.kwRefs = append(e.kwRefs, nil)
			}
			e.kwRefs[id] = append(e.kwRefs[id], kwRef{rule: idx, kw: k})
		}
		for _, o := range r.Orgs {
			n := NormalizeOrg(o)
			cr.orgs = append(cr.orgs, n)
			e.orgs[n] = append(e.orgs[n], idx)
			if w := strings.Count(n, " ") + 1; w > e.orgWords {
				e.orgWords = w
			}
		}
		e.rules = append(e.rules, cr)
	}
	e.ac = buildAutomaton(patterns)
	e.finish()
	if e.minLab == 1<<30 {
		e.minLab = 0
	}
	return e, nil
}

// NumRules is the number of rules compiled in.
func (e *Engine) NumRules() int { return len(e.rules) }

func addRef(m map[string][]lookRef, key string, ref lookRef) {
	for _, r := range m[key] {
		if r == ref {
			return
		}
	}
	m[key] = append(m[key], ref)
}

func removeHyphens(s string) string {
	if strings.IndexByte(s, '-') < 0 {
		return s
	}
	return strings.ReplaceAll(s, "-", "")
}

// indexLabel adds one apex label to every look-alike index.
func (e *Engine) indexLabel(ref lookRef, label, suffix string) {
	n := len(label)
	if n < minLookalikeLabel {
		return
	}
	addRef(e.label, label, ref)
	sk, _ := skeletonOf(label)
	addRef(e.skel, sk, ref)
	if hl := removeHyphens(label); len(hl) >= minLookalikeLabel {
		addRef(e.hyph, hl, ref)
	}
	addRef(e.glued, label+"-"+strings.ReplaceAll(suffix, ".", "-"), ref)
	if n < minDistanceLabel {
		return
	}
	if n < e.minLab {
		e.minLab = n
	}
	if n > e.maxLab {
		e.maxLab = n
	}
	pre := label
	if len(pre) > prefixLen {
		pre = pre[:prefixLen]
	}
	addRef(e.d1, pre, ref)
	for i := 0; i < len(pre); i++ {
		addRef(e.d1, pre[:i]+pre[i+1:], ref)
	}
	if n >= longLabel {
		if n > e.maxLong {
			e.maxLong = n
		}
		addRef(e.d2, pre, ref)
		for i := 0; i < len(pre); i++ {
			v := pre[:i] + pre[i+1:]
			addRef(e.d2, v, ref)
			for j := 0; j < len(v); j++ {
				addRef(e.d2, v[:j]+v[j+1:], ref)
			}
		}
	}
}

// finish builds the Bloom filters once every rule is indexed.
func (e *Engine) finish() {
	e.bloomD = newBloom(len(e.d1) + len(e.d2))
	for k := range e.d1 {
		e.bloomD.add(fnv1a(k))
	}
	for k := range e.d2 {
		e.bloomD.add(fnv1a(k))
	}
	e.bloomX = newBloom(len(e.label) + len(e.skel) + len(e.hyph) + len(e.glued))
	for _, m := range []map[string][]lookRef{e.label, e.skel, e.hyph, e.glued} {
		for k := range m {
			e.bloomX.add(fnv1a(k))
		}
	}
}

type kwBest struct {
	rule   int32
	score  int
	kw     string
	whole  bool
	risk   string
	substr bool
}

type lookBest struct {
	ref    lookRef
	score  int
	reason string
}

// scratch is per-call working memory, reused through a pool so that a Match that finds nothing allocates (almost) nothing.
type scratch struct {
	covered []int32
	hits    []acHit
	kw      []kwBest
	look    []lookBest
	cands   []candidate
	buf     [96]byte
	vbuf    [96]byte
}

type candidate struct {
	label string
	isReg bool
}

func containsRule(s []int32, r int32) bool {
	for _, x := range s {
		if x == r {
			return true
		}
	}
	return false
}

// Match returns the hits of one certificate that score at least MinScore, appended to out. It never reports an apex or a known host of a rule as
// brand abuse of that rule.
func (e *Engine) Match(en ctlog.Entry, out []Match) []Match {
	if len(e.rules) == 0 {
		return out
	}
	s := e.pool.Get().(*scratch)
	defer e.pool.Put(s)
	names := en.Names
	if len(names) > maxNamesPerEntry {
		names = names[:maxNamesPerEntry]
	}
	for _, raw := range names {
		name, wildcard := raw, false
		if strings.HasPrefix(name, "*.") {
			name, wildcard = name[2:], true
		}
		if name == "" || strings.IndexByte(name, '*') >= 0 {
			continue
		}
		out = e.matchName(s, &en, name, wildcard, out)
	}
	if en.SubjectO != "" {
		out = e.matchOrg(&en, out)
	}
	return out
}

func (e *Engine) matchName(s *scratch, en *ctlog.Entry, name string, wildcard bool, out []Match) []Match {
	s.covered = s.covered[:0]
	// 1. under a watched domain, and what is known to be the organization's own
	hasKnown := false
	for pos := 0; ; {
		suffix := name[pos:]
		if refs, ok := e.known[suffix]; ok {
			hasKnown = true
			s.covered = append(s.covered, refs...)
		}
		i := strings.IndexByte(name[pos:], '.')
		if i < 0 {
			break
		}
		pos += i + 1
	}
	for pos := 0; ; {
		suffix := name[pos:]
		if refs, ok := e.apex[suffix]; ok {
			for _, ri := range refs {
				if hasKnown && containsRule(s.covered, ri) && e.isKnown(ri, name) {
					continue
				}
				score, reason := scoreSubdomain, "under the watched domain "+suffix
				if pos == 0 {
					score, reason = scoreApexItself, "a certificate for the watched domain "+suffix+" itself"
				}
				if wildcard {
					score, reason = scoreWildcard, "a wildcard certificate for "+suffix
					if pos == 0 {
						reason = "a wildcard certificate for the watched domain " + suffix
					}
				}
				if score >= e.minScore {
					out = append(out, newMatch(en, &e.rules[ri], KindSubdomain, name, suffix, score, reason, wildcard))
				}
			}
			s.covered = append(s.covered, refs...)
		}
		i := strings.IndexByte(name[pos:], '.')
		if i < 0 {
			break
		}
		pos += i + 1
	}
	// 2. brand words inside the name
	out = e.matchKeywords(s, en, name, wildcard, out)
	// 3. look-alikes of a watched domain's label
	out = e.matchLookalikes(s, en, name, wildcard, out)
	return out
}

// isKnown reports whether name is, or is under, one of rule ri's known hosts.
func (e *Engine) isKnown(ri int32, name string) bool {
	for _, k := range e.rules[ri].known {
		if name == k || strings.HasSuffix(name, "."+k) {
			return true
		}
	}
	return false
}

func labelBounds(name string, start, end int) (int, int) {
	ls := strings.LastIndexByte(name[:start], '.') + 1
	le := len(name)
	if i := strings.IndexByte(name[end:], '.'); i >= 0 {
		le = end + i
	}
	return ls, le
}

func (e *Engine) matchKeywords(s *scratch, en *ctlog.Entry, name string, wildcard bool, out []Match) []Match {
	s.hits = e.ac.scan(name, s.hits[:0])
	if len(s.hits) == 0 {
		return out
	}
	s.kw = s.kw[:0]
	risk, riskDone := "", false
	for _, h := range s.hits {
		start, end := int(h.start), int(h.end)
		before := start == 0 || name[start-1] == '-' || name[start-1] == '.'
		after := end == len(name) || name[end] == '-' || name[end] == '.'
		whole := before && after
		for _, ref := range e.kwRefs[h.id] {
			if containsRule(s.covered, ref.rule) {
				continue
			}
			var score int
			var riskWord string
			switch {
			case whole:
				score = scoreKeywordToken
				if !riskDone {
					risk, riskDone = findRiskWord(name), true
				}
				if risk != "" {
					score, riskWord = scoreKeywordRisk, risk
				}
			case len(ref.kw) >= 5:
				// a brand word glued into a longer label: only when it is a meaningful share of the label or sits at its start or end
				// ("paypalsecure", "securepaypal" yes; "pineapplefarm" for apple no)
				ls, le := labelBounds(name, start, end)
				if start != ls && end != le && (end-start)*2 < le-ls {
					continue
				}
				score = scoreKeywordSubstr
			default:
				continue
			}
			found := false
			for i := range s.kw {
				if s.kw[i].rule == ref.rule {
					found = true
					if score > s.kw[i].score {
						s.kw[i] = kwBest{rule: ref.rule, score: score, kw: ref.kw, whole: whole, risk: riskWord, substr: !whole}
					}
					break
				}
			}
			if !found {
				s.kw = append(s.kw, kwBest{rule: ref.rule, score: score, kw: ref.kw, whole: whole, risk: riskWord, substr: !whole})
			}
		}
	}
	for _, b := range s.kw {
		if b.score < e.minScore {
			continue
		}
		var reason string
		switch {
		case b.risk != "":
			reason = fmt.Sprintf("the brand word %q next to %q in %s", b.kw, b.risk, name)
		case b.whole:
			reason = fmt.Sprintf("the brand word %q is a word of %s", b.kw, name)
		default:
			reason = fmt.Sprintf("the brand word %q is inside a label of %s", b.kw, name)
		}
		out = append(out, newMatch(en, &e.rules[b.rule], KindKeyword, name, b.kw, b.score, reason, wildcard))
	}
	return out
}

// findRiskWord returns the first word of name (split on '.' and '-') that is a risk word, or "".
func findRiskWord(name string) string {
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' || name[i] == '-' {
			if i > start {
				if w := name[start:i]; riskWords[w] {
					return w
				}
			}
			start = i + 1
		}
	}
	return ""
}

func (e *Engine) matchLookalikes(s *scratch, en *ctlog.Entry, name string, wildcard bool, out []Match) []Match {
	if len(e.label) == 0 {
		return out
	}
	rest, regLabel, suffix, ok := splitRegistrable(name)
	if !ok {
		return out
	}
	s.cands = s.cands[:0]
	s.cands = append(s.cands, candidate{regLabel, true})
	addTokens := func(label string) {
		if strings.IndexByte(label, '-') < 0 {
			return
		}
		start := 0
		for i := 0; i <= len(label); i++ {
			if i == len(label) || label[i] == '-' {
				if i-start >= minLookalikeLabel {
					s.cands = append(s.cands, candidate{label[start:i], false})
				}
				start = i + 1
			}
		}
	}
	addTokens(regLabel)
	for rest != "" && len(s.cands) < maxCandidateLabels {
		i := strings.LastIndexByte(rest, '.')
		l := rest[i+1:]
		if len(l) >= minLookalikeLabel {
			s.cands = append(s.cands, candidate{l, false})
			addTokens(l)
		}
		if i < 0 {
			break
		}
		rest = rest[:i]
	}
	s.look = s.look[:0]
	for _, c := range s.cands {
		e.evalCandidate(s, c.label, c.isReg, suffix)
	}
	for _, b := range s.look {
		if containsRule(s.covered, b.ref.rule) || b.score < e.minScore {
			continue
		}
		apex := e.rules[b.ref.rule].apexes[b.ref.apex].name
		out = append(out, newMatch(en, &e.rules[b.ref.rule], KindLookalike, name, apex, b.score, b.reason, wildcard))
	}
	return out
}

func (e *Engine) record(s *scratch, ref lookRef, score int, reason func() string) {
	for i := range s.look {
		if s.look[i].ref == ref {
			if score > s.look[i].score {
				s.look[i].score, s.look[i].reason = score, reason()
			}
			return
		}
	}
	s.look = append(s.look, lookBest{ref: ref, score: score, reason: reason()})
}

// evalCandidate compares one label of a name with every watched label, using only map lookups.
func (e *Engine) evalCandidate(s *scratch, c string, isReg bool, suffix string) {
	n := len(c)
	if n < minLookalikeLabel || n > 63 {
		return
	}
	apexOf := func(ref lookRef) *apexInfo { return &e.rules[ref.rule].apexes[ref.apex] }
	sk, idn := appendSkeleton(s.buf[:0], c)
	// the same name on another TLD, and the name with its TLD glued in ("acme-com.xyz")
	hc := fnv1a(c)
	if isReg && e.bloomX.has(hc) {
		for _, ref := range e.label[c] {
			a := apexOf(ref)
			if a.suffix != suffix {
				e.record(s, ref, scoreTLDSwap, func() string { return fmt.Sprintf("%s on .%s instead of .%s", c, suffix, a.suffix) })
			}
		}
		for _, ref := range e.glued[c] {
			a := apexOf(ref)
			e.record(s, ref, scoreGluedTLD, func() string { return fmt.Sprintf("%s with its TLD glued in", a.label) })
		}
	}
	// the same look
	var skRefs []lookRef
	if e.bloomX.has(fnv1a(sk)) {
		skRefs = e.skel[string(sk)]
	}
	for _, ref := range skRefs {
		a := apexOf(ref)
		if c == a.label {
			continue
		}
		score := scoreHomoglyph
		if idn {
			score = scoreHomoglyphIDN
		}
		e.record(s, ref, score, func() string {
			if idn {
				return fmt.Sprintf("%s is an internationalised name whose characters imitate %s", c, a.label)
			}
			return fmt.Sprintf("%s looks like %s (look-alike characters)", c, a.label)
		})
	}
	if idn {
		return
	}
	// a hyphen added or removed
	var hyRefs []lookRef
	if rh := removeHyphens(c); e.bloomX.has(fnv1a(rh)) {
		hyRefs = e.hyph[rh]
	}
	for _, ref := range hyRefs {
		a := apexOf(ref)
		if c != a.label {
			e.record(s, ref, scoreHyphen, func() string { return fmt.Sprintf("%s is %s with a hyphen added or removed", c, a.label) })
		}
	}
	// a typing slip: one edit (two for long labels). Variants of the label with one or two letters deleted are looked up in the index.
	if e.maxLab == 0 || n < e.minLab-1 || n > e.maxLab+2 {
		return
	}
	check := func(refs []lookRef) {
		for _, ref := range refs {
			a := apexOf(ref)
			if c == a.label {
				continue
			}
			limit := 1
			if len(a.label) >= longLabel {
				limit = 2
			}
			if d := osaWithin(c, a.label, limit); d <= limit {
				score := scoreDistance1
				if d == 2 {
					score = scoreDistance2
				}
				e.record(s, ref, score, func() string {
					if d == 1 {
						return fmt.Sprintf("%s is one character away from %s", c, a.label)
					}
					return fmt.Sprintf("%s is two characters away from %s", c, a.label)
				})
			}
		}
	}
	pre := c
	if len(pre) > prefixLen {
		pre = pre[:prefixLen]
	}
	look := func(m map[string][]lookRef, k []byte) {
		if e.bloomD.has(fnv1a(k)) {
			check(m[string(k)])
		}
	}
	look(e.d1, append(s.vbuf[:0], pre...))
	for i := 0; i < len(pre); i++ {
		v := append(s.vbuf[:0], pre[:i]...)
		v = append(v, pre[i+1:]...)
		look(e.d1, v)
	}
	if e.maxLong > 0 && n >= 7 && n <= e.maxLong+2 && n <= 40 {
		look(e.d2, append(s.vbuf[:0], pre...))
		for i := 0; i < len(pre); i++ {
			v := append(s.vbuf[:0], pre[:i]...)
			v = append(v, pre[i+1:]...)
			look(e.d2, v)
			for j := 0; j < len(v); j++ {
				w := append(s.vbuf[len(v):len(v)], v[:j]...)
				w = append(w, v[j+1:]...)
				look(e.d2, w)
			}
		}
	}
}

// matchOrg looks for the subject organization among the rules' organization names. It reports only when the certificate also names a host that is
// NOT the organization's own (an organization's certificate for its own domains is the subdomain hit's business): that is the new asset.
func (e *Engine) matchOrg(en *ctlog.Entry, out []Match) []Match {
	n := NormalizeOrg(en.SubjectO)
	if len(n) < MinOrgLen {
		return out
	}
	type orgHit struct {
		rule  int32
		score int
		org   string
	}
	var hits []orgHit
	add := func(rules []int32, score int, org string) {
		for _, ri := range rules {
			dup := false
			for i := range hits {
				if hits[i].rule == ri {
					dup = true
					if score > hits[i].score {
						hits[i].score, hits[i].org = score, org
					}
				}
			}
			if !dup {
				hits = append(hits, orgHit{ri, score, org})
			}
		}
	}
	if rules, ok := e.orgs[n]; ok {
		add(rules, scoreOrgExact, n)
	}
	if e.orgWords > 0 && strings.IndexByte(n, ' ') >= 0 {
		var starts, ends [32]int
		w := 0
		for i := 0; i < len(n) && w < len(starts); {
			j := strings.IndexByte(n[i:], ' ')
			if j < 0 {
				j = len(n) - i
			}
			starts[w], ends[w] = i, i+j
			w++
			i += j + 1
		}
		for a := 0; a < w; a++ {
			for b := a; b < w && b-a < e.orgWords; b++ {
				if a == 0 && b == w-1 {
					continue // the whole name: the exact case above
				}
				if rules, ok := e.orgs[n[starts[a]:ends[b]]]; ok {
					add(rules, scoreOrgContains, n[starts[a]:ends[b]])
				}
			}
		}
	}
	for _, h := range hits {
		if h.score < e.minScore {
			continue
		}
		rule := &e.rules[h.rule]
		foreign := ""
		for _, raw := range en.Names {
			name := strings.TrimPrefix(raw, "*.")
			if name != "" && !e.ruleCovers(rule, name) {
				foreign = name
				break
			}
		}
		if foreign == "" {
			continue
		}
		out = append(out, newMatch(en, rule, KindOrg, foreign, h.org, h.score,
			fmt.Sprintf("the certificate's organization %q names %q", en.SubjectO, h.org), strings.HasPrefix(foreign, "*.")))
	}
	return out
}

func (e *Engine) ruleCovers(r *compiledRule, name string) bool {
	for _, a := range r.apexes {
		if name == a.name || strings.HasSuffix(name, "."+a.name) {
			return true
		}
	}
	for _, k := range r.known {
		if name == k || strings.HasSuffix(name, "."+k) {
			return true
		}
	}
	return false
}
