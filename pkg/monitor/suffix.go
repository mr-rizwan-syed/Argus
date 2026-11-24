package monitor

import (
	_ "embed"
	"strings"
)

//go:embed suffixes.txt
var suffixData string

// twoLabelSuffixes holds the embedded two-label public suffixes ("co.uk", "pages.dev").
var twoLabelSuffixes = loadSuffixes()

func loadSuffixes() map[string]struct{} {
	m := map[string]struct{}{}
	for _, line := range strings.Split(suffixData, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m[line] = struct{}{}
	}
	return m
}

// splitRegistrable splits a lowercase host name into the part before its registrable domain, the registrable domain's own label, and the public
// suffix: "a.b.shop.co.uk" -> ("a.b", "shop", "co.uk"). The suffix rule is the last two labels when they are in the embedded list, else the last
// label. ok is false for a name with fewer than two labels (or one that is nothing but a suffix). No allocation: the parts are slices of name.
func splitRegistrable(name string) (rest, label, suffix string, ok bool) {
	last := strings.LastIndexByte(name, '.')
	if last < 0 {
		return "", "", "", false
	}
	suffix = name[last+1:]
	end := last // end of the label to the left of the suffix
	if prev := strings.LastIndexByte(name[:last], '.'); prev >= 0 {
		if _, two := twoLabelSuffixes[name[prev+1:]]; two {
			suffix = name[prev+1:]
			end = prev
		}
	} else if _, two := twoLabelSuffixes[name]; two {
		return "", "", "", false // the name is itself a two-label suffix
	}
	if end <= 0 {
		return "", "", "", false
	}
	start := strings.LastIndexByte(name[:end], '.')
	label = name[start+1 : end]
	if start >= 0 {
		rest = name[:start]
	}
	return rest, label, suffix, label != ""
}

// registrable returns the registrable domain of a host name ("login.acme.co.uk" -> "acme.co.uk").
func registrable(name string) (string, bool) {
	_, label, suffix, ok := splitRegistrable(name)
	if !ok {
		return "", false
	}
	return label + "." + suffix, true
}
