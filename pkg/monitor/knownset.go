package monitor

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// HashSet is a large set of hosts that are known (the organization's own, or already in someone's asset list), held as hashes only: the platform never
// sends the names, so a leaked rules file does not leak an asset list. A name is hashed with a per-set salt, so the same host in two sets gives two
// different hashes and a precomputed table of common names does not apply.
//
// It is consulted only for a HIT (a certificate that already matched a rule), never for every certificate in the logs, so its size costs memory but no time:
// a hit is checked for its own name and each parent domain, a handful of map lookups.
type HashSet struct {
	salt string
	m    map[[16]byte]struct{}
}

// KnownHash is the hash a name is stored under: the first 16 bytes of SHA-256(salt + "\n" + lower-case name), as 32 hex characters. The platform computes the
// same thing (test vector in knownset_test.go and in the platform's tests).
func KnownHash(salt, name string) string {
	sum := sha256.Sum256([]byte(salt + "\n" + strings.ToLower(name)))
	return hex.EncodeToString(sum[:16])
}

func newHashSet(name string, ks KnownSet) (*HashSet, error) {
	if !idPattern.MatchString(name) {
		return nil, fmt.Errorf("known set %q: a set name is 1 to 64 characters from letters, digits and . _ : -", name)
	}
	if ks.Salt == "" || len(ks.Salt) > 128 {
		return nil, fmt.Errorf("known set %q: the salt must be 1 to 128 characters", name)
	}
	if len(ks.Hashes) > MaxKnownHashes {
		return nil, fmt.Errorf("known set %q has %d hashes: at most %d", name, len(ks.Hashes), MaxKnownHashes)
	}
	h := &HashSet{salt: ks.Salt, m: make(map[[16]byte]struct{}, len(ks.Hashes))}
	for i, x := range ks.Hashes {
		var k [16]byte
		if len(x) != 32 {
			return nil, fmt.Errorf("known set %q, hash #%d: want 32 hex characters (got %d)", name, i+1, len(x))
		}
		if _, err := hex.Decode(k[:], []byte(strings.ToLower(x))); err != nil {
			return nil, fmt.Errorf("known set %q, hash #%d: not hex", name, i+1)
		}
		h.m[k] = struct{}{}
	}
	return h, nil
}

// Len is the number of hosts in the set.
func (h *HashSet) Len() int {
	if h == nil {
		return 0
	}
	return len(h.m)
}

// Covers reports whether name, or any parent domain of it that has at least two labels, is in the set. A leading "*." is ignored.
func (h *HashSet) Covers(name string) bool {
	if h == nil || len(h.m) == 0 {
		return false
	}
	name = strings.TrimSuffix(strings.ToLower(strings.TrimPrefix(name, "*.")), ".")
	for pos := 0; ; {
		suffix := name[pos:]
		if strings.IndexByte(suffix, '.') < 0 {
			return false // a bare ending such as "com" is never a host
		}
		sum := sha256.Sum256([]byte(h.salt + "\n" + suffix))
		var k [16]byte
		copy(k[:], sum[:16])
		if _, ok := h.m[k]; ok {
			return true
		}
		i := strings.IndexByte(suffix, '.')
		pos += i + 1
	}
}
