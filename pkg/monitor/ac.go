package monitor

// A small Aho-Corasick automaton over lowercase ASCII keywords: one pass over a host name finds every keyword in it, however many rules there are.
// Symbols are a-z (0-25), 0-9 (26-35), '-' (36) and everything else (37, which no keyword contains, so it resets the match).

const acSymbols = 38

func acSymbol(c byte) int {
	switch {
	case c >= 'a' && c <= 'z':
		return int(c - 'a')
	case c >= '0' && c <= '9':
		return int(c-'0') + 26
	case c == '-':
		return 36
	}
	return 37
}

type automaton struct {
	next [][acSymbols]int32 // full DFA: next[state][symbol]
	out  [][]int32          // pattern ids ending at each state (including those reached through failure links)
	lens []int32            // length of each pattern
}

// buildAutomaton compiles the patterns; pattern i keeps the id i.
func buildAutomaton(patterns []string) *automaton {
	a := &automaton{next: make([][acSymbols]int32, 1), out: make([][]int32, 1), lens: make([]int32, len(patterns))}
	for i := range a.next[0] {
		a.next[0][i] = -1
	}
	for id, p := range patterns {
		a.lens[id] = int32(len(p))
		s := int32(0)
		for i := 0; i < len(p); i++ {
			c := acSymbol(p[i])
			if a.next[s][c] < 0 {
				a.next = append(a.next, [acSymbols]int32{})
				for k := range a.next[len(a.next)-1] {
					a.next[len(a.next)-1][k] = -1
				}
				a.out = append(a.out, nil)
				a.next[s][c] = int32(len(a.next) - 1)
			}
			s = a.next[s][c]
		}
		a.out[s] = append(a.out[s], int32(id))
	}
	fail := make([]int32, len(a.next))
	queue := make([]int32, 0, len(a.next))
	for c := 0; c < acSymbols; c++ {
		if a.next[0][c] < 0 {
			a.next[0][c] = 0
		} else {
			queue = append(queue, a.next[0][c])
		}
	}
	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		for c := 0; c < acSymbols; c++ {
			t := a.next[s][c]
			if t < 0 {
				a.next[s][c] = a.next[fail[s]][c]
				continue
			}
			fail[t] = a.next[fail[s]][c]
			a.out[t] = append(a.out[t], a.out[fail[t]]...)
			queue = append(queue, t)
		}
	}
	return a
}

type acHit struct {
	id         int32
	start, end int32 // end exclusive
}

// scan appends every occurrence of every pattern in s to dst (no callback, so a scan allocates nothing once dst has room).
func (a *automaton) scan(s string, dst []acHit) []acHit {
	if a == nil || len(a.lens) == 0 {
		return dst
	}
	state := int32(0)
	for i := 0; i < len(s); i++ {
		state = a.next[state][acSymbol(s[i])]
		for _, id := range a.out[state] {
			dst = append(dst, acHit{id: id, start: int32(i + 1 - int(a.lens[id])), end: int32(i + 1)})
		}
	}
	return dst
}
