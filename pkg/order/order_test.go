package order

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestPermIsABijection(t *testing.T) {
	for _, n := range []uint64{1, 2, 3, 7, 100, 255, 256, 257, 1000, 4097, 65536, 100003} {
		p := NewPerm(n, 42)
		seen := make([]bool, n)
		for i := uint64(0); i < n; i++ {
			v := p.At(i)
			if v >= n {
				t.Fatalf("n=%d: value %d out of range", n, v)
			}
			if seen[v] {
				t.Fatalf("n=%d: value %d appears twice", n, v)
			}
			seen[v] = true
		}
	}
}

func TestPermDependsOnTheSeedAndIsRepeatable(t *testing.T) {
	a, b, c := NewPerm(100000, 1), NewPerm(100000, 1), NewPerm(100000, 2)
	same, diff := 0, 0
	for i := uint64(0); i < 1000; i++ {
		if a.At(i) != b.At(i) {
			t.Fatal("the same seed must give the same order")
		}
		if a.At(i) == c.At(i) {
			same++
		} else {
			diff++
		}
	}
	if same > 20 {
		t.Fatalf("two seeds gave nearly the same order (%d of 1000 equal)", same)
	}
}

func TestPermScattersNeighbours(t *testing.T) {
	// consecutive positions must land far apart, or "random" would still hit one network repeatedly
	n := uint64(1 << 20)
	p := NewPerm(n, 7)
	close := 0
	for i := uint64(0); i < 10000; i++ {
		d := int64(p.At(i)) - int64(p.At(i+1))
		if d < 0 {
			d = -d
		}
		if d < 256 { // the same /24
			close++
		}
	}
	if close > 50 {
		t.Fatalf("%d of 10000 consecutive probes fell in the same /24", close)
	}
}

func write(t *testing.T, lines ...string) string {
	f := filepath.Join(t.TempDir(), "in.txt")
	if err := os.WriteFile(f, []byte(strings.Join(lines, "\n")+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestSpaceCountsLikeTheSequentialReader(t *testing.T) {
	in := write(t, "10.0.0.0/24", "10.0.1.0/30", "10.0.2.0/31", "10.0.2.2/32", "192.168.1.5")
	s, err := Build(in, []string{"443"})
	if err != nil {
		t.Fatal(err)
	}
	// /24 -> 254 (network and broadcast skipped), /30 -> 2, /31 -> 2 (both usable), /32 -> 1, a single address -> 1
	if s.Total() != 254+2+2+1+1 {
		t.Fatalf("total %d", s.Total())
	}
	if got := s.At(0); got != "10.0.0.1:443" {
		t.Fatalf("first address %s", got)
	}
	if got := s.At(253); got != "10.0.0.254:443" {
		t.Fatalf("last of the /24 %s", got)
	}
	if got := s.At(254); got != "10.0.1.1:443" {
		t.Fatalf("first of the /30 %s", got)
	}
}

func TestEveryAddressAndPortExactlyOnceInRandomOrder(t *testing.T) {
	in := write(t, "10.0.0.0/28", "10.1.0.0/29", "172.16.0.9")
	s, err := Build(in, []string{"443", "8443"})
	if err != nil {
		t.Fatal(err)
	}
	var seq []string
	for i := uint64(0); i < s.Total(); i++ {
		seq = append(seq, s.At(i))
	}
	p := NewPerm(s.Total(), 99)
	var shuffled []string
	for k := uint64(0); k < s.Total(); k++ {
		shuffled = append(shuffled, s.At(p.At(k)))
	}
	sort.Strings(seq)
	sort.Strings(shuffled)
	if len(seq) != 14*2+6*2+1*2 {
		t.Fatalf("expected %d probes, got %d", 14*2+6*2+2, len(seq))
	}
	for i := range seq {
		if seq[i] != shuffled[i] {
			t.Fatalf("the shuffled walk is not the same set at %d: %s vs %s", i, seq[i], shuffled[i])
		}
		if i > 0 && seq[i] == seq[i-1] {
			t.Fatalf("duplicate %s", seq[i])
		}
	}
}

func TestBuildRejectsWhatItCannotShuffle(t *testing.T) {
	for _, bad := range []string{"example.com", "2001:db8::/32", "10.0.0.1:443", "10.0.0.0/33", "nonsense"} {
		if _, err := Build(write(t, "10.0.0.0/24", bad), []string{"443"}); err == nil {
			t.Errorf("%q should be refused", bad)
		}
	}
	if _, err := Build("10.0.0.0/30,10.0.1.7", []string{"443"}); err != nil {
		t.Fatalf("a comma list is fine: %v", err)
	}
}
