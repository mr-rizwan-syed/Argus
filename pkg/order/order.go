// Package order walks the address space in a pseudo-random order instead of block by block.
//
// Scanning a list sequentially sends thousands of probes to the same /24 within milliseconds, which is exactly what rate limiters and intrusion
// detection on a network's edge react to (and what makes some hosts there look dead). A random order spreads the same probes so that any one
// network sees a trickle. The order is a bijection over the whole index space (every address:port exactly once), computed on the fly with a
// Feistel network and cycle walking, so it needs O(1) memory, is repeatable from a seed, and "how far did we get" is just a counter.
package order

import (
	"bufio"
	"fmt"
	"math/bits"
	"net"
	"os"
	"sort"
	"strings"
)

// Space maps a dense index 0..Total()-1 to "ip:port" over a list of IPv4 CIDRs and addresses (the same addresses, in the same count, as the
// sequential reader: network and broadcast are skipped for prefixes of /30 and shorter).
type Space struct {
	starts []uint64 // first index of each block
	firsts []uint32 // first usable address of each block
	counts []uint64 // usable addresses in each block
	ports  []string
	total  uint64
}

// Build reads `input` (a file with one CIDR or IPv4 address per line, or a comma separated list) for the given ports.
func Build(input string, ports []string) (*Space, error) {
	if len(ports) == 0 {
		return nil, fmt.Errorf("no ports")
	}
	s := &Space{ports: ports}
	add := func(item string) error {
		item = strings.TrimSpace(item)
		if item == "" {
			return nil
		}
		first, count, err := parseBlock(item)
		if err != nil {
			return err
		}
		if count == 0 {
			return nil
		}
		s.starts = append(s.starts, s.total)
		s.firsts = append(s.firsts, first)
		s.counts = append(s.counts, count)
		s.total += count * uint64(len(ports))
		return nil
	}
	if st, err := os.Stat(input); err == nil && !st.IsDir() {
		f, err := os.Open(input)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			if err := add(sc.Text()); err != nil {
				return nil, err
			}
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
	} else {
		for _, item := range strings.Split(input, ",") {
			if err := add(item); err != nil {
				return nil, err
			}
		}
	}
	return s, nil
}

func parseBlock(item string) (first uint32, count uint64, err error) {
	if strings.Contains(item, "/") {
		_, n, err := net.ParseCIDR(item)
		if err != nil {
			return 0, 0, err
		}
		ip4 := n.IP.To4()
		if ip4 == nil {
			return 0, 0, fmt.Errorf("random order supports IPv4 only (%s)", item)
		}
		ones, size := n.Mask.Size()
		count = uint64(1) << uint(size-ones)
		first = ipToUint(ip4)
		if ones <= 30 { // network and broadcast, as the sequential reader skips them
			first++
			count -= 2
		}
		return first, count, nil
	}
	ip := net.ParseIP(item)
	if ip == nil || ip.To4() == nil {
		return 0, 0, fmt.Errorf("random order needs IPv4 addresses or CIDRs (got %q)", item)
	}
	return ipToUint(ip.To4()), 1, nil
}

func ipToUint(ip net.IP) uint32 {
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// Total is the number of address:port pairs.
func (s *Space) Total() uint64 { return s.total }

// At returns the "ip:port" at index i (0 <= i < Total()).
func (s *Space) At(i uint64) string {
	nPorts := uint64(len(s.ports))
	b := sort.Search(len(s.starts), func(k int) bool { return s.starts[k] > i }) - 1
	within := i - s.starts[b]
	addr := s.firsts[b] + uint32(within/nPorts)
	port := s.ports[within%nPorts]
	return fmt.Sprintf("%d.%d.%d.%d:%s", addr>>24, (addr>>16)&0xff, (addr>>8)&0xff, addr&0xff, port)
}

// Perm is a keyed bijection on [0, n).
type Perm struct {
	n     uint64
	half  uint
	mask  uint64
	keys  [4]uint64
}

// NewPerm builds the permutation of n items for a seed.
func NewPerm(n, seed uint64) *Perm {
	b := uint(bits.Len64(n - 1))
	if n <= 1 {
		b = 1
	}
	half := (b + 1) / 2
	p := &Perm{n: n, half: half, mask: (uint64(1) << half) - 1}
	k := seed
	for i := range p.keys {
		k = splitmix(k + 0x9e3779b97f4a7c15)
		p.keys[i] = k
	}
	return p
}

func splitmix(x uint64) uint64 {
	x += 0x9e3779b97f4a7c15
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9
	x = (x ^ (x >> 27)) * 0x94d049bb133111eb
	return x ^ (x >> 31)
}

func (p *Perm) feistel(x uint64) uint64 {
	l, r := x>>p.half, x&p.mask
	for _, k := range p.keys {
		l, r = r, l^(splitmix(r^k)&p.mask)
	}
	return l<<p.half | r
}

// At returns the item that comes at position i of the shuffled order (a bijection: every value in [0, n) appears exactly once).
func (p *Perm) At(i uint64) uint64 {
	x := p.feistel(i)
	for x >= p.n { // cycle walking: stay inside [0, n)
		x = p.feistel(x)
	}
	return x
}
