package monitor

// bloom is a small Bloom filter used as a cheap front for the look-alike index: nearly every label of nearly every certificate matches nothing, and
// a hash and two bit tests (a few nanoseconds, in a table that stays in cache) answer that without touching the big maps.
type bloom struct {
	bits []uint64
	mask uint64
}

func newBloom(keys int) *bloom {
	n := uint64(1 << 12)
	for n < uint64(keys)*16 {
		n <<= 1
	}
	return &bloom{bits: make([]uint64, n/64), mask: n - 1}
}

func fnv1a[T ~string | ~[]byte](v T) uint64 {
	h := uint64(14695981039346656037)
	for i := 0; i < len(v); i++ {
		h ^= uint64(v[i])
		h *= 1099511628211
	}
	return h
}

func (b *bloom) add(h uint64) {
	i1 := h & b.mask
	i2 := (h>>29 ^ h*0x9e3779b97f4a7c15>>17) & b.mask
	b.bits[i1>>6] |= 1 << (i1 & 63)
	b.bits[i2>>6] |= 1 << (i2 & 63)
}

func (b *bloom) has(h uint64) bool {
	i1 := h & b.mask
	i2 := (h>>29 ^ h*0x9e3779b97f4a7c15>>17) & b.mask
	return b.bits[i1>>6]&(1<<(i1&63)) != 0 && b.bits[i2>>6]&(1<<(i2&63)) != 0
}
