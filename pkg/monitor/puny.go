package monitor

import "strings"

// punycodeDecode decodes the part after "xn--" of an internationalised label (RFC 3492). ok is false for anything malformed.
func punycodeDecode(s string) ([]rune, bool) {
	const (
		base        = 36
		tmin        = 1
		tmax        = 26
		skew        = 38
		damp        = 700
		initialBias = 72
		initialN    = 128
	)
	adapt := func(delta, numPoints int, first bool) int {
		if first {
			delta /= damp
		} else {
			delta /= 2
		}
		delta += delta / numPoints
		k := 0
		for delta > ((base-tmin)*tmax)/2 {
			delta /= base - tmin
			k += base
		}
		return k + (base-tmin+1)*delta/(delta+skew)
	}
	var out []rune
	rest := s
	if b := strings.LastIndexByte(s, '-'); b >= 0 {
		for i := 0; i < b; i++ {
			if s[i] >= 0x80 {
				return nil, false
			}
			out = append(out, rune(s[i]))
		}
		rest = s[b+1:]
	}
	n, i, bias := initialN, 0, initialBias
	for pos := 0; pos < len(rest); {
		oldi, w := i, 1
		for k := base; ; k += base {
			if pos >= len(rest) {
				return nil, false
			}
			c := rest[pos]
			pos++
			var digit int
			switch {
			case c >= 'a' && c <= 'z':
				digit = int(c - 'a')
			case c >= 'A' && c <= 'Z':
				digit = int(c - 'A')
			case c >= '0' && c <= '9':
				digit = int(c-'0') + 26
			default:
				return nil, false
			}
			if digit > (1<<30-i)/w {
				return nil, false
			}
			i += digit * w
			t := tmin
			if k > bias {
				t = k - bias
			}
			if t > tmax {
				t = tmax
			}
			if digit < t {
				break
			}
			w *= base - t
			if w > 1<<30 {
				return nil, false
			}
		}
		n += i / (len(out) + 1)
		bias = adapt(i-oldi, len(out)+1, oldi == 0)
		i %= len(out) + 1
		if n > 0x10ffff || (n >= 0xd800 && n < 0xe000) {
			return nil, false
		}
		out = append(out, 0)
		copy(out[i+1:], out[i:])
		out[i] = rune(n)
		i++
	}
	return out, true
}
