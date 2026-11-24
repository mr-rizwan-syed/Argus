package monitor

import "strings"

// Skeletons: two labels that LOOK alike get the same skeleton. A label is lowercased, its confusable characters are replaced by the plain letter they
// imitate (0 o, 1 l, i l, 3 e, 4 a, 5 s, 8 b; Cyrillic and Greek lookalikes; fullwidth; accented Latin) and the digraphs that read as another letter are
// folded (rn m, vv w, cl d). The same function is applied to the apex's label, so "paypa1", "paypai", "раураl" (Cyrillic) and "paypal" all share one
// skeleton. An internationalised label (xn--) is decoded first.

var asciiSkeleton = func() (t [128]byte) {
	for i := range t {
		t[i] = byte(i)
	}
	t['i'] = 'l'
	t['1'] = 'l'
	t['0'] = 'o'
	t['3'] = 'e'
	t['4'] = 'a'
	t['5'] = 's'
	t['8'] = 'b'
	for c := 'A'; c <= 'Z'; c++ { // upper case reads as the same letter
		t[c] = t[c+32]
	}
	return
}()

// confusables maps non-ASCII characters to the ASCII letters they are mistaken for (a compact table of the ones seen in real attacks).
var confusables = map[rune]string{
	// Cyrillic
	'а': "a", 'е': "e", 'о': "o", 'р': "p", 'с': "c", 'х': "x", 'у': "y", 'і': "i", 'ј': "j", 'ѕ': "s", 'һ': "h", 'ԁ': "d", 'ԛ': "q", 'ԝ': "w",
	'к': "k", 'м': "m", 'н': "h", 'т': "t", 'в': "b", 'ь': "b", 'ѵ': "v", 'ӏ': "l", 'ё': "e", 'ї': "i", 'ґ': "r", 'ү': "y", 'ө': "o", 'ɡ': "g", 'ɑ': "a",
	// Greek
	'α': "a", 'β': "b", 'ε': "e", 'ι': "i", 'κ': "k", 'ν': "v", 'ο': "o", 'ρ': "p", 'τ': "t", 'υ': "u", 'χ': "x", 'ω': "w", 'η': "n", 'μ': "u",
	// Latin look-alikes and accents
	'ı': "i", 'ł': "l", 'ø': "o", 'đ': "d", 'ð': "d", 'þ': "p", 'ß': "ss", 'æ': "ae", 'œ': "oe", 'ƒ': "f", 'ʀ': "r", 'ɴ': "n",
	'à': "a", 'á': "a", 'â': "a", 'ã': "a", 'ä': "a", 'å': "a", 'ā': "a", 'ă': "a", 'ą': "a",
	'ç': "c", 'ć': "c", 'č': "c", 'ď': "d", 'è': "e", 'é': "e", 'ê': "e", 'ë': "e", 'ē': "e", 'ė': "e", 'ę': "e", 'ě': "e",
	'ì': "i", 'í': "i", 'î': "i", 'ï': "i", 'ī': "i", 'į': "i", 'ń': "n", 'ñ': "n", 'ň': "n",
	'ò': "o", 'ó': "o", 'ô': "o", 'õ': "o", 'ö': "o", 'ō': "o", 'ő': "o",
	'ś': "s", 'š': "s", 'ş': "s", 'ť': "t", 'ù': "u", 'ú': "u", 'û': "u", 'ü': "u", 'ū': "u", 'ů': "u", 'ű': "u", 'ų': "u",
	'ý': "y", 'ÿ': "y", 'ź': "z", 'ż': "z", 'ž': "z", 'ǝ': "e", 'ɩ': "i", 'ɯ': "m", 'ʏ': "y",
}

// appendSkeleton appends the skeleton of label to dst. idn reports that the label was an xn-- label that was decoded. A label that cannot be
// decoded is skeletonised as it is.
func appendSkeleton(dst []byte, label string) ([]byte, bool) {
	idn := false
	if strings.HasPrefix(label, "xn--") {
		if runes, ok := punycodeDecode(label[4:]); ok {
			idn = true
			start := len(dst)
			for _, r := range runes {
				dst = appendRuneSkeleton(dst, r)
			}
			return foldDigraphs(dst, start), idn
		}
	}
	start := len(dst)
	ascii := true
	for i := 0; i < len(label); i++ {
		if label[i] >= 0x80 {
			ascii = false
			break
		}
	}
	if ascii {
		for i := 0; i < len(label); i++ {
			dst = append(dst, asciiSkeleton[label[i]])
		}
	} else {
		for _, r := range label {
			dst = appendRuneSkeleton(dst, r)
		}
	}
	return foldDigraphs(dst, start), idn
}

func appendRuneSkeleton(dst []byte, r rune) []byte {
	switch {
	case r < 0x80:
		return append(dst, asciiSkeleton[r])
	case r >= 0xff21 && r <= 0xff3a: // fullwidth A-Z
		return append(dst, asciiSkeleton[r-0xff21+'a'])
	case r >= 0xff41 && r <= 0xff5a: // fullwidth a-z
		return append(dst, asciiSkeleton[r-0xff41+'a'])
	case r >= 0xff10 && r <= 0xff19: // fullwidth 0-9
		return append(dst, asciiSkeleton[r-0xff10+'0'])
	}
	lower := r
	if r >= 'А' && r <= 'Я' { // upper-case Cyrillic: the same letters as lower-case
		lower = r + 32
	}
	if m, ok := confusables[lower]; ok {
		for i := 0; i < len(m); i++ {
			dst = append(dst, asciiSkeleton[m[i]])
		}
		return dst
	}
	if r >= 0x300 && r <= 0x36f { // combining marks add nothing visible
		return dst
	}
	return append(dst, '?') // an unknown character stays distinct from every letter
}

// foldDigraphs folds rn->m, vv->w and cl->d in b[start:] in place.
func foldDigraphs(b []byte, start int) []byte {
	w := start
	for i := start; i < len(b); i++ {
		if i+1 < len(b) {
			switch {
			case b[i] == 'r' && b[i+1] == 'n':
				b[w] = 'm'
				w++
				i++
				continue
			case b[i] == 'v' && b[i+1] == 'v':
				b[w] = 'w'
				w++
				i++
				continue
			case b[i] == 'c' && b[i+1] == 'l':
				b[w] = 'd'
				w++
				i++
				continue
			}
		}
		b[w] = b[i]
		w++
	}
	return b[:w]
}

// skeletonOf is appendSkeleton for callers that want a string.
func skeletonOf(label string) (string, bool) {
	var buf [96]byte
	b, idn := appendSkeleton(buf[:0], label)
	return string(b), idn
}
