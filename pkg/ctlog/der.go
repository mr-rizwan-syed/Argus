package ctlog

// A hand-written DER walker that pulls out only what the monitor needs from a (pre)certificate: the DNS names of the subject alternative
// name, the subject and issuer common name / organization / organizational unit, the validity and a fingerprint. It never allocates a
// certificate structure, never recurses, and never panics: every read is bounds-checked and malformed input just ends the walk.
//
// It is deliberately NOT a certificate parser. It does not verify anything (signatures, chains, critical extensions) and it accepts what
// crypto/x509 would reject; the tests check that on every real fixture it AGREES with crypto/x509 on names, subject and issuer.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

// maxNames is the most names kept per entry (the contract in entry.go).
const maxNames = 100

var (
	oidCN  = [3]byte{0x55, 0x04, 0x03} // 2.5.4.3
	oidO   = [3]byte{0x55, 0x04, 0x0a} // 2.5.4.10
	oidOU  = [3]byte{0x55, 0x04, 0x0b} // 2.5.4.11
	oidSAN = [3]byte{0x55, 0x1d, 0x11} // 2.5.29.17

	errDER = errors.New("ctlog: malformed DER")
)

// readTLV reads one element from b: its tag, its contents and what follows. ok is false for anything it cannot read safely
// (truncated, indefinite length, high tag numbers, lengths beyond b).
func readTLV(b []byte) (tag byte, val, rest []byte, ok bool) {
	if len(b) < 2 {
		return 0, nil, nil, false
	}
	tag = b[0]
	if tag&0x1f == 0x1f { // multi-byte tag numbers do not occur in the structures walked here
		return 0, nil, nil, false
	}
	l := int(b[1])
	off := 2
	if l&0x80 != 0 {
		n := l & 0x7f
		if n == 0 || n > 4 || len(b) < 2+n { // indefinite length is BER, not DER; more than 4 length bytes is absurd
			return 0, nil, nil, false
		}
		l = 0
		for i := 0; i < n; i++ {
			l = l<<8 | int(b[2+i])
		}
		off = 2 + n
	}
	if l < 0 || len(b)-off < l {
		return 0, nil, nil, false
	}
	return tag, b[off : off+l], b[off+l:], true
}

// lean is what the walk fills in: strings only for the fields kept.
type lean struct {
	names                                             []string
	subjectCN, subjectO, subjectOU, issuerCN, issuerO string
	notBefore, notAfter                               time.Time
}

// parseCertificate walks a DER Certificate (SEQUENCE { tbsCertificate, signatureAlgorithm, signature }).
func parseCertificate(der []byte, out *lean) error {
	tag, cert, _, ok := readTLV(der)
	if !ok || tag != 0x30 {
		return errDER
	}
	return parseTBSContents(cert, out)
}

// parseTBS walks a DER TBSCertificate (SEQUENCE { ... }), which is what a precertificate entry carries.
func parseTBS(der []byte, out *lean) error {
	tag, tbs, _, ok := readTLV(der)
	if !ok || tag != 0x30 {
		return errDER
	}
	return parseTBSBody(tbs, out)
}

// parseTBSContents reads the first element of a Certificate's contents (the TBSCertificate) and walks it.
func parseTBSContents(cert []byte, out *lean) error {
	tag, tbs, _, ok := readTLV(cert)
	if !ok || tag != 0x30 {
		return errDER
	}
	return parseTBSBody(tbs, out)
}

// parseTBSBody walks the contents of a TBSCertificate:
// version [0] EXPLICIT (optional), serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo, [1] [2] (optional), extensions [3] EXPLICIT.
// Fields before the end that cannot be read end the walk with an error; what was read stays in out.
func parseTBSBody(b []byte, out *lean) error {
	tag, v, rest, ok := readTLV(b)
	if !ok {
		return errDER
	}
	if tag == 0xa0 { // version
		if tag, v, rest, ok = readTLV(rest); !ok {
			return errDER
		}
	}
	if tag != 0x02 { // serialNumber
		return errDER
	}
	// signature AlgorithmIdentifier
	if tag, _, rest, ok = readTLV(rest); !ok || tag != 0x30 {
		return errDER
	}
	// issuer
	if tag, v, rest, ok = readTLV(rest); !ok || tag != 0x30 {
		return errDER
	}
	parseName(v, &out.issuerCN, &out.issuerO, nil)
	// validity
	if tag, v, rest, ok = readTLV(rest); !ok || tag != 0x30 {
		return errDER
	}
	parseValidity(v, out)
	// subject
	if tag, v, rest, ok = readTLV(rest); !ok || tag != 0x30 {
		return errDER
	}
	parseName(v, &out.subjectCN, &out.subjectO, &out.subjectOU)
	// subjectPublicKeyInfo
	if tag, _, rest, ok = readTLV(rest); !ok || tag != 0x30 {
		return errDER
	}
	// optional issuerUniqueID [1], subjectUniqueID [2], then extensions [3]
	for len(rest) > 0 {
		if tag, v, rest, ok = readTLV(rest); !ok {
			return errDER
		}
		if tag == 0xa3 {
			parseExtensions(v, out)
			break
		}
	}
	return nil
}

// parseName reads the attributes of a Name (the contents of its outer SEQUENCE OF RelativeDistinguishedName). The last common name wins,
// like crypto/x509's pkix.Name; the first organization and organizational unit are kept.
func parseName(b []byte, cn, o, ou *string) {
	gotO, gotOU := false, false
	for len(b) > 0 {
		tag, rdn, rest, ok := readTLV(b)
		if !ok {
			return
		}
		b = rest
		if tag != 0x31 { // SET
			continue
		}
		for len(rdn) > 0 {
			tag, atv, restRDN, ok := readTLV(rdn)
			if !ok {
				break
			}
			rdn = restRDN
			if tag != 0x30 { // AttributeTypeAndValue
				continue
			}
			otag, oid, valRest, ok := readTLV(atv)
			if !ok || otag != 0x06 || len(oid) != 3 {
				continue
			}
			vtag, val, _, ok := readTLV(valRest)
			if !ok {
				continue
			}
			var key [3]byte
			copy(key[:], oid)
			switch key {
			case oidCN:
				*cn = decodeString(vtag, val)
			case oidO:
				if o != nil && !gotO {
					*o, gotO = decodeString(vtag, val), true
				}
			case oidOU:
				if ou != nil && !gotOU {
					*ou, gotOU = decodeString(vtag, val), true
				}
			}
		}
	}
}

// decodeString converts an ASN.1 string to UTF-8: UTF8String, PrintableString and IA5String as they are (invalid bytes read as Latin-1), BMPString
// as UTF-16BE, UniversalString as UTF-32BE, T61String as Latin-1.
func decodeString(tag byte, v []byte) string {
	switch tag {
	case 0x1e: // BMPString
		if len(v)%2 != 0 {
			return string(v)
		}
		u := make([]uint16, len(v)/2)
		for i := range u {
			u[i] = uint16(v[2*i])<<8 | uint16(v[2*i+1])
		}
		return string(utf16.Decode(u))
	case 0x1c: // UniversalString
		if len(v)%4 != 0 {
			return string(v)
		}
		r := make([]rune, 0, len(v)/4)
		for i := 0; i+3 < len(v); i += 4 {
			r = append(r, rune(uint32(v[i])<<24|uint32(v[i+1])<<16|uint32(v[i+2])<<8|uint32(v[i+3])))
		}
		return string(r)
	case 0x14: // T61String
		return latin1(v)
	}
	if utf8.Valid(v) {
		return string(v)
	}
	return latin1(v)
}

func latin1(v []byte) string {
	r := make([]rune, len(v))
	for i, c := range v {
		r[i] = rune(c)
	}
	return string(r)
}

// parseValidity reads notBefore and notAfter (UTCTime or GeneralizedTime). A time that cannot be read is left zero.
func parseValidity(b []byte, out *lean) {
	tag, v, rest, ok := readTLV(b)
	if !ok {
		return
	}
	out.notBefore = parseTime(tag, v)
	tag, v, _, ok = readTLV(rest)
	if !ok {
		return
	}
	out.notAfter = parseTime(tag, v)
}

func parseTime(tag byte, v []byte) time.Time {
	var year, i int
	switch {
	case tag == 0x17 && len(v) >= 12: // YYMMDDHHMMSS[Z]
		y, ok := digits(v, 0, 2)
		if !ok {
			return time.Time{}
		}
		year, i = 1900+y, 2
		if y < 50 {
			year = 2000 + y
		}
	case tag == 0x18 && len(v) >= 14: // YYYYMMDDHHMMSS[Z]
		y, ok := digits(v, 0, 4)
		if !ok {
			return time.Time{}
		}
		year, i = y, 4
	default:
		return time.Time{}
	}
	month, ok1 := digits(v, i, 2)
	day, ok2 := digits(v, i+2, 2)
	hour, ok3 := digits(v, i+4, 2)
	min, ok4 := digits(v, i+6, 2)
	sec, ok5 := digits(v, i+8, 2)
	if !(ok1 && ok2 && ok3 && ok4 && ok5) || month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || min > 59 || sec > 60 {
		return time.Time{}
	}
	return time.Date(year, time.Month(month), day, hour, min, sec, 0, time.UTC)
}

func digits(v []byte, at, n int) (int, bool) {
	if at+n > len(v) {
		return 0, false
	}
	x := 0
	for _, c := range v[at : at+n] {
		if c < '0' || c > '9' {
			return 0, false
		}
		x = x*10 + int(c-'0')
	}
	return x, true
}

// parseExtensions walks the Extensions SEQUENCE and collects the dNSNames of the subject alternative name.
func parseExtensions(b []byte, out *lean) {
	tag, exts, _, ok := readTLV(b)
	if !ok || tag != 0x30 {
		return
	}
	for len(exts) > 0 {
		tag, ext, rest, ok := readTLV(exts)
		if !ok {
			return
		}
		exts = rest
		if tag != 0x30 {
			continue
		}
		otag, oid, after, ok := readTLV(ext)
		if !ok || otag != 0x06 || len(oid) != 3 || oid[0] != oidSAN[0] || oid[1] != oidSAN[1] || oid[2] != oidSAN[2] {
			continue
		}
		tag, v, after2, ok := readTLV(after)
		if !ok {
			return
		}
		if tag == 0x01 { // critical BOOLEAN
			if tag, v, _, ok = readTLV(after2); !ok {
				return
			}
		}
		if tag != 0x04 { // OCTET STRING holding the GeneralNames
			return
		}
		parseGeneralNames(v, out)
		return
	}
}

// parseGeneralNames reads SEQUENCE OF GeneralName and keeps the dNSName ([2] IA5String) entries, normalised.
func parseGeneralNames(b []byte, out *lean) {
	tag, names, _, ok := readTLV(b)
	if !ok || tag != 0x30 {
		return
	}
	for len(names) > 0 && len(out.names) < maxNames {
		tag, v, rest, ok := readTLV(names)
		if !ok {
			return
		}
		names = rest
		if tag == 0x82 {
			out.addName(v)
		}
	}
}

// addName normalises a DNS name (lowercase, no trailing dot) and adds it unless it is empty, too long, not plain ASCII, or already there.
func (l *lean) addName(raw []byte) {
	for len(raw) > 0 && raw[len(raw)-1] == '.' {
		raw = raw[:len(raw)-1]
	}
	if len(raw) == 0 || len(raw) > 253 {
		return
	}
	var buf [64]byte
	b := buf[:0]
	for _, c := range raw {
		if c <= 0x20 || c >= 0x7f {
			return
		}
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b = append(b, c)
	}
	for _, n := range l.names {
		if n == string(b) { // the compiler does not allocate for this comparison
			return
		}
	}
	l.names = append(l.names, string(b))
}

// looksLikeHost is true for a subject common name that can be used as a name when the certificate has no subject alternative name:
// letters, digits, '-', '_', '.', an optional leading "*.", at least one dot, no spaces.
func looksLikeHost(s string) bool {
	if len(s) < 3 || len(s) > 253 {
		return false
	}
	dot := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
		case c == '.':
			dot = true
		case c == '*' && i == 0 && len(s) > 2 && s[1] == '.':
		default:
			return false
		}
	}
	return dot
}

// fill copies a walk's result into an Entry (names, subject, issuer, validity). When the certificate has no SAN dNSName, a host-like subject CN is
// the one name.
func (l *lean) fill(e *Entry) {
	e.Names = l.names
	if len(e.Names) == 0 && looksLikeHost(l.subjectCN) {
		var one lean
		one.addName([]byte(l.subjectCN))
		e.Names = one.names
	}
	e.SubjectCN, e.SubjectO, e.SubjectOU = l.subjectCN, l.subjectO, l.subjectOU
	e.IssuerCN, e.IssuerO = l.issuerCN, l.issuerO
	e.NotBefore, e.NotAfter = l.notBefore, l.notAfter
}

// entryFromCertificate fills an Entry from a DER certificate (x509 log entries). The fingerprint is the SHA-256 of the DER.
func entryFromCertificate(der []byte, e *Entry) error {
	var l lean
	err := parseCertificate(der, &l)
	l.fill(e)
	e.Precert = false
	sum := sha256.Sum256(der)
	e.Fingerprint = hex.EncodeToString(sum[:])
	return err
}

// entryFromTBS fills an Entry from a DER TBSCertificate (precertificate log entries).
func entryFromTBS(tbs []byte, e *Entry) error {
	var l lean
	err := parseTBS(tbs, &l)
	l.fill(e)
	e.Precert = true
	sum := sha256.Sum256(tbs)
	e.Fingerprint = hex.EncodeToString(sum[:])
	return err
}
