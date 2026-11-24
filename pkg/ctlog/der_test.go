package ctlog

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

var testKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

// makeCert builds a real certificate with crypto/x509.
func makeCert(t testing.TB, tmpl *x509.Certificate) []byte {
	t.Helper()
	if tmpl.SerialNumber == nil {
		tmpl.SerialNumber = big.NewInt(42)
	}
	if tmpl.NotBefore.IsZero() {
		tmpl.NotBefore = time.Date(2026, 11, 1, 10, 20, 30, 0, time.UTC)
		tmpl.NotAfter = time.Date(2027, 1, 20, 10, 20, 30, 0, time.UTC)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &testKey.PublicKey, testKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// agree checks the lean walker against crypto/x509 on one DER certificate: names, subject, issuer, validity.
func agree(t testing.TB, der []byte) Entry {
	t.Helper()
	var e Entry
	if err := entryFromCertificate(der, &e); err != nil {
		t.Fatalf("lean parser: %v", err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("x509: %v", err)
	}
	want := normalisedNames(c)
	if !reflect.DeepEqual(e.Names, want) {
		t.Errorf("names: lean %v, x509 %v", e.Names, want)
	}
	if e.SubjectCN != c.Subject.CommonName || e.IssuerCN != c.Issuer.CommonName {
		t.Errorf("CN: lean %q/%q, x509 %q/%q", e.SubjectCN, e.IssuerCN, c.Subject.CommonName, c.Issuer.CommonName)
	}
	if got, want := e.SubjectO, first(c.Subject.Organization); got != want {
		t.Errorf("subject O: lean %q, x509 %q", got, want)
	}
	if got, want := e.IssuerO, first(c.Issuer.Organization); got != want {
		t.Errorf("issuer O: lean %q, x509 %q", got, want)
	}
	if got, want := e.SubjectOU, first(c.Subject.OrganizationalUnit); got != want {
		t.Errorf("subject OU: lean %q, x509 %q", got, want)
	}
	if !e.NotBefore.Equal(c.NotBefore) || !e.NotAfter.Equal(c.NotAfter) {
		t.Errorf("validity: lean %v..%v, x509 %v..%v", e.NotBefore, e.NotAfter, c.NotBefore, c.NotAfter)
	}
	return e
}

func first(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

// normalisedNames is what Entry.Names must be for a certificate: its SAN DNS names, or a host-like CN when there are none; lowercase, no trailing
// dot, plain ASCII, no duplicates, at most maxNames.
func normalisedNames(c *x509.Certificate) []string {
	var l lean
	for _, n := range c.DNSNames {
		l.addName([]byte(n))
		if len(l.names) >= maxNames {
			break
		}
	}
	var e Entry
	l.subjectCN = c.Subject.CommonName
	l.fill(&e)
	return e.Names
}

func TestLeanParserAgreesWithX509(t *testing.T) {
	long := strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + "." + strings.Repeat("c", 60) + ".example.org"
	many := make([]string, 150)
	for i := range many {
		many[i] = fmt.Sprintf("host%03d.many.example.com", i)
	}
	cases := []struct {
		name string
		tmpl *x509.Certificate
	}{
		{"SAN and CN", &x509.Certificate{Subject: pkix.Name{CommonName: "www.example.com"}, DNSNames: []string{"www.example.com", "example.com"}}},
		{"SAN only, empty subject", &x509.Certificate{DNSNames: []string{"only.example.net"}}},
		{"CN only", &x509.Certificate{Subject: pkix.Name{CommonName: "cn-only.example.org"}}},
		{"CN that is not a host", &x509.Certificate{Subject: pkix.Name{CommonName: "My Private Root"}}},
		{"wildcard", &x509.Certificate{Subject: pkix.Name{CommonName: "*.example.com"}, DNSNames: []string{"*.example.com", "example.com"}}},
		{"uppercase and trailing dot", &x509.Certificate{DNSNames: []string{"WWW.Example.COM", "www.example.com."}}},
		{"IDN as punycode", &x509.Certificate{DNSNames: []string{"xn--bcher-kva.example", "xn--80ak6aa92e.com"}}},
		{"organization and unit", &x509.Certificate{Subject: pkix.Name{CommonName: "acme.com", Organization: []string{"Acme Corporation"}, OrganizationalUnit: []string{"Web"}, Country: []string{"US"}}, DNSNames: []string{"acme.com"}}},
		{"organization with non-ASCII", &x509.Certificate{Subject: pkix.Name{Organization: []string{"Müller & Söhne GmbH"}, CommonName: "mueller.example"}, DNSNames: []string{"mueller.example"}}},
		{"long names", &x509.Certificate{DNSNames: []string{long}}},
		{"150 names, capped at 100", &x509.Certificate{DNSNames: many}},
		{"duplicates", &x509.Certificate{DNSNames: []string{"a.example.com", "a.example.com", "A.EXAMPLE.COM"}}},
		{"IP, email and URI SANs are not names", &x509.Certificate{DNSNames: []string{"real.example.com"}, IPAddresses: []net.IP{net.ParseIP("192.0.2.7"), net.ParseIP("2001:db8::1")}, EmailAddresses: []string{"ops@example.com"}, URIs: []*url.URL{{Scheme: "https", Host: "uri.example.com", Path: "/x"}}}},
		{"only IP SANs", &x509.Certificate{IPAddresses: []net.IP{net.ParseIP("203.0.113.9")}}},
		{"UTCTime and GeneralizedTime", &x509.Certificate{DNSNames: []string{"time.example.com"}, NotBefore: time.Date(2049, 12, 31, 23, 59, 59, 0, time.UTC), NotAfter: time.Date(2051, 1, 2, 3, 4, 5, 0, time.UTC)}},
		{"v1-style: no extensions", &x509.Certificate{Subject: pkix.Name{CommonName: "plain.example.com"}, NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := agree(t, makeCert(t, tc.tmpl))
			if len(e.Fingerprint) != 64 {
				t.Errorf("fingerprint %q", e.Fingerprint)
			}
		})
	}
}

func TestSpecificFields(t *testing.T) {
	der := makeCert(t, &x509.Certificate{
		Subject:  pkix.Name{CommonName: "Acme Login", Organization: []string{"Acme Inc"}},
		DNSNames: []string{"Login.Acme.COM.", "acme-login.example"},
	})
	var e Entry
	if err := entryFromCertificate(der, &e); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(e.Names, []string{"login.acme.com", "acme-login.example"}) {
		t.Errorf("names %v", e.Names)
	}
	if e.SubjectO != "Acme Inc" || e.SubjectCN != "Acme Login" || e.IssuerO != "Acme Inc" {
		t.Errorf("subject/issuer: %+v", e)
	}
	if e.Precert {
		t.Error("an x509 entry is not a precert")
	}
}

func TestPrecertTBS(t *testing.T) {
	der := makeCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "pre.example.com", Organization: []string{"Pre Org"}}, DNSNames: []string{"pre.example.com", "www.pre.example.com"}})
	c, _ := x509.ParseCertificate(der)
	var e Entry
	if err := entryFromTBS(c.RawTBSCertificate, &e); err != nil {
		t.Fatal(err)
	}
	if !e.Precert || !reflect.DeepEqual(e.Names, []string{"pre.example.com", "www.pre.example.com"}) || e.SubjectO != "Pre Org" {
		t.Errorf("%+v", e)
	}
	if e.Fingerprint == "" {
		t.Error("no fingerprint")
	}
}

func TestNoNamesAtAll(t *testing.T) {
	der := makeCert(t, &x509.Certificate{Subject: pkix.Name{Organization: []string{"Org Only"}}})
	var e Entry
	if err := entryFromCertificate(der, &e); err != nil {
		t.Fatal(err)
	}
	if len(e.Names) != 0 || e.SubjectO != "Org Only" {
		t.Errorf("%+v", e)
	}
}

func TestMalformedNeverPanics(t *testing.T) {
	der := makeCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "x.example.com", Organization: []string{"O"}}, DNSNames: []string{"x.example.com"}})
	// every truncation, and every single-byte corruption
	for n := 0; n <= len(der); n++ {
		var e Entry
		_ = entryFromCertificate(der[:n], &e)
		_ = entryFromTBS(der[:n], &e)
	}
	for i := range der {
		for _, v := range []byte{0x00, 0xff, 0x80, 0x7f, 0x30} {
			c := append([]byte(nil), der...)
			c[i] = v
			var e Entry
			_ = entryFromCertificate(c, &e)
			_ = entryFromTBS(c, &e)
		}
	}
	for _, b := range [][]byte{nil, {}, {0x30}, {0x30, 0x80}, {0x30, 0x84, 0xff, 0xff, 0xff, 0xff}, {0x30, 0x03, 0x30, 0x82, 0x01}, {0x1f, 0x00}} {
		var e Entry
		_ = entryFromCertificate(b, &e)
		_ = entryFromTBS(b, &e)
	}
}

func FuzzParse(f *testing.F) {
	f.Add(makeCert(f, &x509.Certificate{Subject: pkix.Name{CommonName: "fuzz.example.com", Organization: []string{"Fuzz"}}, DNSNames: []string{"fuzz.example.com", "*.fuzz.example.com"}}))
	f.Add(makeCert(f, &x509.Certificate{DNSNames: []string{"xn--bcher-kva.example"}}))
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x00})
	f.Fuzz(func(t *testing.T, b []byte) {
		var e Entry
		_ = entryFromCertificate(b, &e)
		_ = entryFromTBS(b, &e)
		if len(e.Names) > maxNames {
			t.Fatalf("%d names", len(e.Names))
		}
	})
}

func TestStringDecoding(t *testing.T) {
	if got := decodeString(0x1e, []byte{0x00, 0x41, 0x00, 0xe9}); got != "Aé" {
		t.Errorf("BMPString: %q", got)
	}
	if got := decodeString(0x1c, []byte{0, 0, 0, 0x41, 0, 0, 0, 0xe9}); got != "Aé" {
		t.Errorf("UniversalString: %q", got)
	}
	if got := decodeString(0x0c, []byte("héllo")); got != "héllo" {
		t.Errorf("UTF8String: %q", got)
	}
	if got := decodeString(0x13, []byte{0x66, 0xe9}); got != "fé" {
		t.Errorf("invalid UTF-8 read as Latin-1: %q", got)
	}
}

func TestTimes(t *testing.T) {
	cases := []struct {
		tag  byte
		in   string
		want time.Time
	}{
		{0x17, "261101102030Z", time.Date(2026, 11, 1, 10, 20, 30, 0, time.UTC)},
		{0x17, "491231235959Z", time.Date(2049, 12, 31, 23, 59, 59, 0, time.UTC)},
		{0x17, "500101000000Z", time.Date(1950, 1, 1, 0, 0, 0, 0, time.UTC)},
		{0x18, "20510102030405Z", time.Date(2051, 1, 2, 3, 4, 5, 0, time.UTC)},
		{0x17, "26110110203", time.Time{}},
		{0x17, "26AB01102030Z", time.Time{}},
		{0x18, "20261301000000Z", time.Time{}},
		{0x04, "261101102030Z", time.Time{}},
	}
	for _, c := range cases {
		if got := parseTime(c.tag, []byte(c.in)); !got.Equal(c.want) {
			t.Errorf("%q: %v, want %v", c.in, got, c.want)
		}
	}
}

func BenchmarkParseCertificate(b *testing.B) {
	der := makeCert(b, &x509.Certificate{Subject: pkix.Name{CommonName: "bench.example.com", Organization: []string{"Bench Org"}}, DNSNames: []string{"bench.example.com", "www.bench.example.com", "*.bench.example.com"}})
	b.SetBytes(int64(len(der)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var e Entry
		_ = entryFromCertificate(der, &e)
	}
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "entries/s")
}

func BenchmarkX509ParseForComparison(b *testing.B) {
	der := makeCert(b, &x509.Certificate{Subject: pkix.Name{CommonName: "bench.example.com", Organization: []string{"Bench Org"}}, DNSNames: []string{"bench.example.com", "www.bench.example.com", "*.bench.example.com"}})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = x509.ParseCertificate(der)
	}
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "entries/s")
}
