package ctlog

// REAL entries from live logs (testdata/real_fixtures.json) and a check that the lean parser agrees with crypto/x509 on every one: names,
// subject, issuer, validity. The file is produced by TestUpdateFixtures:
//
//	CT_UPDATE_FIXTURES=1 go test ./pkg/ctlog/ -run TestUpdateFixtures
//
// It reads a handful of recent entries from two RFC 6962 logs and one Static CT log (a few KB in total; the chains are not kept).

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

const fixturePath = "testdata/real_fixtures.json"

type fixtureFile struct {
	Taken  string          `json:"taken"`
	RFC    []rfcLogFixture `json:"rfc6962"`
	Static staticFixt      `json:"static"`
}

type rfcLogFixture struct {
	Log     string `json:"log"`
	Entries []struct {
		Leaf string `json:"leaf"` // base64 MerkleTreeLeaf
		Cert string `json:"cert"` // precertificates only: base64 DER of the whole precertificate (an x509 entry's certificate is in its leaf)
	} `json:"entries"`
}

type staticFixt struct {
	Log   string   `json:"log"`
	Tile  string   `json:"tile"`  // base64 of consecutive TileLeaf entries (the start of a real data tile)
	Count int      `json:"count"` // how many
	Certs []string `json:"certs"` // base64 DER per entry, for comparison
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func TestRealFixturesAgreeWithX509(t *testing.T) {
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Skipf("no real fixtures yet (%v): run CT_UPDATE_FIXTURES=1 go test -run TestUpdateFixtures", err)
	}
	var f fixtureFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	checked, precerts, withO, noNames := 0, 0, 0, 0
	compare := func(where string, e Entry, certDER []byte) {
		t.Helper()
		c, err := x509.ParseCertificate(certDER)
		if err != nil {
			t.Errorf("%s: x509 cannot read the fixture: %v", where, err)
			return
		}
		if want := normalisedNames(c); !reflect.DeepEqual(e.Names, want) {
			t.Errorf("%s: names: lean %v, x509 %v", where, e.Names, want)
		}
		if e.SubjectCN != c.Subject.CommonName || e.IssuerCN != c.Issuer.CommonName {
			t.Errorf("%s: CN: lean %q/%q, x509 %q/%q", where, e.SubjectCN, e.IssuerCN, c.Subject.CommonName, c.Issuer.CommonName)
		}
		if e.SubjectO != first(c.Subject.Organization) || e.IssuerO != first(c.Issuer.Organization) || e.SubjectOU != first(c.Subject.OrganizationalUnit) {
			t.Errorf("%s: O/OU: lean %q/%q/%q, x509 %q/%q/%q", where, e.SubjectO, e.IssuerO, e.SubjectOU, first(c.Subject.Organization), first(c.Issuer.Organization), first(c.Subject.OrganizationalUnit))
		}
		if !e.NotBefore.Equal(c.NotBefore) || !e.NotAfter.Equal(c.NotAfter) {
			t.Errorf("%s: validity: lean %v..%v, x509 %v..%v", where, e.NotBefore, e.NotAfter, c.NotBefore, c.NotAfter)
		}
		if len(e.Names) == 0 { // an IP-address or email-only certificate: nothing to find, and x509 agrees (the names check above)
			noNames++
		}
		checked++
		if e.Precert {
			precerts++
		}
		if e.SubjectO != "" {
			withO++
		}
	}
	for _, lg := range f.RFC {
		for i, ent := range lg.Entries {
			leaf, _ := base64.StdEncoding.DecodeString(ent.Leaf)
			cert, _ := base64.StdEncoding.DecodeString(ent.Cert)
			var e Entry
			if err := parseLeaf(leaf, &e); err != nil {
				t.Errorf("%s #%d: %v", lg.Log, i, err)
				continue
			}
			if len(cert) == 0 { // x509 entry: the certificate is inside the leaf
				cert, _, _ = readU24(leaf[12:])
			}
			compare(fmt.Sprintf("%s #%d", lg.Log, i), e, cert)
		}
	}
	tile, _ := base64.StdEncoding.DecodeString(f.Static.Tile)
	rest := tile
	for i := 0; i < f.Static.Count; i++ {
		te, r, err := nextTileEntry(rest)
		if err != nil {
			t.Fatalf("static #%d: %v", i, err)
		}
		rest = r
		var e Entry
		if te.precert {
			err = entryFromTBS(te.der, &e)
		} else {
			err = entryFromCertificate(te.der, &e)
		}
		if err != nil {
			t.Errorf("static #%d: %v", i, err)
			continue
		}
		cert, _ := base64.StdEncoding.DecodeString(f.Static.Certs[i])
		compare(fmt.Sprintf("%s #%d", f.Static.Log, i), e, cert)
	}
	if len(rest) != 0 {
		t.Errorf("%d bytes left over in the static fixture", len(rest))
	}
	t.Logf("%d real entries agree with crypto/x509 (%d precertificates, %d with a subject organization, %d without DNS names), taken %s", checked, precerts, withO, noNames, f.Taken)
	if checked < 10 || noNames*2 > checked {
		t.Errorf("%d fixtures, %d without names", checked, noNames)
	}
}

func liveGet(ctx context.Context, url string) ([]byte, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("User-Agent", defaultUserAgent)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20))
}

// TestUpdateFixtures (CT_UPDATE_FIXTURES=1) re-reads real entries from live logs and rewrites testdata/real_fixtures.json.
func TestUpdateFixtures(t *testing.T) {
	if os.Getenv("CT_UPDATE_FIXTURES") == "" {
		t.Skip("set CT_UPDATE_FIXTURES=1 to refresh the real fixtures from live logs")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	f := fixtureFile{Taken: time.Now().UTC().Format("2006-01-02")}
	for _, base := range []string{"https://ct.cloudflare.com/logs/nimbus2026/", "https://elephant2026h2.ct.sectigo.com/"} {
		sth, err := liveGet(ctx, base+"ct/v1/get-sth")
		if err != nil {
			t.Logf("skipping %s: %v", base, err)
			continue
		}
		var h struct {
			TreeSize uint64 `json:"tree_size"`
		}
		json.Unmarshal(sth, &h)
		body, err := liveGet(ctx, fmt.Sprintf("%sct/v1/get-entries?start=%d&end=%d", base, h.TreeSize-300, h.TreeSize-1))
		if err != nil {
			t.Logf("skipping %s: %v", base, err)
			continue
		}
		var resp struct {
			Entries []struct {
				LeafInput string `json:"leaf_input"`
				ExtraData string `json:"extra_data"`
			} `json:"entries"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatal(err)
		}
		lg := rfcLogFixture{Log: base}
		var x, p int
		for _, e := range resp.Entries {
			leaf, _ := base64.StdEncoding.DecodeString(e.LeafInput)
			extra, _ := base64.StdEncoding.DecodeString(e.ExtraData)
			if len(leaf) < 12 {
				continue
			}
			precert := leaf[11] == 1
			if (precert && p >= 2) || (!precert && x >= 2) {
				continue
			}
			var cert []byte
			if precert {
				cert, _, _ = readU24(extra) // extra_data of a precert entry starts with the pre_certificate
				p++
			} else {
				x++
			}
			lg.Entries = append(lg.Entries, struct {
				Leaf string `json:"leaf"`
				Cert string `json:"cert"`
			}{b64(leaf), b64(cert)})
		}
		f.RFC = append(f.RFC, lg)
	}
	// a Static CT log: the start of a recent full data tile
	base := "https://mon.willow.ct.letsencrypt.org/2026h2/"
	cp, err := liveGet(ctx, base+"checkpoint")
	if err != nil {
		t.Fatal(err)
	}
	_, size, _ := parseCheckpoint(cp)
	tile := size/tileWidth - 3
	raw, err := liveGet(ctx, base+"tile/data/"+tilePath(tile))
	if err != nil {
		t.Fatal(err)
	}
	if zr, err := gzip.NewReader(bytes.NewReader(raw)); err == nil { // (http.DefaultClient already unzips when the server says so)
		if un, err := io.ReadAll(zr); err == nil {
			raw = un
		}
	}
	rest := raw
	var kept []byte
	st := staticFixt{Log: base}
	for i := 0; i < 5 && len(rest) > 0; i++ {
		te, r, err := nextTileEntry(rest)
		if err != nil {
			t.Fatal(err)
		}
		kept = append(kept, rest[:len(rest)-len(r)]...)
		rest = r
		cert := te.der // a precert entry's whole precertificate is in the tile too; an x509 entry's certificate is the entry itself
		if te.precert {
			cert = te.preCert
		}
		st.Certs = append(st.Certs, b64(cert))
		st.Count++
	}
	st.Tile = b64(kept)
	f.Static = st
	out, _ := json.MarshalIndent(f, "", " ")
	if err := os.WriteFile(fixturePath, out, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s: %d bytes, %d RFC 6962 logs, %d static entries (%s)", fixturePath, len(out), len(f.RFC), st.Count, strings.TrimSuffix(base, "/"))
}
