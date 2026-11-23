package utils

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func ctx(t *testing.T, d time.Duration) context.Context {
	c, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return c
}

func TestAHealthyTLSServerGivesItsCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	cert, kind, err := Probe(ctx(t, 3*time.Second), strings.TrimPrefix(srv.URL, "https://"), SockOpts{})
	if err != nil || kind != FailNone || cert == nil {
		t.Fatalf("kind=%v err=%v cert=%v", kind, err, cert)
	}
}

func TestAClosedPortIsRefusedNotATimeout(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	l.Close()
	_, kind, err := Probe(ctx(t, 3*time.Second), addr, SockOpts{})
	if err == nil || kind != FailRefused {
		t.Fatalf("kind=%v err=%v", kind, err)
	}
}

func TestAPortThatIsOpenButNotTLSIsTLSFailure(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			c.Close()
		}
	}()
	_, kind, err := Probe(ctx(t, 3*time.Second), l.Addr().String(), SockOpts{})
	if err == nil || kind != FailTLS {
		t.Fatalf("kind=%v err=%v", kind, err)
	}
}

func TestAServerThatStallsTheHandshakeIsAHandshakeTimeout(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c // accept and say nothing
		}
	}()
	_, kind, err := Probe(ctx(t, 300*time.Millisecond), l.Addr().String(), SockOpts{})
	if err == nil || kind != FailHandshakeTimeout {
		t.Fatalf("kind=%v err=%v", kind, err)
	}
}

func TestSocketOptionsDoNotBreakAProbe(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	_, kind, err := Probe(ctx(t, 3*time.Second), strings.TrimPrefix(srv.URL, "https://"), SockOpts{SynRetries: 2, FastClose: true})
	if err != nil || kind != FailNone {
		t.Fatalf("with socket options: kind=%v err=%v", kind, err)
	}
}

func TestFailNamesMatchTheProgressLine(t *testing.T) {
	want := map[Fail]string{FailConnectTimeout: "connect_timeout", FailRefused: "refused", FailUnreachable: "unreachable", FailReset: "reset",
		FailLocal: "local_err", FailHandshakeTimeout: "handshake_timeout", FailTLS: "tls_fail", FailNoCert: "no_cert"}
	for k, n := range want {
		if k.String() != n {
			t.Errorf("%d is called %q, want %q", k, k.String(), n)
		}
	}
	if len(failNames) != FailKinds {
		t.Fatalf("%d names for %d kinds", len(failNames), FailKinds)
	}
}
