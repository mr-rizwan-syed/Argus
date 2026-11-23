package utils

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
)

// Fail says WHY a probe produced no certificate. Telling "nobody answered" from "something answered and it was not TLS" from "this machine
// ran out of sockets" is what lets a scan be judged afterwards: a scan with many local failures lost replies, whatever the targets did.
type Fail int

const (
	FailNone             Fail = iota
	FailConnectTimeout        // no answer to the SYN within the deadline: the usual fate of an unused address
	FailRefused               // RST: the host is there, the port is closed
	FailUnreachable           // no route / host or network unreachable (an ICMP error)
	FailReset                 // the connection was reset while connecting
	FailLocal                 // OUR side failed: out of descriptors, buffers, ports or memory; the probe says nothing about the target
	FailHandshakeTimeout      // TCP connected but the TLS handshake stalled
	FailTLS                   // TCP connected, then TLS failed: not TLS, a TLS version or cipher we do not offer, an alert, the peer hung up
	FailNoCert                // a handshake finished without a certificate
	FailOther
	failKinds
)

// Names, in the order of the Fail constants, for the progress line and tests.
var failNames = [...]string{"ok", "connect_timeout", "refused", "unreachable", "reset", "local_err", "handshake_timeout", "tls_fail", "no_cert", "other"}

func (f Fail) String() string { return failNames[f] }

// SockOpts are optional socket settings (Linux). The zero value changes nothing.
type SockOpts struct {
	SynRetries int  // TCP_SYNCNT: give up the connect after this many SYN retransmits (the kernel default is 6, about two minutes)
	FastClose  bool // SO_LINGER 0: close with a reset instead of FIN + TIME_WAIT, so finished probes leave nothing behind in the kernel
}

// Probe dials addr, does a TLS handshake without verification and returns the first certificate. On failure it also returns the reason.
func Probe(ctx context.Context, addr string, opts SockOpts) (*x509.Certificate, Fail, error) {
	d := &net.Dialer{Control: sockControl(opts)}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, classifyDial(err), err
	}
	conn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true})
	defer conn.Close()
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, classifyTLS(err), err
	}
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, FailNoCert, fmt.Errorf("no certificates presented by %s", addr)
	}
	return certs[0], FailNone, nil
}

func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var t interface{ Timeout() bool }
	return errors.As(err, &t) && t.Timeout()
}

func classifyDial(err error) Fail {
	switch {
	case isTimeout(err):
		return FailConnectTimeout
	case errors.Is(err, syscall.ECONNREFUSED):
		return FailRefused
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETDOWN), errors.Is(err, syscall.EHOSTDOWN):
		return FailUnreachable
	case errors.Is(err, syscall.ECONNRESET):
		return FailReset
	case errors.Is(err, syscall.EMFILE), errors.Is(err, syscall.ENFILE), errors.Is(err, syscall.ENOBUFS), errors.Is(err, syscall.ENOMEM),
		errors.Is(err, syscall.EADDRNOTAVAIL), errors.Is(err, syscall.EADDRINUSE), errors.Is(err, syscall.EAGAIN):
		return FailLocal
	case errors.Is(err, context.Canceled):
		return FailOther
	}
	return FailOther
}

func classifyTLS(err error) Fail {
	switch {
	case isTimeout(err):
		return FailHandshakeTimeout
	case errors.Is(err, context.Canceled):
		return FailOther
	case errors.Is(err, syscall.EMFILE), errors.Is(err, syscall.ENOBUFS), errors.Is(err, syscall.ENOMEM):
		return FailLocal
	}
	var alert tls.AlertError
	var hdr tls.RecordHeaderError
	if errors.As(err, &alert) || errors.As(err, &hdr) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET) {
		return FailTLS
	}
	return FailTLS
}

// FailCounts are running totals per reason, safe to share between goroutines through the Stats type in package stats.
const FailKinds = int(failKinds)
