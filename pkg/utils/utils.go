package utils

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var domainRegex = regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

// GetSSLCertContext dials addr over TLS and returns the first peer certificate.
// The context deadline covers the entire operation — TCP connect + TLS handshake —
// so a server that accepts the socket but stalls the handshake cannot hold a worker
// beyond the caller's deadline.
func GetSSLCertContext(ctx context.Context, addr string) (*x509.Certificate, error) {
	conn, err := (&tls.Dialer{
		Config: &tls.Config{InsecureSkipVerify: true},
	}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	certs := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates presented by %s", addr)
	}
	return certs[0], nil
}

// IPsFromCIDR generates a slice of IP strings from the given CIDR.
// For prefix lengths <= 30, the network and broadcast addresses are skipped.
// /31 and /32 follow RFC 3021 — all addresses are usable hosts.
func IPsFromCIDR(cidr string, chanInput chan string, ports []string) error {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}

	ones, _ := ipnet.Mask.Size()
	skipEnds := ones <= 30

	isFirst := true
	var prev net.IP

	for cur := ip.Mask(ipnet.Mask); ipnet.Contains(cur); inc(cur) {
		if skipEnds {
			if isFirst {
				isFirst = false
				continue // skip network address
			}
			// Send prev only once we know the current IP is still in range,
			// meaning prev is not the broadcast address.
			if prev != nil {
				for _, port := range ports {
					chanInput <- prev.String() + ":" + port
				}
			}
			prev = make(net.IP, len(cur))
			copy(prev, cur)
		} else {
			for _, port := range ports {
				chanInput <- cur.String() + ":" + port
			}
		}
	}
	// When skipEnds, the final prev holds the broadcast address — intentionally not sent.

	return nil
}

// inc increments an IP address
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// func ExtractNames(cert *x509.Certificate) []string {
// 	names := append([]string{cert.Subject.CommonName}, cert.DNSNames...)
// 	return names
// }

// ReadCheckpoint returns the line index stored in file, or 0 if file is absent.
func ReadCheckpoint(file string) (int, error) {
	data, err := os.ReadFile(file)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("checkpoint %s: %w", file, err)
	}
	return n, nil
}

// WriteCheckpoint atomically writes the current line index to file.
func WriteCheckpoint(file string, line int) error {
	return os.WriteFile(file, []byte(strconv.Itoa(line)+"\n"), 0644)
}

// CountInput returns the total number of host:port addresses IntakeFunction will
// generate for the given input. For CIDRs the count is computed with bit-math
// (no iteration), so it is fast even for large ranges.
// Returns 0 when the total cannot be determined.
// Returns -1 when the input contains IPv6 CIDRs whose count overflows int64.
func CountInput(input string, ports []string) int64 {
	return countInputFrom(input, ports, 0)
}

// CountInputFrom is like CountInput but only counts lines at index >= skipLines.
func CountInputFrom(input string, ports []string, skipLines int) int64 {
	return countInputFrom(input, ports, skipLines)
}

func countInputFrom(input string, ports []string, skipLines int) int64 {
	var total int64
	lineNum := 0
	countItem := func(item string) {
		item = strings.TrimSpace(item)
		if item == "" {
			return
		}
		if isHostPort(item) {
			total++
		} else if isCIDR(item) {
			n := countCIDR(item)
			if n < 0 {
				total = -1
				return
			}
			if total >= 0 {
				total += n * int64(len(ports))
			}
		} else {
			if total >= 0 {
				total += int64(len(ports))
			}
		}
	}

	if _, err := os.Stat(input); err == nil {
		f, err := os.Open(input)
		if err != nil {
			return 0
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if lineNum < skipLines {
				lineNum++
				continue
			}
			lineNum++
			countItem(sc.Text())
		}
	} else {
		for _, item := range strings.Split(input, ",") {
			countItem(item)
		}
	}
	return total
}

// countCIDR returns the number of usable host addresses in a CIDR, matching
// the skip-network/broadcast logic in IPsFromCIDR.
// Returns -1 for IPv6 CIDRs (shift would overflow int64); callers that display
// a percentage should treat a negative return as "total unknown".
func countCIDR(cidr string) int64 {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0
	}
	ones, bits := ipnet.Mask.Size()
	if bits == 0 {
		return 0
	}
	shift := uint(bits - ones)
	if shift >= 63 {
		return -1 // IPv6 or pathological — cannot represent in int64
	}
	size := int64(1) << shift
	if ones <= 30 { // matches IPsFromCIDR: skip network + broadcast
		size -= 2
	}
	if size < 0 {
		size = 0
	}
	return size
}

// IntakeFunction feeds host:port addresses from input into chanInput.
func IntakeFunction(chanInput chan string, ports []string, input string) error {
	return IntakeFunctionFrom(chanInput, ports, input, 0, nil)
}

// IntakeFunctionFrom is like IntakeFunction but skips the first skipLines lines
// and calls beforeLine(lineIndex) just before each line is processed.
// beforeLine is used to write checkpoints; pass nil to disable.
func IntakeFunctionFrom(chanInput chan string, ports []string, input string, skipLines int, beforeLine func(int)) error {
	lineNum := 0
	processLine := func(raw string) error {
		if lineNum < skipLines {
			lineNum++
			return nil
		}
		if beforeLine != nil {
			beforeLine(lineNum)
		}
		err := processInput(raw, chanInput, ports)
		lineNum++
		return err
	}

	if _, err := os.Stat(input); err == nil {
		f, err := os.Open(input)
		if err != nil {
			return fmt.Errorf("open %s: %w", input, err)
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if err := processLine(sc.Text()); err != nil {
				return err
			}
		}
		return sc.Err()
	}
	for _, item := range strings.Split(input, ",") {
		if err := processLine(item); err != nil {
			return err
		}
	}
	return nil
}

func isCIDR(value string) bool {
	return strings.Contains(value, `/`)
}

func isHostPort(value string) bool {
	_, _, err := net.SplitHostPort(value)
	return err == nil
}

func processInput(argItem string, chanInput chan string, ports []string) error {
	argItem = strings.TrimSpace(argItem)
	if argItem == "" {
		return nil
	}
	if isHostPort(argItem) {
		chanInput <- argItem
	} else if isCIDR(argItem) {
		if err := IPsFromCIDR(argItem, chanInput, ports); err != nil {
			return fmt.Errorf("invalid CIDR %q: %w", argItem, err)
		}
	} else {
		for _, port := range ports {
			chanInput <- argItem + ":" + port
		}
	}
	return nil
}

// SHA256Fingerprint returns the SHA-256 digest of raw as an uppercase colon-
// separated hex string (e.g. "AA:BB:CC:..."), the conventional fingerprint format.
func SHA256Fingerprint(raw []byte) string {
	sum := sha256.Sum256(raw)
	var b strings.Builder
	for i, v := range sum {
		if i > 0 {
			b.WriteByte(':')
		}
		fmt.Fprintf(&b, "%02X", v)
	}
	return b.String()
}

func IsValidDomain(domain string) bool {
	return domainRegex.MatchString(domain)
}

func IsWildcard(domain string) bool {
	replaced := strings.Replace(domain, "*.", "", -1)
	return (strings.Contains(domain, "*") && IsValidDomain(replaced))
}
