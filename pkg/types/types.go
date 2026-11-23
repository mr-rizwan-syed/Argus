package types

import "net"

// Scraper Arg types
type ScrapeArgs struct {
	Concurrency    int
	Ports          []string
	Timeout        int
	PortList       string
	Help           bool
	Input          string
	Debug          bool
	JsonOutput     bool
	PrintWildcards bool
	PrintStats     bool
	Resume         bool // skip to checkpoint if one exists for args.Input
	NoCheckpoint   bool // disable auto-checkpoint (set for stdin/temp inputs)

	// Accuracy and pacing (all optional; the zero values behave exactly as before).
	Order      string // "sequential" (the input order, default) or "random" (a shuffled walk over every address:port, see package order)
	Seed       uint64 // random order: the seed (0 = pick one and print it); a resume must use the seed it started with
	Rate       int    // most probes started per second (0 = no cap; concurrency alone then decides)
	SynRetries int    // TCP_SYNCNT for each probe's socket (0 = the kernel default)
	FastClose  bool   // close sockets with a reset instead of FIN + TIME_WAIT
}

// Result Types
type CertificateInfo struct {
	OriginIP            string   `json:"originip"`
	Organization        []string `json:"org"`
	OrganizationUnit    []string `json:"orgunit"`
	CommonName          string   `json:"commonName"`
	SAN                 []string `json:"san"`
	Domains             []string `json:"domains"`
	Emails              []string `json:"emails"`
	IPAddrs             []net.IP `json:"ips"`
	CertFingerprint     string   `json:"cert_fingerprint"`
	PubkeyFingerprint   string   `json:"pubkey_fingerprint"`
}

type Result struct {
	IP          string
	Hit         bool
	Timeout     bool
	FailKind    int // utils.Fail: why there is no certificate (0 = there is one)
	Error       error
	Certificate *CertificateInfo
}

