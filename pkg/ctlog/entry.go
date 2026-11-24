// Package ctlog reads Certificate Transparency logs directly and hands the names of every logged certificate to the monitor.
//
// This file is the CONTRACT between the readers (this package) and the matching engine (package monitor). Nothing else in this package may be
// needed to compile the monitor: it only uses Entry and Source.
package ctlog

import (
	"context"
	"time"
)

// Entry is one logged certificate (or precertificate), reduced to what the monitor needs. Readers fill it from the log entry directly, without
// a full certificate parse: names, the subject and issuer fields that matter, validity and a fingerprint.
type Entry struct {
	Log      string    `json:"log"`                // the log's name from the log list, e.g. "Sectigo Statue2027h1"
	Operator string    `json:"operator,omitempty"` // the operator's name from the log list, e.g. "Sectigo"
	Index    uint64    `json:"index"`              // position in the log
	Seen     time.Time `json:"seen"`               // when this process read the entry
	Logged   time.Time `json:"logged,omitempty"`   // the log's own timestamp for the entry (zero when unknown)

	// Names are the lowercase DNS names of the certificate: every dNSName of the subject alternative name and, when there is none, the subject
	// common name if it looks like a host name. No trailing dot, no duplicates; a wildcard keeps its "*." ("*.example.com"). At most 100.
	Names []string `json:"names"`

	SubjectCN string `json:"subject_cn,omitempty"`
	SubjectO  string `json:"subject_o,omitempty"`
	SubjectOU string `json:"subject_ou,omitempty"`
	IssuerCN  string `json:"issuer_cn,omitempty"`
	IssuerO   string `json:"issuer_o,omitempty"`

	NotBefore time.Time `json:"not_before,omitempty"`
	NotAfter  time.Time `json:"not_after,omitempty"`
	Precert   bool      `json:"precert,omitempty"`

	// Fingerprint is the lowercase hex SHA-256 of the DER that was parsed (the certificate, or the precertificate's TBS).
	Fingerprint string `json:"fingerprint,omitempty"`
}

// Source reads certificate logs until ctx is cancelled and calls emit for every entry it reads, in no particular order across logs. emit is called
// from the readers' goroutines and must return quickly (the monitor's emit only queues).
type Source interface {
	Run(ctx context.Context, emit func(Entry)) error
}
