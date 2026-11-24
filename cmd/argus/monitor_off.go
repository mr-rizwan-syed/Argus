//go:build !monitor

package main

import (
	"fmt"
	"os"
)

// The CT monitor (monitor.go, pkg/ctlog, pkg/monitor) is built only with `-tags monitor`. The scanner servers build Argus without it, so the
// source shipped to them stays small (cloud-init user data is capped at 64 KB) and carries no code a scan never runs.
func runMonitor(args []string) int {
	fmt.Fprintln(os.Stderr, "argus: this build has no monitor; build with `go build -tags monitor ./cmd/argus`")
	return 2
}
