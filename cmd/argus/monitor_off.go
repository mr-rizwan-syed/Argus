//go:build nomonitor

package main

import (
	"fmt"
	"os"
)

// The CT monitor (monitor.go, pkg/ctlog, pkg/monitor) is part of every normal build. `-tags nomonitor` leaves it out and uses this stub instead: CertAtlas's
// scanner servers build that way, so the source shipped to them stays small (cloud-init user data is capped at 64 KB) and carries no code a scan never runs.
func runMonitor(args []string) int {
	fmt.Fprintln(os.Stderr, "argus: this build has no monitor; build without `-tags nomonitor` to get it")
	return 2
}
