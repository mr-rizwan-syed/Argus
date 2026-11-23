//go:build !linux

package utils

import "syscall"

// sockControl: the socket options are Linux-only; elsewhere they are ignored.
func sockControl(SockOpts) func(network, address string, c syscall.RawConn) error { return nil }
