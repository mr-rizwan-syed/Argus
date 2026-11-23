//go:build linux

package utils

import "syscall"

const tcpSynCnt = 7 // TCP_SYNCNT

// sockControl returns a dialer Control function applying opts, or nil when there is nothing to apply.
func sockControl(o SockOpts) func(network, address string, c syscall.RawConn) error {
	if o.SynRetries <= 0 && !o.FastClose {
		return nil
	}
	return func(network, address string, c syscall.RawConn) error {
		var inner error
		err := c.Control(func(fd uintptr) {
			if o.SynRetries > 0 {
				if e := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpSynCnt, o.SynRetries); e != nil {
					inner = e
				}
			}
			if o.FastClose {
				if e := syscall.SetsockoptLinger(int(fd), syscall.SOL_SOCKET, syscall.SO_LINGER, &syscall.Linger{Onoff: 1, Linger: 0}); e != nil {
					inner = e
				}
			}
		})
		if err != nil {
			return err
		}
		return inner
	}
}
