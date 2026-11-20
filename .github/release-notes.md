Fast, adaptive TLS certificate scanner. Scans IPs, CIDRs, a file or stdin and prints what the certificates reveal.

## Install

**Go one-liner** (Go 1.22.2 or newer; installs to `$(go env GOPATH)/bin`):

```sh
go install github.com/mr-rizwan-syed/argus/cmd/argus@latest
```

**Pre-built binary (Linux x86-64)** from this release:

```sh
curl -fsSLO https://github.com/mr-rizwan-syed/Argus/releases/latest/download/argus-linux-amd64
curl -fsSLO https://github.com/mr-rizwan-syed/Argus/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS && chmod +x argus-linux-amd64 && ./argus-linux-amd64 -h
```

The binary is static (no libc needed) and was built by GitHub Actions with Go 1.24.0:
`CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "-s -w" ./cmd/argus`.
Only Linux x86-64 is published; macOS and ARM builds compile but have not been tested. Windows is not supported.

See the [README](https://github.com/mr-rizwan-syed/Argus#readme) for usage. Use it only on networks you own or are
authorised to test.

Argus began as a fork of [Caduceus](https://github.com/g0ldencybersec/Caduceus) by g0ldencybersec. See
[NOTICE.md](https://github.com/mr-rizwan-syed/Argus/blob/main/NOTICE.md) for credits and licensing.
