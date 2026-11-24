# Argus

Argus (after Argus Panoptes, the hundred-eyed giant of Greek mythology) is a fast, adaptive **TLS certificate scanner**.
Point it at IPs, CIDR ranges, a file of targets or stdin, and it connects over TLS and prints what the certificates
reveal: hidden domains, organisations, e-mail addresses and exposed infrastructure.

- Single static binary, **no third-party dependencies** (Go standard library only)
- **Adaptive concurrency**: starts from what the machine can take (file descriptors, memory, CPU) and backs off under pressure
- **Live progress** and a completion summary on stderr, results on stdout, so it pipes cleanly
- Certificate **and public-key SHA-256 fingerprints** in the JSON output, for pivoting between hosts
- Several TLS ports per run, a handshake timeout that covers connect and handshake
- **Checkpoint and resume** for long scans (read [the caveat](#checkpoint-and-resume) first)

> Use it only on networks you own or are authorised to test. See [Responsible use](#responsible-use).

## How it works

For every `address:port` in your target list Argus does exactly three things:

1. **Connects** with an ordinary TCP connection (from the operating system's normal socket API).
2. **Completes the TLS handshake** like any client would, without verifying the certificate chain, so self-signed,
   expired and internal certificates are read too.
3. **Reads the certificate the server presents, then closes the connection.** Nothing is sent after the handshake: no
   HTTP request, no banner grab, no payload. (Checked from the server side: one connection, a TLS 1.3 handshake, and
   zero bytes of application data before the client closes.)

For a bare IP no server name (SNI) is sent, so the server answers with its **default certificate**. That is what exposes
virtual hosts and internal names that DNS never told you about. If a target is a hostname, that name is sent as SNI.

CIDRs are expanded as they are scanned, never held in memory as a list, and the scan runs with
[adaptive concurrency](#concurrency) so it does not exhaust the machine it runs on.

### Why that matters

- **Light touch.** One connection and no request per target, and a single port (443) unless you ask for more with `-p`.
  Tools in the same space typically do more to every target: sweep many ports, send an HTTP request after connecting, or
  repeat the handshake to test every protocol version and cipher suite.
- **It is not a port scanner.** Argus only visits the `address:port` pairs you give it. It never sweeps ports to find
  what is open; if you need discovery, run a port scanner first and feed the results to Argus as `ip:port` lines.
- **No raw packets, no root.** It uses normal TCP connections (no SYN scanning, no libpcap, no special privileges), so it
  runs as an ordinary user on any machine that can open outbound connections.
- **Names, owners and pivots in one pass.** Subject names, organisations, e-mail addresses and IPs from each certificate,
  plus certificate and public-key fingerprints to link hosts that share a key.
- **One static binary, standard library only.** Nothing to install beyond the executable.

### What it is not

Argus is **not stealthy**. Each probe is a real TCP connection and TLS handshake, which the target's firewall, IDS or
logs can record as a connection that opens and closes without a request, and a large sweep is visible by sheer volume.
"Low noise" here means fewer packets and no application traffic compared with port or HTTP scanning, not invisibility.
Scan only what you are authorised to scan (see [Responsible use](#responsible-use)).

## Install

### Go one-liner

Needs Go 1.22.2 or newer. The binary lands in `$(go env GOPATH)/bin` (usually `~/go/bin`, make sure it is on your `PATH`).

```sh
go install github.com/mr-rizwan-syed/argus/cmd/argus@latest
argus -h
```

### Pre-built binary from Releases (Linux x86-64)

```sh
curl -fsSLO https://github.com/mr-rizwan-syed/Argus/releases/latest/download/argus-linux-amd64
curl -fsSLO https://github.com/mr-rizwan-syed/Argus/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS                  # verify
chmod +x argus-linux-amd64
sudo install -m 0755 argus-linux-amd64 /usr/local/bin/argus   # optional
```

Releases are built by GitHub Actions when a version tag is pushed (`git tag v1.0.1 && git push origin v1.0.1`), see
[`.github/workflows/release.yml`](.github/workflows/release.yml). Only Linux x86-64 is published: macOS and ARM builds
compile but have not been tested, and Windows is not supported.

The same binary is also committed in this repository:

```sh
git clone git@github.com:mr-rizwan-syed/Argus.git && cd Argus
sha256sum -c bin/SHA256SUMS
chmod +x bin/argus-linux-amd64 && ./bin/argus-linux-amd64 -h
```

The binary is static (`CGO_ENABLED=0`, no libc needed), stripped, and built with Go 1.24.0 on Linux x86-64 using
`CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "-s -w" ./cmd/argus`. Building the same source with those
exact flags and Go version gives a **byte-identical** binary (check with `sha256sum`). Without `-buildvcs=false` Go stamps
the git revision into the binary, so the file works the same but its hash differs.

### Build from source

Needs Go 1.22.2 or newer. No C compiler is required.

```sh
git clone git@github.com:mr-rizwan-syed/Argus.git && cd Argus
CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "-s -w" -o argus ./cmd/argus
./argus -h
```

(`-trimpath -buildvcs=false -ldflags "-s -w"` only make the binary smaller and reproducible; a plain
`go build -o argus ./cmd/argus` works too.)

Cross-compiling works for Linux and macOS (`GOOS=linux|darwin`, `GOARCH=amd64|arm64`). **Windows is not supported**: the
file-descriptor handling uses Unix-only system calls.

## Quick start

```sh
argus -i 203.0.113.10                      # one host, port 443
argus -i 203.0.113.0/24                    # a CIDR
argus -i 203.0.113.10,198.51.100.0/28      # a comma-separated list
argus -i targets.txt                       # a file, one IP / CIDR / ip:port per line
cat targets.txt | argus                    # the same, from stdin
argus -i targets.txt -p 443,8443,9443      # several ports
argus -i targets.txt -j > results.jsonl    # full certificate data, one JSON object per line
```

By default Argus prints the domain names found in each certificate, one per line:

```
$ argus -i 127.0.0.1 -p 8443
www.example.test
www.example.test
api.example.test
```

A name can appear twice: the certificate's common name is also listed among its alternative names. De-duplicate with
`sort -u` when you only want the set of names.

## Options

| Flag | Default | Meaning |
|---|---|---|
| `-i <value>` | stdin | IPs and CIDRs separated by commas, **or** a path to a file with one entry per line. Omit it to read targets from stdin. |
| `-p <ports>` | `443` | Comma-separated TLS ports to check on every address. |
| `-c <n>` | `0` (auto) | Starting concurrency. `0` picks it from the machine, see [Concurrency](#concurrency). |
| `-t <seconds>` | `4` | Timeout for one TLS attempt. It covers the TCP connect **and** the whole handshake. |
| `-j` | off | Print the full certificate data as JSON Lines instead of just domain names. |
| `-wc` | off | Include wildcard names (`*.example.test`) in the domain output. |
| `-debug` | off | Also print failures and timeouts, on stdout. |
| `-resume` | off | Continue from the checkpoint of a previous run on the same input file. |
| `-order <mode>` | `sequential` | `random` walks every address:port in a shuffled order (a keyed bijection, O(1) memory), so no network sees a burst of probes. IPv4 addresses and CIDRs only. |
| `-seed <n>` | `0` (pick) | Seed of the random order. It is printed at the start and kept in the checkpoint; a resume uses the seed it started with. |
| `-rate <n>` | `0` (no cap) | Most probes started per second. Without it only concurrency bounds the speed, which lets a fast machine outrun its own NIC, connection tracker or the targets' networks. |
| `-syncnt <n>` | `0` (kernel) | `TCP_SYNCNT`: give a connect up after n SYN retransmits (the kernel's default is 6, about two minutes). Linux only. |
| `-fast-close` | off | `SO_LINGER` 0: close with a reset instead of FIN and TIME_WAIT, so finished probes leave nothing behind in the kernel. Linux only. |
| `-h` | | Show the usage message. |

### Input formats

| Entry | Means |
|---|---|
| `203.0.113.10` | that host, on every port given with `-p` |
| `203.0.113.10:8443` | exactly that address and port (`-p` is not applied) |
| `203.0.113.0/24` | every usable address in the range, on every port. For `/30` and larger the network and broadcast addresses are skipped; `/31` and `/32` keep every address |
| blank lines | ignored |

Argus is built and tested with IPv4. IPv6 input is accepted by the parser, but large IPv6 ranges are not practical.

## Output

Results go to **stdout**; progress, warnings and the summary go to **stderr**, so `argus ... > out.jsonl` stays clean.

### JSON Lines (`-j`)

One object per certificate that answered:

```json
{"originip":"127.0.0.1:8443","org":["Example Org"],"orgunit":["Security"],"commonName":"www.example.test","san":["www.example.test","*.example.test","api.example.test"],"domains":["www.example.test","www.example.test","*.example.test","api.example.test"],"emails":["security@example.test"],"ips":["127.0.0.1"],"cert_fingerprint":"29:01:DB:C1:DB:10:FE:86:3A:43:01:E4:FF:AD:8A:D9:C7:65:C0:4E:2E:F6:31:67:DF:98:E7:76:8B:21:2C:34","pubkey_fingerprint":"48:97:EA:2A:91:23:29:AF:41:AB:84:BB:30:03:25:3F:CC:56:1F:5E:68:B1:99:62:FA:C3:84:5B:E9:0F:2F:E0"}
```

| Field | Content |
|---|---|
| `originip` | `address:port` the certificate came from |
| `org`, `orgunit` | Subject organisation and organisational unit (lists, may be empty) |
| `commonName` | Subject common name |
| `san` | DNS names in the Subject Alternative Name extension |
| `domains` | common name followed by the SAN names |
| `emails` | e-mail addresses in the certificate |
| `ips` | IP addresses in the certificate's SAN |
| `cert_fingerprint` | SHA-256 of the certificate, uppercase hex with colons |
| `pubkey_fingerprint` | SHA-256 of the public key (`SubjectPublicKeyInfo`), same format: hosts sharing a key share this value even when their certificates differ |

Hosts that do not answer, or do not speak TLS, print nothing (add `-debug` to see them).

### Progress on stderr

```
[argus] CPUs=4  FD-limit=65535  MemAvail=2714MB  concurrency=3000 (auto)      # at start
[argus] 52/256 (20.3%)  hits=2  rate=10/s  concurrency=50                       # every 5 seconds
[argus] done  256/256 (100.0%)  hits=2                                          # at the end
```

The progress and `done` lines end with one counter per reason a probe produced no certificate:
`connect_timeout` (nobody answered the SYN: the normal fate of an unused address), `refused`, `unreachable`, `reset`,
`local_err` (**this machine** ran out of descriptors, buffers, ports or memory: the probe says nothing about the
target), `handshake_timeout` (TCP connected, TLS stalled), `tls_fail` (TCP connected, then not TLS, or a TLS version or
cipher Argus does not offer) and `no_cert`. A scan with a noticeable `local_err` lost replies.

`hits` is the number of certificates found, `rate` the addresses probed per second. The `done` line is the summary:
**if the percentage is below 100 the scan was cut short** (for example by SIGTERM), so do not treat the results as
complete. Input problems are reported as `[argus] input error: ...`.

## Concurrency

With `-c 0` (the default) Argus probes the machine at start-up and uses the lowest of three ceilings:

| Constraint | Formula |
|---|---|
| File descriptors | 75 % of the soft limit (raised to the hard limit at start-up) |
| Memory | available MB × 1024 ÷ 100 KB per active TLS connection |
| CPU | number of CPUs × 750 |

A background monitor checks descriptor use and free memory every 2 seconds and raises or lowers the concurrency; a
warning such as `[adaptive] ⚠ pressure fd=…% mem-free=…% → N` is printed when it backs off. **`-c N` sets the starting
value, not a hard cap**, so on a machine where you need a ceiling, limit it with `ulimit -n` (Argus stays within the
descriptor limit).

For large scans raise the limit first, for example `ulimit -n 50000`. As a reference, about 60 to 70 million addresses
per hour on a 4 vCPU cloud VM was measured in real use; your network and the targets decide the rest.

## Random order

Sequential scanning sends thousands of probes to one /24 within milliseconds, which is what rate limiters and intrusion
detection at a network's edge react to. `-order random` spreads the same probes so a network sees a trickle. Every
address:port is still probed exactly once. In this mode the checkpoint (`<input>.argchk.rand`) is a counter and the seed,
not a line number, and `-resume` goes back a few concurrency-fulls (the probes that were in flight), so a resumed run can
contain duplicate results; deduplicate by `originip`.

## Checkpoint and resume

When the input is a **file**, Argus keeps a checkpoint beside it, `<input>.argchk` (the index of the input line it is
working on). A clean run deletes it. After a crash or a kill, run the same command with `-resume`:

```sh
argus -i ranges.txt -j >> results.jsonl 2>> argus.log      # interrupted...
argus -i ranges.txt -j -resume >> results.jsonl 2>> argus.log
# [argus] resuming from line 4210
```

Things to know:

- Checkpointing is off for stdin and for inline (comma-separated) input.
- After a resume the progress percentage and `done` totals count only the lines still to do.
- **The checkpoint is where the feeder was, not what has finished.** Addresses already handed to the workers, plus
  results still in the output buffer, are lost if the process dies, and a plain `-resume` skips them. In testing about 6 %
  of a small range was missed after a kill with `kill -9`; on a big scan at high concurrency the gap is larger. A kill can
  also cut the last output line in half.
- Be safe: step the checkpoint back, trim the torn line, append, and de-duplicate afterwards.

```sh
# 1. cut a half-written last line (only if the file does not end with a newline)
[ -n "$(tail -c1 results.jsonl)" ] && sed -i '$d' results.jsonl
# 2. go back a few thousand addresses' worth of lines (here 50 lines; scale to your concurrency and line sizes)
echo $(( $(cat ranges.txt.argchk) > 50 ? $(cat ranges.txt.argchk) - 50 : 0 )) > ranges.txt.argchk
# 3. resume, appending
argus -i ranges.txt -j -resume >> results.jsonl 2>> argus.log
# 4. drop the duplicates the overlap produced (keeps the first result per address)
awk -F'"' '!seen[$4]++' results.jsonl > results.dedup.jsonl
```

## Tips

- **One result file per run** and keep `argus.log` (stderr): the `done` line tells you whether the scan finished.
- Split very large CIDRs into smaller ones (for example `/16`s) when you plan to resume: a checkpoint is per input line.
- Run it on a throw-away cloud VM close to the targets for big scans; scanning from a home connection is slow and noisy.
- Use `-t 2` on fast networks to finish sooner, and a larger value for slow or distant targets.

## Certificate Transparency monitor

`argus monitor` is a second mode that reads the public Certificate Transparency logs and reports the new certificates that
match your rules: new hosts of a domain you watch, look-alikes of a brand, and certificates that name an organization. It
does not scan anything and never connects to the names it finds. It is part of every normal build, so the install is the same:

```bash
go install github.com/mr-rizwan-syed/argus/cmd/argus@main      # @latest gives the newest tagged release, which may predate the monitor
argus monitor -rules examples/rules.json -stdout 2>monitor.log | jq --unbuffered -r '"\(.kind)\t\(.score)\t\(.domain)"'
```

Ready-made rule files to try, with what each one should show, are in [`examples/`](examples/README.md). To send matches
somewhere else instead:

```bash
argus monitor -rules rules.json -out matches.jsonl
argus monitor -rules-url https://platform.example/api/ct/rules -rules-secret-file /etc/argus/rules.secret \
              -post-url https://platform.example/api/ct/matches -post-secret-file /etc/argus/post.secret \
              -spool-dir /var/lib/argus/spool -log-state /var/lib/argus/ct-state.json -stats-file /var/lib/argus/ct-stats.json
```

A rule is one organization: up to 5 `apexes` (its domains), 5 `keywords` (brand words looked for inside other people's
domains), 5 `orgs` (names looked for in certificate subjects) and 50 `known` hosts that are its own and never reported.
Rules carry no personal data. The file is `{"version": 1, "rules": [{"id": "acme", "apexes": ["acme.com"], "keywords":
["acme"], "orgs": ["Acme Inc"], "known": ["www.acme.com"]}]}` and is re-read when it changes (`-rules-url`: every minute,
with ETag; plain HTTP only for localhost). Leave a field out rather than giving it an empty list: an empty value makes the
whole file refused.

**Large known lists.** `known` holds at most 50 hosts. For thousands, put hashes in a top-level `sets` object and name it from a rule with
`known_set` (or `known_sets`, up to four): `{"sets": {"mine": {"salt": "any text", "hashes": ["<32 hex>", ...]}}}`. A host is stored as the first
16 bytes of SHA-256 of `<salt>\n<lower-case host>`, in hex, so the file holds no names. A hit whose name, or any parent domain of it, is in the
set is dropped; the set is looked up only for hits, never for every certificate (about a microsecond with 100,000 hosts), and before the
daily cap counts anything, so known hosts never use the cap up. `"kinds": ["subdomain"]` limits a rule to the kinds of hit you want
(`subdomain`, `keyword`, `lookalike`, `org`); an unwanted kind is dropped before the cap too.

Each match is one JSON line: `rule_id`, `kind` (`subdomain`, `keyword`, `lookalike`, `org`), `domain`, `matched`, `score`
(0-100), `reasons` in plain words, `names`, `new_domain`, the issuer and subject organization, validity dates, the
certificate fingerprint, the log and when it was seen. Useful flags: `-min-score` (default 50), `-daily-cap` per rule (500),
`-dedupe-window` (24 h), `-log-state` (a restart continues where it stopped), `-backfill`, `-include-operator` /
`-exclude-operator`, `-spool-dir` (undelivered batches wait there, bounded by `-spool-max-mb`) and `-stats-file`.
`-source replay -replay file.jsonl` feeds saved entries through the same rules, for testing. Run `argus monitor -h` for all
of them.

Expect real load: the logs together produce well over a thousand certificates a second. Measured on a 2 vCPU server it
used about a fifth of both cores and 60 MB of memory. Run it on its own server, not next to a scan.

`-tags nomonitor` leaves the monitor out and compiles a stub instead (`argus monitor` then says this build has none). Use it
when you ship the scanner somewhere with a tight size limit; CertAtlas builds its scan servers that way.

## Responsible use

Argus makes ordinary TLS connections to every address you give it. Scan only systems and networks you own or have
written permission to test, respect the acceptable-use rules of your network and cloud provider, and follow the laws
that apply to you. You are responsible for how you use it.

## Project layout

```
cmd/argus/        command line entry point
cmd/argus/monitor.go   the `argus monitor` command (left out by `-tags nomonitor`)
pkg/ctlog/        reads Certificate Transparency logs
pkg/monitor/      rules, matching, deduplication, outputs
pkg/scrape/       the scan pipeline: feeder, TLS workers, output writer, progress, checkpoint
pkg/adaptive/     adaptive concurrency limiter
pkg/utils/        TLS dialing, input parsing, CIDR expansion, fingerprints, checkpoint files
pkg/workers/      turns results into output lines
pkg/types/        shared types
bin/              pre-built binary and its checksum
```

## License and credits

Argus is released under the [MIT license](LICENSE).

It began as a fork of [Caduceus](https://github.com/g0ldencybersec/Caduceus) by **g0ldencybersec**, whose original commits
are preserved in this repository's history. Caduceus did not publish a license, so see [NOTICE.md](NOTICE.md) for the
credits and for exactly what the MIT license here does and does not cover.
