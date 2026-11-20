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

## Install

### Pre-built binary (Linux x86-64)

```sh
git clone git@github.com:mr-rizwan-syed/Argus.git && cd Argus
sha256sum -c bin/SHA256SUMS            # verify
chmod +x bin/argus-linux-amd64
./bin/argus-linux-amd64 -h
sudo install -m 0755 bin/argus-linux-amd64 /usr/local/bin/argus   # optional
```

The binary is static (`CGO_ENABLED=0`), stripped, and was built with Go 1.24.0 on Linux x86-64 using
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

## Responsible use

Argus makes ordinary TLS connections to every address you give it. Scan only systems and networks you own or have
written permission to test, respect the acceptable-use rules of your network and cloud provider, and follow the laws
that apply to you. You are responsible for how you use it.

## Project layout

```
cmd/argus/        command line entry point
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
