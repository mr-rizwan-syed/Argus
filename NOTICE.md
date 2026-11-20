# Credits and notices

## Original author

Argus began as a fork of **[Caduceus](https://github.com/g0ldencybersec/Caduceus)** by **g0ldencybersec** (commits
under the name *g0lden*). The idea of scanning IPs and CIDRs for TLS certificates and printing the names they carry,
and the first version of the scanner's structure, come from that project. This repository keeps Caduceus's original
commit history, so the authorship of those commits is preserved (`git log`).

Thank you to g0ldencybersec for publishing it.

## What has changed since

Argus has since been substantially rewritten: adaptive concurrency (`pkg/adaptive`), live progress and a completion
summary, certificate and public-key fingerprints, multi-port scanning, a handshake timeout that covers connect and
handshake, and checkpoint/resume.

## Licensing of the code

The [MIT license](LICENSE) in this repository covers the code written for Argus.

At the time Argus was forked, the Caduceus repository **did not publish a license**. Without a license its author keeps
all rights to the code that originates there, so the MIT license here grants no rights in that original code beyond
what its author has granted. If you reuse Argus in a context where that matters, check with the original author
first.

If you are the author of Caduceus and would like the credit changed, a license added, or any code removed or
rewritten, please open an issue.
