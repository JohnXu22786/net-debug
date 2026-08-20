# Security

`dsh-http-debug` is an HTTP debugging toolset for DeepSeek Harness. The SSRF /
private-network protection is a safety control, not a security boundary, and
the package has no ambition to be one: it always runs in the context of the
user who installed it.

## What it protects against

- By default, requests to loopback, RFC 1918 private, CGNAT, link-local,
  multicast, and other reserved IPv4/IPv6 ranges are refused — including hosts
  that *resolve* to them and every redirect hop.
- The `--allow-private` flag and the `allowPrivateScan` config option exist to
  make an explicit, intentional exception; they are off by default.

## What it does not protect against

- It does not gate every conceivable request shape (e.g. rebinding tricks are
  mitigated best-effort and documented).
- It does not sandbox the network; a malicious prompt that obtains an explicit
  override can reach private hosts.

## Reporting

Found a security issue? Do not open a public issue. Report it privately via
GitHub's vulnerability reporting flow on this repository, or open a
confidential issue describing the problem without live exploit details.
