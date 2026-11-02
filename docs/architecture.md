# Architecture and trust boundaries

```text
Synthetic queries ─┐
Offline PCAP ──────┼─> parse / validate ─> lexical features ─> weighted score
Opt-in live DNS ───┘                                         │
                                                            ├─> bounded SQLite events ─> loopback dashboard
                                                            └─> optional sandbox hosts.preview
```

The default path consumes only supplied synthetic JSON and writes a local database. DNS input is untrusted: unsupported names are rejected, IP addresses are normalized, SQL values are parameterized, and Jinja escapes event fields. Popular suffixes add context only unless the explicit legacy-policy flag is selected.

Capture and dashboard can run as separate processes. SQLite WAL and a short timeout support simultaneous writes/reads. Retention is enforced during writes; the dashboard reads a consistent snapshot and does not purge records. The dashboard has no credentials because it is explicitly restricted to loopback and read-only use; it is not suitable as a remotely accessible service.

The original privileged hosts-file write was replaced by sandbox-only preview generation. This changes enforcement behavior deliberately: no actual traffic is blocked. A high-risk observation means that selected heuristics fired, not that a tunnel or attacker has been verified.

Sensitive assets include DNS query names, source addresses, captures, local database files, and user-supplied list contents. Keep their runtime copies out of Git. An attacker already controlling the host or its filesystem is outside this lab's assurance boundary.
