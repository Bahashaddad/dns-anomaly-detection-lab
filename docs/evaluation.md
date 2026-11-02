# Evaluation and corrected claims

## Executed deterministic checks

The supplied five-query offline example yields scores 0, 0, 80, 100, and 60. Two are high-risk synthetic examples. Tests assert those values; they are not malware or tunnel ground truth. Other tests cover scoring boundaries, malformed names, suffix boundaries, IPv4/IPv6 parsing, reply/non-DNS filtering, malformed PCAP names, retention/concurrent writers, dashboard escaping, and sandbox deduplication/restore.

## Original-report discrepancies

- The supplied implementation computes entropy over the complete name after removing dots, not only the subdomain.
- Actual configuration uses entropy 3.8, an entropy-rule first-label minimum of 12, long-label threshold 25, and full-label threshold 4. The original report lists conflicting values.
- `teams.microsoft.com` and `outlook.office.com` score 0 under those rules, not the reported 15.
- The configured weights 35/30/25/15, capped at 100, cannot produce the reported 95-point example.
- The supplied `alerts.json` is empty; a reproducible source log for the claimed run is absent.
- Fifteen random DNS queries without assertions do not establish accuracy, lack of false positives, or prevention efficacy.
- An observed query has already reached the capture point. A later hosts-file change cannot retract it or establish an inline IPS. Direct DNS tools and encrypted/custom resolvers can bypass ordinary local hostname mappings.

## What remains unmeasured

No labeled benign/tunnel corpus, actual tunnel session, precision/recall estimate, false-positive rate, throughput benchmark, network-wide enforcement experiment, or production deployment has been verified. No real malicious traffic was generated. Live capture is implemented but not exercised in the preparation environment.

For a future evaluation, obtain authorized labeled inputs, document collection/sampling, separate tuning and evaluation sets, define counting units, and report false positives/negatives alongside resource use. Do not invent those results from synthetic score examples.

## Sources for technical boundaries

- Microsoft DNS client troubleshooting explains that nslookup directly contacts DNS servers: https://github.com/MicrosoftDocs/SupportArticles-docs/blob/main/support/windows-client/networking/troubleshoot-dns-client-resolution-issues.md
- Scapy documents offline PCAP input and capture behavior: https://scapy.readthedocs.io/en/stable/usage.html

These sources support implementation boundaries; they do not validate this detector's accuracy.
