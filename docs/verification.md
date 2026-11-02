# Verification — 2026-11-02

## Executed checks

- Fresh isolated Windows/Python 3.12 environment installed the supplied requirements-dev.txt successfully.
- pip check reported no broken requirements.
- 21 pytest cases passed, including malformed names, scoring boundaries, explicit popularity policy, IPv4/IPv6 DNS parsing, synthetic offline PCAP handling, default offline demo, concurrent bounded storage, escaped dashboard output, loopback restriction, sandbox deduplication, and restore.
- The documented offline demo ran without live capture: five observations, scores 0/0/80/100/60, all observe-only.
- CLI sandbox generation and restore ran against workspace preview files; the operating-system hosts file was not opened or modified.
- Critical-error Ruff checks passed (E9, F63, F7, F82). This is not a claim that every optional lint/security rule was enabled.
- pip-audit 2.10.1 found no known vulnerabilities in the eight pinned runtime packages at audit time. JSON is dependency-audit.json. This is not proof of absence of all vulnerabilities.
- A limited tracked-file publication guard passed against a Git-staged snapshot. Personal identifiers and the original adapter identifier were checked without printing their values; no matches remained in the repository candidate.
- Original network.zip and DNS TUNNELING IPS.pdf hashes were recorded and rechecked unchanged. The originals were not modified.

## Not verified

- Python 3.13 could not be invoked in the preparation sandbox; the instructions target the owner's installed interpreter, and hosted CI includes both Python 3.12 and 3.13. No local 3.13 PASS is claimed.
- GitHub Actions has not run until the owner publishes/pushes this new repository.
- No live capture, adapter/driver setup, real malicious traffic, actual tunnel session, production deployment, precision/recall, false-positive rate, or throughput benchmark was tested.
- Dashboard responses, escaping, and static asset delivery were checked through Flask's test client. Manual browser appearance remains an owner check.
- Original PDF text and project-owned source were reviewed; all original screenshots/embedded objects, vendor code, compiled binaries, and virtual-environment files were not individually cleared. They are excluded.
- No old Git history is imported. Review any existing destination repository/history separately.

## Publication decision

Prepared for owner review as an explicitly educational, offline-first anomaly-detection lab. Before public release, try the local demo/dashboard, inspect hosted CI, and keep the limitations visible. Do not present a high heuristic score as proof of tunneling or the sandbox artifact as active protection.
