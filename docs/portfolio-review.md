# Portfolio review

## 1. Actual purpose

The original captures UDP DNS queries with Scapy, computes lexical features, scores anomalies, checks popularity through Tranco, records JSON observations, displays a Flask dashboard, and attempts hosts-file changes. It is a heuristic observation prototype, not a validated inline IPS.

## 2. Quality and suitability

Worth developing for network-security/SOC roles. The original has useful modular separation but unsafe default mutation, brittle packet parsing, non-reproducible testing, and report discrepancies. Its large archive mainly consists of a bundled Python environment and ranking caches rather than unique project source. This cleaned edition is an offline-first educational candidate, not certified security software.

## 3. Findings and remediation

| Severity | Original file | Problem and impact | Prepared-copy remediation | Required before public publication? |
|---|---|---|---|---|
| High | prevent.py | Unvalidated network names written into privileged hosts file; false positives and malformed input can damage resolution | No OS hosts-file writes; strict validation and optional reversible sandbox artifact | Yes; applied |
| High claim issue | capture.py, prevent.py, report | Passive observation plus later hostname mapping does not prove packet prevention | IDS/anomaly scope explicit; no prevention guarantee | Yes; corrected |
| Medium | capture.py | IPv4/UTF-8 assumptions can fail on IPv6 or malformed data | Validate names, handle IPv4/IPv6, skip unsupported packets | Yes; tested |
| Medium | capture.py, dashboard.py | Whole JSON rewritten per packet, concurrent reads and unbounded growth | WAL SQLite, parameterized writes, retention and read snapshots | Yes; tested |
| Medium | prevent.py | Import-time network retrieval; last-two-label registrable-domain error; popularity treated as trust | Explicit suffix file, no automatic network retrieval or PSL inference; context only by default | Yes; applied |
| Medium | test.py | Shell invocation and live third-party queries without assertions | Deterministic synthetic/PCAP tests; no live query generator shipped | Yes; applied |
| Medium | config.py | Machine-specific capture adapter and fixed OS hosts path | Explicit interface argument; no OS hosts target | Yes; applied |
| Privacy/rights | report and original metadata | Student IDs, contributor/Git identity details, unreviewed third-party artifacts | Originals excluded; contributor agreement confirmed; MIT for original code/docs | Yes; excluded |
| High credibility | report | Threshold/score contradictions and unsupported accuracy claims | Corrected evidence discussion; no invented performance metrics | Yes; corrected |

No complete vulnerability audit of the 9,191 bundled environment files or native binaries is claimed. They were inventoried and excluded. The runtime dependency set in this edition is resolved/audited separately. No actual credential revocation was required from an identified live credential finding; no claim of exhaustive secret absence is made.

## 4. File-by-file classification

`file-classification.csv` classifies project-owned files and groups excluded environment/Git/cache content. A complete 9,239-entry filename inventory is delivered separately to the owner, rather than bloating the public repository. No excluded contents are copied. Original source/readme inspection found no README, requirements manifest, license, assertions-based test suite, or supplied PCAP. The empty alerts file does not substantiate the original results table.

## 5. Complete directory tree

See `directory-tree.txt`. Runtime artifacts are intentionally absent.

## 6. README

No README existed in the archive. The complete new README.md explains verified features, installation, offline demo, optional modes, exact scoring, security boundaries, known issues, future work, and license. It does not promise real tunnel detection, live-capture validation, or inline enforcement.

## 7. Exact corrected files and functionality changes

The files in this repository are the exact replacements/additions. The original scoring arithmetic is preserved. `LOW SCORE` replaces misleading `CLEAN`; popularity no longer implies `TRUSTED`. Original popularity escalation is available explicitly. Live capture remains explicit; automatic privileged enforcement and third-party query generation are deliberately replaced by safer sandbox/offline exercises. These behavior changes are documented rather than silently removed.

## 8. Publication checklist

- [x] Separate copy; originals preserved.
- [x] Default offline demonstration; no system hosts modification.
- [x] Deterministic tests and runtime dependency manifest.
- [x] Sensitive source report, metadata, captures, and environments excluded.
- [x] Contributor publication/MIT agreement confirmed by owner.
- [ ] Run the local dashboard and review it in your browser.
- [ ] After uploading, inspect the actual hosted GitHub Actions run.
- [ ] If discussing live capture, test it only on an authorized lab interface and report its result separately.
- [ ] Before claiming detection accuracy, complete a labeled evaluation; current scores alone do not support it.

## 9. Skills and CV wording

Supported skills: Python security automation, DNS packet parsing, network-security fundamentals, explainable detection rules, input validation, local monitoring views, SQLite, and automated testing. No SIEM deployment, production IPS operation, machine learning, incident attribution, or measured detection accuracy is established.

Suggested wording: “Developed an academic DNS anomaly-detection prototype using Scapy and heuristic scoring; later added reproducible offline analysis, safe input handling, bounded event storage, and regression tests.” Distinguish your original contributions, team work, and later AI-assisted changes.

## 10. Honest score

Original artifact: code 4/10, operational security 3/10, documentation accuracy 3/10, organization 3/10, presentation 4/10, portfolio potential 8/10. Equal-weight original-artifact average: 4.2/10. Potential career benefit after careful preparation: 8/10 for network-defense roles. The prepared edition improves engineering and reproducibility, but no new measured detection-accuracy or security-certification score is invented.

## Repository presentation

- Name: dns-anomaly-detection-lab
- Description: Educational DNS anomaly-detection lab using Scapy, explainable heuristic scoring, and a local monitoring dashboard.
- Topics: python, scapy, dns, network-security, intrusion-detection, anomaly-detection, security-automation, educational-project
- License: MIT for original code/docs, with contributor agreement; dependencies retain their terms.
- Screenshots: optional synthetic dashboard only; exclude real query/source details.
- Release: consider v0.1.0 after owner review and hosted CI. Record subsequent fixes in the changelog.
- Pinning: a strong candidate for a network-defense portfolio once you can explain false positives, visibility boundaries, and the difference between observation and prevention.
