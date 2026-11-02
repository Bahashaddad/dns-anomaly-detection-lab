# DNS Anomaly Detection Lab

An educational Python lab for observing DNS queries, extracting lexical features, applying explainable heuristic scores, and viewing retained events in a local Flask dashboard.

**A high score is not proof of DNS tunneling.** This project is not an inline IPS, does not drop packets, and does not modify the operating system's hosts file. Its default demonstration is fully offline and requires no administrator privileges or packet-capture driver.

## Objectives and features

- Compute whole-name Shannon entropy, first-label length, label count, and query-type indicators.
- Assign transparent, weighted scores and low-score/suspicious/high-risk labels.
- Read synthetic queries or local PCAP/PCAPNG data; live UDP DNS capture is an explicit option.
- Handle IPv4 and IPv6 sources and skip malformed/unsupported query names.
- Store a bounded event history in SQLite with concurrent-reader support.
- Display a read-only, loopback dashboard with escaped output and no third-party assets.
- Optionally annotate explicitly listed popular suffixes; popularity does not imply safety.
- Optionally write a reversible `hosts.preview` sandbox artifact. It does not block traffic.

## Technologies and structure

Python, Scapy, Flask, Jinja, SQLite, pytest, Ruff, and pip-audit. The tested runtime dependency closure is pinned in `requirements.txt`; development tools are in `requirements-dev.txt`.

```text
capture.py        CLI modes, packet parsing, and event processing
rules.py          Name validation and lexical features
detect.py         Scoring and explicit popularity-context policy
config.py         Thresholds and local defaults
storage.py        Bounded SQLite event store
dashboard.py      Read-only loopback Flask application
mitigation.py     Optional sandbox preview and restore
templates/        Dashboard template
static/           Local dashboard styling
examples/         Synthetic reserved-domain observations and suffix list
tests/            Deterministic behavior and boundary tests
docs/             Architecture, evaluation, security review, and source disposition
tools/            Tracked-file publication guard
```

The complete tree is in [docs/directory-tree.txt](docs/directory-tree.txt).

## Install

Open PowerShell in this repository. With your installed Python 3.13:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
```

Python 3.12 is also supported by the supplied CI workflow. See [verification](docs/verification.md) for which interpreter versions were actually exercised. Run commands from the repository directory. No credentials or environment file are required.

## Quick offline demonstration

```powershell
.\.venv\Scripts\python.exe capture.py --demo
.\.venv\Scripts\python.exe dashboard.py
```

Open **http://127.0.0.1:5002**. The demo adds five synthetic observations using `.test` names and documentation-only source addresses. Scores are **0, 0, 80, 100, and 60**. Two observations have a high score; they are synthetic examples, not detected attacks.

The dashboard refreshes every three seconds. Repeating the demo adds five more observations; it does not reset the database. Press **Ctrl+C** to stop the dashboard. To keep a separate demonstration run without deleting anything:

```powershell
.\.venv\Scripts\python.exe capture.py --demo --database runtime/session2.sqlite3
.\.venv\Scripts\python.exe dashboard.py --database runtime/session2.sqlite3
```

## Configuration

| Option / file | Meaning |
|---|---|
| `config.py` | Explainable scoring thresholds and weights |
| `--database PATH` | Local event store; default `runtime/events.sqlite3` |
| `--max-events N` | Retained events, 1–100000; default 1000 |
| `dashboard.py --port N` | Loopback dashboard port; default 5002 |
| `--popular-domains PATH` | Local file with one explicitly listed suffix per line |
| `--legacy-popularity-escalation` | Reproduce the original >=50 popular-suffix escalation; off by default |
| `--sandbox-hosts DIRECTORY` | Opt-in preview files in a chosen sandbox directory |

The dashboard shows up to 200 newest events; its totals cover retained events, not all traffic ever observed. It does not change retention settings when opening the database.

## Optional offline PCAP analysis

```powershell
.\.venv\Scripts\python.exe capture.py --pcap captures/authorized-lab.pcap
```

Supply a capture you own or are authorized to analyze; no PCAP is bundled. Reading an offline capture sends no DNS queries and does not need live adapter access. The parser considers UDP queries destined for port 53, extracts the first question, and ignores responses, other transports, and reverse lookups. TCP DNS, DoH, DoT, multi-question analysis, and complete tunnel reconstruction are not implemented.

## Optional authorized live capture

Windows live capture requires a compatible Npcap installation, a working interface, and suitable capture permissions. Install capture components only from their official sources. Live capture was not exercised during preparation.

List Scapy interfaces:

```powershell
.\.venv\Scripts\python.exe -c "from scapy.all import show_interfaces; show_interfaces()"
```

Then explicitly select an interface you are authorized to monitor:

```powershell
.\.venv\Scripts\python.exe capture.py --live --interface "YOUR_INTERFACE"
```

Use a separate terminal for the dashboard. Capturing one interface does not provide automatic network-wide visibility. Stop with Ctrl+C. Live observations may contain sensitive browsing and internal-network data; never commit them.

## Optional sandbox mitigation exercise

```powershell
.\.venv\Scripts\python.exe capture.py --demo --sandbox-hosts runtime/sandbox
Get-Content runtime/sandbox/hosts.preview
.\.venv\Scripts\python.exe mitigation.py --sandbox runtime/sandbox --restore
```

Only high-risk observations are added to the preview. The tool validates names, suppresses exact duplicates, and saves the initial preview content for restoration. The preview is a teaching artifact, not an active DNS policy. Do not copy its entries into the system hosts file as a claim of reliable tunnel prevention.

If a process is interrupted during a sandbox operation, a stale `.lock` file may remain. After confirming no sandbox writer is running, remove only that sandbox lock before retrying. The preview is not designed as a multi-process production policy store.

## Detection logic

| Feature | Condition | Points |
|---|---|---:|
| Whole-name entropy plus first-label length | Entropy >=3.8 and first label >=12 | 35 |
| Long first label | Length >=25 | 30 |
| Query type | TXT or NULL | 25 |
| Full-name label count | At least 4 labels | 15 |

The sum is capped at 100. Scores below 50 are **LOW SCORE**, 50–74 **SUSPICIOUS**, and 75–100 **HIGH RISK**. A low score is not a guarantee of benign traffic. These values reproduce the original scoring arithmetic, not statistically calibrated probabilities.

Optional suffix context uses exact names or a dot-delimited suffix match; it does not infer registrable domains using the last two labels. No list is downloaded automatically. The supplied context file is synthetic, not a Tranco ranking or a security allowlist.

## Checks

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\python.exe -m pip_audit --disable-pip --no-deps -r requirements.txt
```

After initializing Git and staging files, run `python tools/check_publication.py`. The guard is limited and does not replace a secret/history review. GitHub Actions runs offline tests and never starts a live capture or privileged mitigation.

## Security and limitations

Use only authorized data and synthetic demonstrations. Keep runtime databases, packet captures, original reports, environment files, and local adapter details private. The dashboard binds to loopback, rejects remote request addresses, has no write routes, and is not an authenticated multi-user monitoring service.

Lexical heuristics can miss low-entropy/low-volume tunnels and flag legitimate long or random-looking names. There is no labeled evaluation corpus, measured false-positive rate, throughput benchmark, or demonstrated prevention efficacy. Non-ASCII/binary labels outside the supported subset are skipped. Observations are local records, not tamper-proof forensic evidence or SIEM integration.

## Future work

Evaluate against an authorized labeled dataset, report precision/recall and throughput with reproducible methods, add temporal features, and explore resolver-side enforcement as a separately scoped integration. These are recommendations, not implemented features.

## Authorship and license

Original academic contributors: Baha'a Aldeen Shaddad, George Ghassan Wahhab, Ibrahim Al-Shishani, and Wadee Amwar Zaki Eizar. The owner confirmed contributor agreement for publication and MIT licensing.

This edition adds later AI-assisted engineering, tests, synthetic examples, and corrected documentation; do not present those additions as historical coursework results. Original code and portfolio documentation use [MIT](LICENSE). Dependencies and external publications retain their own licenses. No third-party ranking datasets are redistributed.
