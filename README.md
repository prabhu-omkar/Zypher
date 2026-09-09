# Zypher

**Cryptographic discovery and post-quantum migration intelligence, offline.**

Zypher scans source code, compiled binaries, dependency manifests, container
definitions and X.509 certificates; builds a CycloneDX 1.6 Cryptography Bill of
Materials; assesses every asset against four independent quantum-risk models;
and produces a dated migration plan targeting NIST FIPS 203/204/205.

It runs as a single Windows desktop application. No server, no container
runtime, and no network call at any point in a scan.

Built for **Smart India Hackathon 2026**, NTRO Problem Statement **26164**.

---

## Contents

1. [Why discovery comes first](#1-why-discovery-comes-first)
2. [What Zypher does](#2-what-zypher-does)
3. [Quick start](#3-quick-start)
4. [Building from source](#4-building-from-source)
5. [Architecture](#5-architecture)
6. [The six detection tiers](#6-the-six-detection-tiers)
7. [The risk model](#7-the-risk-model)
8. [Migration targets and planning](#8-migration-targets-and-planning)
9. [Crypto agility](#9-crypto-agility)
10. [Multi-installation deployment](#10-multi-installation-deployment)
11. [Change tracking](#11-change-tracking)
12. [Outputs](#12-outputs)
13. [API reference](#13-api-reference)
14. [Configuration](#14-configuration)
15. [Testing](#15-testing)
16. [Project layout](#16-project-layout)
17. [Design principles](#17-design-principles)
18. [Known limits](#18-known-limits)
19. [Standards and references](#19-standards-and-references)
20. [Licence](#20-licence)

---

## 1. Why discovery comes first

A cryptographically relevant quantum computer breaks RSA, Diffie-Hellman and
elliptic-curve cryptography outright — Shor's algorithm is not a speed-up, it is
a different complexity class. Grover's algorithm halves the effective strength
of symmetric keys and hashes.

NIST published the replacements in August 2024: FIPS 203 (ML-KEM), FIPS 204
(ML-DSA) and FIPS 205 (SLH-DSA). NIST IR 8547 sets the timetable — 112-bit
classical asymmetric cryptography is **deprecated after 2030 and disallowed
after 2035**.

The obstacle is not the algorithms. It is that almost no organisation can
answer the first question a migration asks:

> *Where is our cryptography, what does it protect, and how long must that
> protection hold?*

NIST SP 1800-38 puts cryptographic discovery first in its migration programme
for exactly this reason. Zypher is that discovery step, plus the risk model and
the plan that follow from it.

### Harvest now, decrypt later

An adversary does not need a quantum computer today to benefit from one
tomorrow. Traffic captured now can be stored and decrypted the day a CRQC
exists. Any data whose secrecy must outlive that day is *already* exposed,
which is why the assessment is about time and not just about algorithms.

---

## 2. What Zypher does

| Stage | What happens |
|---|---|
| **Discover** | Six detection tiers find cryptographic assets across source, binaries, dependencies, containers and certificates |
| **Normalise** | Findings become typed artefacts, deduplicated on identity, each carrying its evidence and provenance |
| **Assess** | Four risk models run over every asset; the one demanding the earliest start governs |
| **Prescribe** | A FIPS 203/204/205 target chosen by security level and usage, with shipping implementations named |
| **Plan** | Per-asset deadlines grouped into dated waves, with the critical path and long-lead items identified |
| **Monitor** | Two scans compared, so new cryptographic debt is caught as it appears |

---

## 3. Quick start

### Install

Download `Zypher_Setup.exe` from
[Releases](https://github.com/prabhu-omkar/Zypher/releases) and run it. The
installer is per-user and needs no administrator rights. It installs to
`%LOCALAPPDATA%\Programs\Zypher`, creates Desktop and Start Menu shortcuts and
registers an uninstaller.

### Run a scan

1. Open **Scan**
2. Choose a target — a local folder, a Git repository URL, or an uploaded `.zip`
3. Select what the cryptography protects (this sets **X**, see §7)
4. Set the quantum horizon **Z** (default 8 years)
5. **Start scan**

Results land on the Dashboard. The Inventory tab holds the full asset list, the
Mosca worksheet and the migration plan. Reports exports the CBOM, an HTML audit
report and a CSV inventory.

### What it will not do

Zypher makes no network call during a scan. The one feature that can reach the
internet — looking up published advisories against OSV — is **off by default**
and must be enabled explicitly in Settings.

---

## 4. Building from source

### Prerequisites

| Requirement | Version |
|---|---|
| Windows | 10 or 11 (x64) |
| Python | 3.11+ |
| Node.js | 18+ |
| WebView2 Runtime | Preinstalled on Windows 11; [download](https://developer.microsoft.com/microsoft-edge/webview2/) for Windows 10 |

### Setup

```bash
git clone https://github.com/prabhu-omkar/Zypher.git
cd Zypher

python -m venv .venv
.venv\Scripts\activate

pip install -r requirements.txt
pip install -r requirements-dev.txt

cd frontend && npm install && cd ..
```

### The dataflow engine

Tier 4 uses [OpenGrep](https://github.com/opengrep/opengrep) (LGPL-2.1), which
is **not committed to this repository** — the binary is ~52 MB and would
dominate the history. Download `opengrep-core_windows_x86.exe` from the
OpenGrep releases and place it at:

```
vendor/opengrep/opengrep.exe
```

Zypher runs without it: the dataflow tier reports itself unavailable and the
scan says so in its coverage notes rather than silently returning fewer
results.

### Build

```bash
python build.py                # frontend, application and installer
python build.py --app          # skip the installer
python build.py --skip-frontend
```

Build order is enforced, because the installer bundles `dist/Zypher` as its
payload — building it first produces a setup executable that installs nothing.
The script verifies the payload is present in the finished installer before
declaring success.

Output:

```
dist/Zypher/Zypher.exe     the application
dist/Zypher_Setup.exe      the installer
```

### Run in development

```bash
# Terminal 1 — API on :8000
python -m uvicorn backend.main:app --reload

# Terminal 2 — Vite dev server on :5173
cd frontend && npm run dev
```

---

## 5. Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  pywebview  ·  Edge WebView2 window                         │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  React 18 + Vite + Tailwind        (frontend/)         │  │
│  └───────────────────────────────────────────────────────┘  │
│                          │ HTTP, localhost only              │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  FastAPI + Uvicorn                 (backend/main.py)   │  │
│  ├───────────────────────────────────────────────────────┤  │
│  │  scanners/     six detection tiers                     │  │
│  │  cbom/         normalisation, aggregation, CBOM        │  │
│  │  analysis/     risk inputs, four models, agility       │  │
│  │  recommendation/  targets, migration planner           │  │
│  │  reporting/    HTML, CSV, CycloneDX                    │  │
│  └───────────────────────────────────────────────────────┘  │
│                          │                                   │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  Local JSON files  ·  optional MongoDB                 │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

Everything is packaged into one executable by PyInstaller: grammars, signature
rules, dataflow rules, the analysis binary, fonts and the compiled interface.

### Technology choices

| Layer | Choice | Why |
|---|---|---|
| Parsing | tree-sitter | Reads real argument values at call sites instead of guessing from text |
| Binary | YARA-X | VirusTotal's Rust rewrite; ships stable-ABI wheels, so no C toolchain |
| Dataflow | OpenGrep | LGPL fork of Semgrep CE; runs offline with no JVM |
| Certificates | `cryptography` | Real X.509 parsing rather than matching a PEM header |
| Desktop | pywebview + WebView2 | A real browser engine without shipping one |
| Packaging | PyInstaller | One folder, one installer, no runtime prerequisites |

---

## 6. The six detection tiers

No single technique finds everything. The tiers are complementary, not
alternatives, and each states whether it was able to run.

### Baseline — regular expressions

A single combined prefilter decides whether a file is worth opening at all.
Fifteen separate regexes over every line measured 0.2 MB/s on real third-party
code; one combined substring pass rejects the overwhelming majority of files up
front and raised throughput to 1.9 MB/s.

### Tier 1 — syntax-aware parsing (tree-sitter)

Python, JavaScript, TypeScript, Java and Go are parsed, not matched. The
scanner inspects call sites and reads actual arguments, so `key_size=2048` is a
measured fact rather than an assumed default — and a cryptographic word in a
comment is not a finding.

Compiled queries made this tier 7.8× faster than re-parsing per pattern.

### Tier 2 — dependency identity

Manifests across **8 ecosystems in 11 formats** — npm, PyPI, Maven, Gradle, Go,
Cargo, Composer, RubyGems. Every declared library resolves to an exact version
and a Package URL (purl), which is what lets a CBOM be consumed by any
vulnerability service.

Optionally enriched with OSV advisories. Off by default.

### Tier 3 — binary signatures (YARA-X)

30 compiled rules over binaries and firmware, matching at ~145 MB/s. Finds
cryptography in artefacts that have no source to read.

### Tier 4 — dataflow (OpenGrep)

The tier that exists because of a specific defect: a key size written in one
function and used in another is invisible to every tier above. Tier 4 traces
the value across function boundaries with 19 taint rules covering Python, Java,
JavaScript, TypeScript, Go, C#, Ruby and PHP.

Results are **merged into** the existing inventory rather than producing a
parallel one. It does three jobs: fill gaps, correct assumed defaults, and add
coverage that did not exist (C#, PHP).

Cost: 0.77 s for 1,603 files, on a fixed ~1.8 s start-up.

### Tier 5 — certificates (X.509)

A certificate states its own cryptography in machine-readable form. Parsing it
yields the public key algorithm, key size or curve, signature algorithm and the
exact validity window — all measured, not inferred.

The validity window feeds **X** directly (see §7), and expiry is a finding in
its own right.

---

## 7. The risk model

Mosca's inequality is the headline:

> **X + Y > Z** — if the time data must stay secret (X) plus the time to
> migrate (Y) exceeds the time until a quantum computer exists (Z), you are
> already too late.

The honesty of everything downstream depends on where X, Y and Z come from.

### X — a property of the data, not of the algorithm

RSA-2048 protecting a session cookie and RSA-2048 protecting a medical record
share a primitive and nothing else. X comes from a **data-sensitivity profile**
chosen for the scan:

| Profile | Retention | Basis |
|---|---|---|
| Session / ephemeral | 0.5 y | Tokens, short-lived cache |
| General business | 3 y | No statutory retention |
| Financial records | 7 y | SOX §802; Companies Act |
| Personal data | 10 y | Employment and contract records |
| Health records | 25 y | Measured in decades in most jurisdictions |
| Government / classified | 25 y | Standard review cycle |
| National security | 50 y | The class CNSA 2.0 exists for |

**Confidentiality and authenticity do not take the same X.** This is the single
largest accuracy improvement in the model:

- **Confidentiality and key transport** inherit the full retention period.
  Traffic captured today is decrypted when a CRQC exists, so X is the retention
  of the data the session carried — not the duration of the session.
- **Authenticity and integrity** do not. A forged signature is only useful
  while the credential behind it is still trusted, so X is a validity window.
  Harvest-now-decrypt-later does not apply to a signature.

A certificate under a 25-year health profile therefore gets X = its actual
`notAfter`, not 25 years. Where evidence is ambiguous, classification resolves
toward the longer X.

### Y — computed from the evidence

| Factor | Effect |
|---|---|
| Ownership | Own source 0.25y · dependency 0.75y · vendor binary 1.5y |
| Asset lifecycle | Protocol config 0.15y · certificate 0.30y · key 0.75y · HSM 2.5y |
| Reach | Sub-linear in occurrence count |
| Negotiation | ×1.20 for asymmetric — both ends must agree |
| Change control | ×1.30 critical, ×1.15 high |
| Indirection | ×1.20 hardcoded at the call site, ×0.90 already indirected |

Every asset carries its arithmetic:

```
0.75y base (key lifecycle) × 1.3 for critical change control
  × 1.2 for a hardcoded parameter = 1.17 years
```

A number a reviewer cannot take apart is a number they cannot argue with.

### Z — a distribution with a date

Z is anchored to the assessment date, so a scan states the calendar date it
believes a CRQC arrives by. Behind it sits the Global Risk Institute's *Quantum
Threat Timeline Report 2025*: **28–49% within ten years, 51–70% within
fifteen**. Those bands are published; other points are interpolated and
labelled as such in the code.

### Four models, not one

| Model | Computes | Why |
|---|---|---|
| **Mosca** | X + Y > Z | The recognised baseline, as a schedule |
| **Probabilistic** | P(CRQC before protection lapses), as a band | Z is a distribution; collapsing 28–49% to "38%" invents precision |
| **Regulatory** | Slack against a fixed standards deadline | No estimation in it — the only model an auditor can enforce |
| **HNDL** | Years of harvest-now-decrypt-later exposure | Turns the boolean into a magnitude |

The model demanding the earliest start is the **binding model** and it sets the
schedule.

### From bands to dates

Data encrypted on the last day before migration completes must still be secret
X years later — so migration must *finish* X years before a CRQC exists and
*start* Y years before that. The regulatory model's completion date is the
standards deadline itself.

Banding runs on **slack**: the years between today and the date work must
begin. Timing sets the band; business consequence sharpens it by one step, but
only where the band already says something. A critical asset with six years of
runway stays low.

### Short-circuits

Two classes of asset are not banded by the inequality at all, because it does
not describe them:

- **Already broken** — below the 112-bit classical floor (SP 800-131A). MD5,
  SHA-1, DES/3DES, RC4, RSA < 2048, DSA-1024, secp160r1, secp192r1. These are
  exploitable today; no horizon makes them acceptable.
- **Quantum-safe** — post-quantum by design, *or* safe at these parameters
  (AES-256, SHA-384). No quantum adversary gains a useful advantage, so there is
  no deadline and nothing to migrate.

---

## 8. Migration targets and planning

### Choosing a target

Two things decide it, and neither is latency:

**KEM or signature** comes from what the asset is *used for* — established by
the risk layer, not sniffed from the algorithm's name.

**The parameter set** follows the security level being replaced:

| Replacing | Classical strength | Target |
|---|---|---|
| RSA-2048, P-256, DH-2048 | 112–128 bits | ML-KEM-768 / ML-DSA-65 |
| RSA-7680, P-384 | 192 bits | ML-KEM-768 / ML-DSA-65 |
| P-521 | 256 bits | ML-KEM-1024 / ML-DSA-87 |
| Any, national-security profile | — | ML-KEM-1024 / ML-DSA-87 (CNSA 2.0) |

RSA-2048 provides **112 bits**, not 128 (SP 800-57 Part 1 Rev. 5) — precisely
the figure IR 8547 deprecates in 2030. A Category 3 floor applies even where
strict equivalence allows Category 1, because every shipping default is the
Category 3 set.

Latency only adds a cheaper *alternative*, labelled as a step below the target.

### Where to actually get it

| Implementation | Provides | Caveat |
|---|---|---|
| OpenSSL 3.5+ | ML-KEM, ML-DSA, SLH-DSA | Ships `X25519MLKEM768` as a default TLS keyshare; LTS to April 2030 |
| Go 1.24+ | `crypto/mlkem` | Standard library recommends ML-KEM-768; signatures not yet included |
| Java 24+ | JEP 496, JEP 497 | **Not yet wired into `javax.net.ssl`** |
| Bouncy Castle | All three, JVM and .NET | For runtimes older than Java 24 |
| AWS-LC / BoringSSL | ML-KEM, hybrid TLS | Where an OpenSSL-compatible library is vendored |

**liboqs is not a migration target.** Its own documentation states its
algorithms are experimental and must not be used in production. Finding it in a
shipped manifest is itself a finding.

### The plan

Several hundred dates are not a plan. The planner groups them into waves and
then says where the plan does not work:

- **Breached** — past a deadline already in effect. A compliance report, not
  work to schedule.
- **Infeasible** — the longest job cannot finish by the wave's own deadline
  even starting today.
- **Long-lead items** — a year or more; they set the floor on the programme
  regardless of which wave their deadline falls in.
- **Critical path** — the longest single migration. Even run entirely in
  parallel the estate cannot finish sooner.

No constant is invented: boundaries come from the deadlines, durations from the
computed Y, and concurrency is only assessed when a capacity is stated.

---

## 9. Crypto agility

NIST CSWP 39 frames agility as the ability to replace an algorithm without
disrupting what depends on it — a property of how the cryptography is wired in,
not of the primitive.

Four factors, each reported with its reasoning: **indirection**,
**configurability**, **concentration**, **substitutability**.

Only **indirection** feeds the migration estimate. Y already models reach,
ownership and negotiation; folding the whole score in would count those three
twice.

---

## 10. Multi-installation deployment

Zypher runs offline against local files by default. It can also be pointed at
an organisation's own MongoDB so several analysts contribute to one inventory.

Every scan is stamped with an **installation identity** — a UUID generated once
and kept in the installation's own data directory. Ordinary reads return only
the scans this installation produced. Unlocking an admin session is the only
thing that widens the scope.

- Another installation's scan reads as **404, not 403**. A caller not entitled
  to the data is not entitled to know it exists.
- **Deletion is scoped too**, or a shared database lets any installation
  destroy another's work.
- **Ambiguity resolves toward showing less.** A scan with no installation id is
  this installation's on local disk, and unknown-origin in a shared database.

> **This is application-level scoping, not encryption.** Anyone holding the
> connection string can read the collections with a database client. Closing
> that off is a matter of per-user database credentials or field-level
> encryption.

### The estate view

Signing in as admin adds one tab where every asset across every stored scan is
queryable, with server-side filtering, sorting and paging. It deliberately does
**not** deduplicate: the same library in two systems is two things to fix.

Sessions carry an eight-hour absolute lifetime, expire on read, are revoked
server-side on sign-out, and lock out after repeated failures. Leaving admin
mode requires the password as well.

---

## 11. Change tracking

One scan says what the cryptography is. Two say whether it is getting better or
worse.

Assets are matched on algorithm family, artefact type and file — deliberately
**not** on key size. Weakening RSA-2048 to RSA-1024 in the same file is one call
site getting worse; reporting it as a removal plus an unrelated addition hides
the event worth seeing.

A band movement caused by a different horizon, a different sensitivity profile
or different file coverage produces an explicit note saying so.

---

## 12. Outputs

| Format | Contents |
|---|---|
| **CycloneDX 1.6 JSON** | Every asset as a cryptographic-asset component with `cryptoProperties`, purl identity and evidence occurrences |
| **HTML report** | Executive summary, migration schedule, Mosca worksheet, per-asset remediation. Prints to PDF |
| **CSV** | 47 columns — one row per asset with risk inputs, dates, agility and targets |

---

## 13. API reference

The backend is a normal FastAPI application. Interactive docs at
`http://127.0.0.1:8000/docs` while running.

### Scanning

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/scan/path` | Scan a local directory or file |
| `POST` | `/api/scan/git` | Clone and scan a repository |
| `POST` | `/api/scan/upload` | Scan an uploaded file or `.zip` |
| `POST` | `/api/scan/ci` | Blocking scan for a pipeline |
| `GET` | `/api/jobs/{job_id}` | Progress of a running scan |

### Results

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/scans` | List stored scans |
| `GET` | `/api/scans/{id}` | One scan |
| `GET` | `/api/scans/merged` | Every scan unioned and deduplicated |
| `POST` | `/api/scans/{id}/recalculate` | Re-assess at a different Z or profile |
| `GET` | `/api/scans/{id}/migration-plan` | Dated waves; `?capacity=N` |
| `GET` | `/api/scans/{a}/compare/{b}` | What changed between two scans |
| `DELETE` | `/api/scans/{id}` | Remove a scan |

### Exports

| Method | Path |
|---|---|
| `GET` | `/api/scans/{id}/cbom` |
| `GET` | `/api/scans/{id}/report/html` |
| `GET` | `/api/scans/{id}/report/csv` |

### Admin

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/admin/status` | Setup state and whether this caller holds a session |
| `POST` | `/api/admin/setup` · `/login` · `/logout` | Session lifecycle |
| `GET` | `/api/admin/artefacts` | Estate register, paged and filterable |
| `GET` | `/api/admin/facets` | Filter values that occur |
| `GET` | `/api/admin/overview` | Cross-scan metrics |
| `POST` | `/api/admin/reindex` | Rebuild the register after attaching a database |

---

## 14. Configuration

All optional. Zypher works with none of them set.

| Variable | Default | Effect |
|---|---|---|
| `ECDAT_MONGO_URI` | *(unset)* | Shared MongoDB connection string |
| `ECDAT_DB_NAME` | `ecdat_enterprise_inventory` | Database name |
| `ECDAT_VULN_LOOKUP` | `0` | Enable OSV advisory lookup — **the only networked feature** |
| `ECDAT_DATAFLOW` | `1` | Tier 4 dataflow analysis |

> Variable names keep the `ECDAT_` prefix from before the rename so existing
> deployments keep working.

Storage lives beside the executable in a packaged build, or in `data_store/`
when run from source.

---

## 15. Testing

```bash
python -m pytest backend/tests -q        # 424 tests
python -m pytest backend/tests -v        # verbose
python -m pytest backend/tests/test_risk_models.py
```

| Suite | Covers |
|---|---|
| `test_risk_models.py` | X/Y/Z derivation, four models, banding, quantum-safe short-circuits |
| `test_migration_targets.py` | Target selection, security levels, the planner |
| `test_admin_estate.py` | Sessions, lockout, the estate register |
| `test_installation_isolation.py` | Scoping between installations |
| `test_certificate_scanner.py` | X.509 parsing and measured validity |
| `test_agility_and_delta.py` | Agility scoring and scan comparison |
| `test_taint_scanner.py` | Tier 4 dataflow merging |
| `test_ast_scanner.py` · `test_yara_engine.py` · `test_walker.py` | Detection tiers |
| `test_pipeline.py` · `test_merged_view.py` · `test_aggregator.py` | End-to-end |

---

## 16. Project layout

```
Zypher/
├── backend/
│   ├── main.py                  FastAPI application and scan pipeline
│   ├── models.py                Typed domain model
│   ├── config.py                Environment configuration
│   ├── admin_session.py         Session lifetime and login throttling
│   ├── scanners/
│   │   ├── walker.py            Shared traversal with caps and exclusions
│   │   ├── source_scanner.py    Regex baseline + prefilter
│   │   ├── ast_scanner.py       Tier 1 — tree-sitter
│   │   ├── dependency_scanner.py Tier 2 — manifests and purl
│   │   ├── binary_scanner.py    Tier 3 — YARA-X
│   │   ├── taint_scanner.py     Tier 4 — merges dataflow results
│   │   ├── opengrep_engine.py   Tier 4 — subprocess and trace parsing
│   │   ├── certificate_scanner.py Tier 5 — X.509
│   │   └── rules/               YARA and taint rules
│   ├── cbom/
│   │   ├── artefact_extractor.py Evidence → typed artefacts
│   │   ├── aggregator.py        Deduplication on identity
│   │   ├── cbom_builder.py      CycloneDX 1.6
│   │   ├── artefact_register.py Estate-wide flat rows
│   │   ├── purl.py              Package URL construction
│   │   └── storage.py           Local files and MongoDB
│   ├── analysis/
│   │   ├── risk_inputs.py       Where X, Y and Z come from
│   │   ├── quantum_risk_engine.py The four models
│   │   ├── agility.py           CSWP 39 scoring
│   │   ├── delta.py             Scan comparison
│   │   ├── classifier.py        Business criticality
│   │   └── vulnerability_lookup.py OSV (opt-in)
│   ├── recommendation/
│   │   ├── pqc_targets.py       Security levels and implementations
│   │   ├── recommendation_engine.py Target selection
│   │   └── migration_planner.py Dated waves
│   ├── reporting/report_generator.py
│   └── tests/
├── frontend/src/
│   ├── App.jsx
│   ├── components/              Dashboard, Scan, Inventory, Reports, Estate
│   └── lib/                     Risk helpers, admin context
├── assets/
│   ├── make_icon.py             Generates the application icon
│   └── zypher.ico
├── vendor/opengrep/             Dataflow engine (not committed)
├── build.py                     Build orchestrator
├── Zypher.spec · Zypher_Setup.spec
├── launcher.py · installer_wizard.py
└── requirements.txt
```

---

## 17. Design principles

**Coverage is stated, never implied.** A detector that cannot load is written
into the scan's coverage notes. "No findings" and "did not run" must never look
alike.

**Measured beats assumed.** Every parameter records how it was obtained —
`dataflow`, `literal` or `assumed`. A reviewer must be able to tell a measured
1024 from an assumed 2048 without re-reading the source.

**Ambiguity resolves toward showing more risk.** An asset whose primitive
cannot be identified is never reported as safe.

**Numbers show their working.** X, Y, the agility score and the migration
estimate each carry the reasoning that produced them.

**Offline by construction.** The one feature that can reach the network is off
by default. Everything else works with the machine unplugged.

---

## 18. Known limits

- **Windows only.** The backend and scanners are portable; packaging, the
  WebView2 host and the installer are not.
- **Interfile dataflow.** Tier 4 is intrafile. A value crossing a module
  boundary is still resolved as an assumed default, and labelled as one.
- **Infrastructure coverage.** HSM, KMS and cloud key material are found by
  reference, not by interrogating the service.
- **Application-level isolation only.** See §10.
- **Z is an estimate.** Three of the four models depend on it; the regulatory
  model deliberately does not.

---

## 19. Standards and references

**Quantum algorithms** — Shor (1997) *SIAM J. Computing* 26(5); Grover (1996)
*Proc. 28th ACM STOC*; Gidney & Ekerå (2021) *Quantum* 5:433

**Risk model** — Mosca (2018) *IEEE Security & Privacy* 16(5); Mosca & Piani,
*Quantum Threat Timeline Report 2025*, Global Risk Institute

**Standards** — NIST FIPS 203/204/205; NIST IR 8547; NIST SP 800-131A Rev. 2;
NIST SP 800-57 Part 1 Rev. 5; NIST SP 1800-38 (NCCoE); NIST CSWP 39; NSA CNSA 2.0

**Program analysis** — Yamaguchi et al. (2014) *IEEE S&P* 590–604; Koshelev et
al. (2015) *Prog. & Comp. Software* 41(4)

**CBOM** — OWASP/ECMA-424 CycloneDX 1.6; Package URL specification; OSV

---

## 20. Licence

Zypher is released under the MIT Licence — see [LICENSE](LICENSE).

Bundled third-party components keep their own licences:

| Component | Licence |
|---|---|
| OpenGrep | LGPL-2.1 (`vendor/opengrep/LICENSE`) |
| YARA-X | BSD-3-Clause |
| tree-sitter | MIT |
| FastAPI · React · Tailwind | MIT |
| Inter · JetBrains Mono | SIL Open Font Licence 1.1 |

OpenGrep is invoked as a separate process and is not linked into Zypher, which
is what keeps the LGPL obligation to redistribution of the unmodified binary.

---

<div align="center">

**Smart India Hackathon 2026** · NTRO Problem Statement 26164

</div>
