# OpenGrep — bundled third-party component

Zypher bundles the OpenGrep binary to provide **Tier 4 dataflow analysis**: the
ability to follow a cryptographic parameter across function boundaries so that a
key size or algorithm name written at one place in a file is attributed to the
call that consumes it.

| | |
|---|---|
| Component | `opengrep.exe` (Windows x86-64) |
| Version | 1.30.0 |
| Upstream | https://github.com/opengrep/opengrep |
| Release | https://github.com/opengrep/opengrep/releases/tag/v1.30.0 |
| Licence | GNU Lesser General Public License v2.1 (see `LICENSE`) |
| SHA-256 | `b5cf4f8fe9f44e030aab2d579d96bd395c139db1f1ba66633676ff4d5ebc7c39` |

## Why this component

OpenGrep is the community fork of Semgrep CE, maintained under LGPL-2.1 after
the upstream project moved interprocedural taint analysis behind a commercial
licence and relicensed its rule corpus under non-open terms. The fork restores
cross-function taint analysis and native Windows support.

It was chosen over the alternatives for reasons that are specific to this
project's constraints:

* **No runtime dependency.** A single self-contained executable. No JVM, no
  Node, no Python, no background server. CodeQL, SonarQube, IBM's `cbomkit-lib`
  and Joern all require at least one of those.
* **Offline.** The binary contains no network endpoints and no telemetry. Zypher
  is an air-gapped tool and must remain one.
* **Licence.** LGPL-2.1 permits redistribution. The CodeQL CLI terms restrict
  automated analysis to open-source codebases, which excludes the closed-source
  estate Zypher is built to inventory.

## LGPL-2.1 compliance

The binary is redistributed **unmodified** and is invoked as a separate process
over a documented command-line interface. Zypher does not link against it and
contains no OpenGrep code.

The complete corresponding source for this version is published by the upstream
project at the release URL above. No patches have been applied.

Rule files under `backend/scanners/rules/` are Zypher's own work and are not
derived from the Semgrep or OpenGrep rule corpora, both of which carry licences
that forbid redistribution in a product.
