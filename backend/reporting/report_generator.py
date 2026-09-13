import csv
import io
import json
from datetime import datetime, timezone
from typing import Any, Dict, List

from jinja2 import Template

from backend.cbom.cbom_builder import CBOMBuilder
from backend.models import ScanResult

# How each quantum status reads in a document, kept in step with the UI's
# vocabulary in frontend/src/lib/risk.js.
VULN_LABELS = {
    "fully_broken": "Broken by Shor's algorithm",
    "classically_broken": "Already broken classically",
    "degraded": "Degraded by Grover's algorithm",
    "quantum_safe": "Quantum-safe",
    "hybrid_protected": "Hybrid protected",
    "unknown": "Undetermined — inspect manually",
}

BAND_COLOURS = {
    "Critical": "#c62828",
    "High": "#e65100",
    "Medium": "#a97800",
    "Low": "#1b7a4b",
}

SEVERITY_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

# Advisory severities use their own vocabulary (OSV emits "Moderate", not
# "Medium"), and are ranked separately from the quantum risk bands.
ADVISORY_RANK = {"Critical": 0, "High": 1, "Moderate": 2, "Medium": 2, "Low": 3}


def _worst_advisory(artefact):
    """The most severe published advisory on an artefact, or None."""
    if not artefact.known_vulnerabilities:
        return None
    return sorted(
        artefact.known_vulnerabilities,
        key=lambda v: ADVISORY_RANK.get(v.severity, 9),
    )[0]


class ReportGenerator:
    """
    Generates the three export formats:
      1. CycloneDX 1.6 CBOM (JSON)
      2. An audit report (HTML, print-ready)
      3. A flat inventory (CSV)
    """

    # A print-ready light-theme document. The screen UI is dark; a report that
    # gets filed, emailed and printed should not be. The previous template also
    # rendered every artefact into one unbounded table with no ordering, which
    # for a real scan produced hundreds of pages of near-identical rows.
    HTML_REPORT_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ECDAT Quantum Risk Assessment - {{ scan.summary.target_name }}</title>
<style>
  :root {
    --ink: #14213d; --body: #333; --muted: #6b7280; --line: #e3e6ec;
    --paper: #fff; --tint: #f7f8fa;
    --critical: #c62828; --high: #e65100; --medium: #a97800; --low: #1b7a4b;
  }
  * { box-sizing: border-box; }
  body {
    font-family: "Segoe UI", -apple-system, Roboto, Helvetica, Arial, sans-serif;
    color: var(--body); background: #eef0f4;
    margin: 0; padding: 32px 16px; line-height: 1.55; font-size: 14px;
  }
  .sheet {
    max-width: 1080px; margin: 0 auto; background: var(--paper);
    padding: 44px 52px; box-shadow: 0 1px 3px rgba(0,0,0,.12);
  }
  h1 { font-size: 25px; color: var(--ink); margin: 10px 0 4px; letter-spacing: -.01em; }
  h2 {
    font-size: 15px; color: var(--ink); margin: 34px 0 12px;
    padding-bottom: 6px; border-bottom: 2px solid var(--ink);
    text-transform: uppercase; letter-spacing: .06em;
  }
  h3 { font-size: 13px; color: var(--ink); margin: 20px 0 8px; }
  .eyebrow {
    font-size: 10px; font-weight: 700; letter-spacing: .12em;
    text-transform: uppercase; color: var(--muted);
  }
  .masthead { border-bottom: 3px solid var(--ink); padding-bottom: 18px; }
  .meta { display: flex; flex-wrap: wrap; gap: 26px; margin-top: 12px; font-size: 12px; }
  .meta .k { display:block; color: var(--muted); font-size: 10px; text-transform: uppercase; letter-spacing: .07em; }
  .meta .v { display:block; font-weight: 600; color: var(--ink); }

  .kpis { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-top: 22px; }
  .kpi { border: 1px solid var(--line); padding: 14px 16px; }
  .kpi .n { font-size: 27px; font-weight: 700; color: var(--ink); font-variant-numeric: tabular-nums; }
  .kpi .l { font-size: 10px; text-transform: uppercase; letter-spacing: .07em; color: var(--muted); }

  .bar { display: flex; height: 26px; margin: 8px 0 6px; border: 1px solid var(--line); }
  .bar span { display: flex; align-items: center; justify-content: center; color: #fff; font-size: 11px; font-weight: 700; }
  .legend { display: flex; flex-wrap: wrap; gap: 16px; font-size: 11px; }
  .legend i { display: inline-block; width: 9px; height: 9px; margin-right: 5px; }

  table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 12px; }
  th {
    background: var(--tint); text-align: left; padding: 8px 10px;
    font-size: 10px; text-transform: uppercase; letter-spacing: .06em;
    color: var(--muted); border-bottom: 2px solid var(--line); white-space: nowrap;
  }
  td { padding: 8px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
  td.num { text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }
  .mono { font-family: Consolas, "SF Mono", Menlo, monospace; font-size: 11px; word-break: break-all; }

  .tag { display: inline-block; padding: 1px 7px; border: 1px solid; border-radius: 3px; font-size: 10px; font-weight: 700; white-space: nowrap; }
  .t-Critical { color: var(--critical); border-color: var(--critical); background: #fdeaea; }
  .t-High     { color: var(--high);     border-color: var(--high);     background: #fdf0e4; }
  .t-Medium   { color: var(--medium);   border-color: var(--medium);   background: #fbf5e2; }
  .t-Low      { color: var(--low);      border-color: var(--low);      background: #e8f5ee; }

  .callout { border-left: 3px solid var(--ink); background: var(--tint); padding: 12px 16px; margin: 14px 0; font-size: 13px; }
  .item { border: 1px solid var(--line); padding: 14px 16px; margin-bottom: 12px; page-break-inside: avoid; }
  .item h4 { margin: 0 0 3px; font-size: 13px; color: var(--ink); }
  pre { background: var(--tint); border: 1px solid var(--line); padding: 10px; overflow-x: auto; font-size: 11px; margin: 8px 0 0; white-space: pre-wrap; }
  .foot { margin-top: 38px; padding-top: 14px; border-top: 1px solid var(--line); font-size: 10px; color: var(--muted); }
  .note { font-size: 11px; color: var(--muted); font-style: italic; }

  @media print {
    body { background: #fff; padding: 0; font-size: 11px; }
    .sheet { box-shadow: none; padding: 0; max-width: none; }
    h2 { page-break-after: avoid; }
    tr { page-break-inside: avoid; }
  }
</style>
</head>
<body>
<div class="sheet">

  <header class="masthead">
    <div class="eyebrow">National Technical Research Organisation &middot; Problem Statement 26164</div>
    <h1>Cryptographic Discovery &amp; Quantum Risk Assessment</h1>
    <div class="meta">
      <div><span class="k">Target</span><span class="v">{{ scan.summary.target_name }}</span></div>
      <div><span class="k">Scan ID</span><span class="v mono">{{ scan.summary.scan_id }}</span></div>
      <div><span class="k">Generated</span><span class="v">{{ generated_at }}</span></div>
      <div><span class="k">Quantum horizon (Z)</span><span class="v">{{ scan.summary.mosca_global_z }} years</span></div>
      {% if scan.summary.files_scanned %}
      <div><span class="k">Files read</span><span class="v">{{ scan.summary.files_scanned }}</span></div>
      {% endif %}
    </div>
  </header>

  <h2>Executive summary</h2>
  <div class="kpis">
    <div class="kpi"><div class="n">{{ scan.summary.quantum_readiness_score }}</div><div class="l">Readiness / 100</div></div>
    <div class="kpi"><div class="n">{{ scan.summary.total_artefacts }}</div><div class="l">Distinct assets</div></div>
    <div class="kpi"><div class="n" style="color:var(--critical)">{{ risk_counts.Critical }}</div><div class="l">Critical</div></div>
    <div class="kpi"><div class="n" style="color:var(--high)">{{ risk_counts.High }}</div><div class="l">High</div></div>
  </div>

  <div class="callout">
    <strong>{{ verdict }}</strong><br>{{ narrative }}
  </div>

  <h3>Risk distribution</h3>
  <div class="bar">
    {%- for band in bands -%}
      {%- if band.count -%}
      <span style="width:{{ band.pct }}%;background:{{ band.colour }}">{{ band.count }}</span>
      {%- endif -%}
    {%- endfor -%}
  </div>
  <div class="legend">
    {% for band in bands %}
    <span><i style="background:{{ band.colour }}"></i>{{ band.name }} &mdash; {{ band.count }} ({{ band.pct_label }}%)</span>
    {% endfor %}
  </div>

  {% if scan.summary.coverage_notes %}
  <h3>Scan coverage</h3>
  <ul style="font-size:12px;margin:6px 0 0;padding-left:20px;">
    {% for note in scan.summary.coverage_notes %}<li>{{ note }}</li>{% endfor %}
  </ul>
  {% endif %}

  <h2>Methodology</h2>
  <p style="font-size:12px;">
    Each cryptographic asset is evaluated against <strong>Mosca's inequality</strong>. Where
    <strong>X</strong> is the number of years the protected data must remain confidential and
    <strong>Y</strong> is the time required to migrate to a replacement, an asset is exposed when
    <strong>X + Y &gt; Z</strong>, with <strong>Z = {{ scan.summary.mosca_global_z }} years</strong>
    the estimated arrival of a cryptographically relevant quantum computer. Data encrypted today can
    be captured now and decrypted once that machine exists, so an asset whose combined lifetime
    outlasts the horizon is already exposed.
  </p>
  <p style="font-size:12px;">
    Asymmetric algorithms (RSA, ECC, DSA, Diffie-Hellman) are broken outright by
    <strong>Shor's algorithm</strong>. Symmetric ciphers and hashes are weakened by
    <strong>Grover's algorithm</strong>, which halves effective key strength. Primitives already
    broken by classical cryptanalysis (MD5, SHA-1, DES, 3DES, RC4, RSA &le; 1024, SSL/TLS &lt; 1.2)
    are reported as Critical regardless of the horizon.
  </p>

  <h2>Assets requiring action</h2>
  {% if action_items %}
  <p class="note">{{ action_items|length }} asset(s) rated Critical or High, most severe first.</p>
  <table>
    <thead><tr>
      <th>Asset</th><th>Location</th><th class="num">X</th><th class="num">Y</th>
      <th class="num">X+Y</th><th>Exposed</th><th>Risk</th><th>Migrate to</th>
    </tr></thead>
    <tbody>
    {% for row in action_items %}
      <tr>
        <td><strong>{{ row.name }}</strong><br><span class="note">{{ row.vuln }}</span></td>
        <td class="mono">{{ row.location }}{% if row.occurrences > 1 %} <span class="note">(x{{ row.occurrences }})</span>{% endif %}</td>
        <td class="num">{{ row.x }}y</td>
        <td class="num">{{ row.y }}y</td>
        <td class="num"><strong>{{ row.xy }}y</strong></td>
        <td>{{ "Yes" if row.at_risk else "No" }}</td>
        <td><span class="tag t-{{ row.band }}">{{ row.band }}</span></td>
        <td style="font-size:11px;">{{ row.target }}</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p>No asset is rated Critical or High at a {{ scan.summary.mosca_global_z }}-year horizon.</p>
  {% endif %}

  {% if scan.migration_plan and scan.migration_plan.waves %}
  <h2>Migration schedule</h2>
  <p style="font-size:12px;">
    Assets grouped by when work has to begin. Critical path
    {{ scan.migration_plan.critical_path_years }} years &mdash; even run entirely
    in parallel, the estate cannot be finished sooner than that.
  </p>
  <table>
    <thead>
      <tr><th>Wave</th><th>Assets</th><th>Window</th><th>Longest job</th><th>Status</th></tr>
    </thead>
    <tbody>
      {% for wave in scan.migration_plan.waves %}
      <tr>
        <td>{{ wave.label }}</td>
        <td>{{ wave.asset_count }}</td>
        <td>
          {% if wave.deadline_already_passed %}
            deadline passed {{ wave.must_complete_by }}
          {% else %}
            {{ wave.starts_on }} &rarr; {{ wave.must_complete_by }}
          {% endif %}
        </td>
        <td>{{ wave.longest_migration_years }}y</td>
        <td>
          {% if wave.deadline_already_passed %}
            <strong style="color:#b3261e;">Already non-compliant</strong>
          {% elif wave.is_infeasible %}
            <strong style="color:#9a5b00;">Overruns by {{ wave.shortfall_years }}y</strong>
          {% else %}
            Achievable
          {% endif %}
        </td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% if scan.migration_plan.notes %}
  <ul style="font-size:12px;">
    {% for note in scan.migration_plan.notes %}<li>{{ note }}</li>{% endfor %}
  </ul>
  {% endif %}
  {% endif %}

  {% if migration_groups %}
  <h2>Migration targets</h2>
  {% for group in migration_groups %}
  <div class="item">
    <h4>{{ group.standard }}</h4>
    <div class="note">{{ group.count }} asset(s) &middot; {{ group.urgency }} &middot; {{ group.latency }}</div>
    {% if group.hybrid %}<p style="font-size:12px;margin:8px 0 0;"><strong>Hybrid option:</strong> {{ group.hybrid }}</p>{% endif %}
    {% if group.steps %}
    <ol style="font-size:12px;margin:8px 0 0;padding-left:20px;">
      {% for step in group.steps %}<li>{{ step }}</li>{% endfor %}
    </ol>
    {% endif %}
    {% if group.diff %}<pre>{{ group.diff }}</pre>{% endif %}
  </div>
  {% endfor %}
  {% endif %}

  {% if advisories %}
  <h2>Known vulnerabilities</h2>
  <p style="font-size:12px;">
    Published advisories affecting the dependency versions found in this scan,
    from {{ advisory_source }}. These are <strong>separate from the quantum
    assessment</strong>: a CVE is a defect in a released version, while the risk
    bands above describe exposure to a future quantum adversary. A library can
    carry one without the other.
  </p>
  <table>
    <thead><tr>
      <th>Package</th><th>Advisory</th><th>Severity</th><th>Summary</th><th>Fixed in</th>
    </tr></thead>
    <tbody>
    {% for row in advisories %}
      <tr>
        <td class="mono">{{ row.purl }}{% if row.is_range %} <span class="note">(range)</span>{% endif %}</td>
        <td class="mono">{{ row.id }}{% if row.aliases %}<br><span class="note">{{ row.aliases }}</span>{% endif %}</td>
        <td>{{ row.severity }}</td>
        <td style="font-size:11px;">{{ row.summary }}</td>
        <td>{{ row.fixed_version or "&mdash;" }}</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
  {% elif advisory_note %}
  <h2>Known vulnerabilities</h2>
  <p style="font-size:12px;">{{ advisory_note }}</p>
  {% endif %}

  <h2>Complete inventory</h2>
  <p class="note">All {{ scan.summary.total_artefacts }} distinct cryptographic assets, most severe first.</p>
  <table>
    <thead><tr>
      <th>Asset</th><th>Type</th><th class="num">Key</th><th>Found in</th>
      <th>Location</th><th>Quantum status</th><th>Risk</th>
    </tr></thead>
    <tbody>
    {% for row in inventory %}
      <tr>
        <td>{{ row.name }}</td>
        <td>{{ row.type }}</td>
        <td class="num">{{ row.key or "&mdash;" }}</td>
        <td>{{ row.surface }}</td>
        <td class="mono">{{ row.location }}</td>
        <td style="font-size:11px;">{{ row.vuln }}</td>
        <td>{% if row.band %}<span class="tag t-{{ row.band }}">{{ row.band }}</span>{% endif %}</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>

  <div class="foot">
    Generated by ECDAT {{ version }} &middot; CycloneDX 1.6 Cryptographic Bill of Materials &middot;
    Mosca's inequality &middot; NIST FIPS 203 / 204 / 205.
    Findings are derived from static analysis of the scanned target and should be confirmed against
    the running system before remediation is scheduled.
  </div>

</div>
</body>
</html>"""

    VERSION = "1.1.0"

    # ---------------------------------------------------------------- exports

    @classmethod
    def generate_cyclonedx_json(cls, scan_result: ScanResult) -> str:
        cbom_dict = CBOMBuilder.build_cyclonedx_cbom(
            artefacts=scan_result.artefacts,
            target_name=scan_result.summary.target_name,
            scan_id=scan_result.summary.scan_id,
        )
        return json.dumps(cbom_dict, indent=2)

    @classmethod
    def generate_html_report(cls, scan_result: ScanResult) -> str:
        """
        Render the audit report.

        All shaping happens here rather than in the template, so ordering and
        grouping are testable and the template stays declarative.
        """
        summary = scan_result.summary
        risks = scan_result.risk_assessments
        recs = scan_result.recommendations

        counts = {band: summary.risk_distribution.get(band, 0) for band in SEVERITY_RANK}
        total = max(1, summary.total_artefacts)

        bands = [
            {
                "name": band,
                "count": counts[band],
                "colour": BAND_COLOURS[band],
                "pct": round(counts[band] / total * 100, 2),
                "pct_label": round(counts[band] / total * 100),
            }
            for band in SEVERITY_RANK
        ]

        def location_of(art):
            loc = art.location
            return f"{loc}:{art.line_number}" if art.line_number else loc

        # Severity-ordered so the most important findings lead the document.
        ordered = sorted(
            scan_result.artefacts,
            key=lambda a: (
                SEVERITY_RANK.get(
                    risks[a.id].risk_category.value if a.id in risks else "Low", 9
                ),
                -a.occurrence_count,
                a.name,
            ),
        )

        action_items = []
        for art in ordered:
            risk = risks.get(art.id)
            if not risk or risk.risk_category.value not in ("Critical", "High"):
                continue
            rec = recs.get(art.id)
            action_items.append({
                "name": art.name,
                "vuln": VULN_LABELS.get(art.quantum_vulnerability.value, art.quantum_vulnerability.value),
                "location": location_of(art),
                "occurrences": art.occurrence_count,
                "x": risk.shelf_life_x,
                "y": risk.migration_time_y,
                "xy": risk.x_plus_y,
                "at_risk": risk.is_at_risk,
                "band": risk.risk_category.value,
                "target": rec.recommended_standard if rec else "-",
            })

        inventory = [
            {
                "name": art.name,
                "type": art.type.value.replace("_", " "),
                "key": art.key_size_bits,
                "surface": art.target_type.value.replace("_", " "),
                "location": location_of(art),
                "vuln": VULN_LABELS.get(art.quantum_vulnerability.value, art.quantum_vulnerability.value),
                "band": risks[art.id].risk_category.value if art.id in risks else None,
            }
            for art in ordered
        ]

        # One entry per target standard rather than one near-identical block per
        # artefact, which is what made the old report unreadable at scale.
        groups: Dict[str, Dict[str, Any]] = {}
        for art in ordered:
            rec = recs.get(art.id)
            risk = risks.get(art.id)
            if not rec or not risk:
                continue
            group = groups.setdefault(rec.recommended_standard, {
                "standard": rec.recommended_standard,
                "count": 0,
                "urgency": rec.migration_urgency,
                "latency": rec.latency_impact,
                "hybrid": rec.hybrid_recommendation,
                "steps": rec.migration_steps,
                "diff": rec.code_diff_example,
                "worst": 9,
            })
            group["count"] += 1
            group["worst"] = min(group["worst"], SEVERITY_RANK.get(risk.risk_category.value, 9))

        migration_groups = sorted(groups.values(), key=lambda g: (g["worst"], -g["count"]))

        critical, high = counts["Critical"], counts["High"]
        if critical:
            verdict = f"{critical} asset(s) require immediate remediation."
            narrative = (
                "These are either broken by classical cryptanalysis today, or protect data whose "
                "confidentiality requirement outlasts the estimated arrival of a quantum computer "
                "in a business-critical system."
            )
        elif high:
            verdict = f"{high} asset(s) need migration planning this cycle."
            narrative = (
                "Nothing is critically exposed, but these assets' combined data lifetime and "
                "migration time exceed the quantum horizon."
            )
        else:
            verdict = "No critical or high quantum risk identified at this horizon."
            narrative = (
                f"At Z = {summary.mosca_global_z} years, every catalogued asset either carries an "
                "adequate safety margin or is already quantum-resistant. Re-run this assessment if "
                "the estimated horizon shortens."
            )

        advisories = []
        for art in ordered:
            for vuln in art.known_vulnerabilities:
                advisories.append({
                    "purl": art.purl or art.name,
                    "is_range": art.version_is_range,
                    "id": vuln.id,
                    "aliases": ", ".join(vuln.aliases[:3]),
                    "severity": vuln.severity,
                    "summary": vuln.summary,
                    "fixed_version": vuln.fixed_version,
                })
        advisories.sort(key=lambda r: ADVISORY_RANK.get(r["severity"], 9))

        # A report must distinguish "checked and clean" from "never checked".
        record = summary.vulnerability_lookup or {}
        advisory_source = record.get("source", "OSV")
        advisory_note = None
        if not advisories:
            if not record.get("enabled"):
                advisory_note = (
                    "Dependency advisories were not checked. The lookup requires "
                    "network access and is disabled by default."
                )
            elif not record.get("available"):
                advisory_note = (
                    f"The advisory lookup could not run: {record.get('error')}"
                )
            elif record.get("packages_checked"):
                advisory_note = (
                    f"{record['packages_checked']} package(s) were checked against "
                    f"{advisory_source} and no published advisories were found."
                )

        created = summary.created_at
        if isinstance(created, str):
            generated_at = created
        else:
            generated_at = created.strftime("%d %B %Y, %H:%M UTC")

        return Template(cls.HTML_REPORT_TEMPLATE).render(
            scan=scan_result,
            risk_counts=counts,
            bands=bands,
            action_items=action_items,
            inventory=inventory,
            migration_groups=migration_groups,
            advisories=advisories,
            advisory_source=advisory_source,
            advisory_note=advisory_note,
            verdict=verdict,
            narrative=narrative,
            generated_at=generated_at,
            version=cls.VERSION,
        )

    @classmethod
    def generate_csv_report(cls, scan_result: ScanResult) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Artefact ID", "Name", "Type", "Algorithm Family", "Algorithm Class",
            "Key Size (bits)", "Curve", "Mode/Padding", "Discovery Surface",
            "Location", "Line Number", "Occurrences", "Quantum Status", "Broken By",
            "Business Criticality",
            # Crypto agility (NIST CSWP 39): how replaceable this asset is,
            # independently of which algorithm it currently uses.
            "Agility Score", "Agility Band", "Agility Constraint",
            "Certificate Validity (yrs)",
            "Shelf Life X (yrs)", "Migration Time Y (yrs)",
            "Mosca Z Horizon (yrs)", "X+Y (yrs)", "Safety Margin (yrs)",
            "At Risk (X+Y > Z)", "Risk Category",
            # The schedule. A band says how bad an asset is; these say when it
            # has to be dealt with, which is what a migration plan is built on.
            "Crypto Usage", "Binding Model", "Must Start By", "Must Complete By",
            "Slack (yrs)", "Overdue", "HNDL Exposure (yrs)",
            "P(CRQC) Low", "P(CRQC) High",
            "Recommended PQC Standard", "NIST Category",
            "Replaces Classical Bits", "Selection Rationale",
            "Hybrid Recommendation", "Migration Urgency",
            "Package URL", "Version Is Range", "Known Vulnerabilities",
            "Worst Advisory", "Worst Advisory Severity", "Fixed In",
        ])

        # Same severity ordering as the HTML report, so the two agree.
        ordered = sorted(
            scan_result.artefacts,
            key=lambda a: (
                SEVERITY_RANK.get(
                    scan_result.risk_assessments[a.id].risk_category.value
                    if a.id in scan_result.risk_assessments else "Low",
                    9,
                ),
                -a.occurrence_count,
                a.name,
            ),
        )

        for art in ordered:
            risk = scan_result.risk_assessments.get(art.id)
            rec = scan_result.recommendations.get(art.id)
            writer.writerow([
                art.id,
                art.name,
                art.type.value,
                art.algorithm_family,
                art.algorithm_class.value,
                art.key_size_bits or "",
                art.curve or "",
                art.mode_or_padding or "",
                art.target_type.value,
                art.location,
                art.line_number or "",
                art.occurrence_count,
                VULN_LABELS.get(art.quantum_vulnerability.value, art.quantum_vulnerability.value),
                art.broken_by or "",
                art.business_criticality.value,
                art.agility_score if art.agility_score is not None else "",
                art.agility_band or "",
                art.agility_summary or "",
                art.measured_validity_years
                if art.measured_validity_years is not None else "",
                risk.shelf_life_x if risk else "",
                risk.migration_time_y if risk else "",
                risk.threat_timeline_z if risk else "",
                risk.x_plus_y if risk else "",
                risk.safety_margin_years if risk else "",
                ("YES" if risk.is_at_risk else "NO") if risk else "",
                risk.risk_category.value if risk else "",
                risk.crypto_usage.value if risk else "",
                (risk.binding_model.value if risk.binding_model else "") if risk else "",
                (risk.must_start_by.isoformat() if risk.must_start_by else "") if risk else "",
                (risk.must_complete_by.isoformat() if risk.must_complete_by else "") if risk else "",
                (risk.slack_years if risk.slack_years is not None else "") if risk else "",
                ("YES" if risk.is_overdue else "NO") if risk else "",
                risk.hndl_exposure_years if risk else "",
                (risk.breach_probability_low if risk.breach_probability_low is not None else "") if risk else "",
                (risk.breach_probability_high if risk.breach_probability_high is not None else "") if risk else "",
                rec.recommended_standard if rec else "",
                (rec.nist_category if rec.nist_category is not None else "") if rec else "",
                (rec.replaces_classical_bits if rec.replaces_classical_bits is not None else "") if rec else "",
                (rec.selection_rationale or "") if rec else "",
                rec.hybrid_recommendation if rec else "",
                rec.migration_urgency if rec else "",
                art.purl or "",
                "YES" if art.version_is_range else "",
                len(art.known_vulnerabilities) or "",
                worst.id if (worst := _worst_advisory(art)) else "",
                worst.severity if worst else "",
                worst.fixed_version if worst and worst.fixed_version else "",
            ])

        return output.getvalue()
