"""
PRAMAANX - Forensic PDF Report Generator (Milestone E)
======================================================
Compiles professional, court-grade, immutable PDF examination reports
from persistent SQLite case dossiers, evidence registries, and analysis snapshots.

Features:
1. Executive Summary Report: Concise, plain-English overview for stakeholders.
2. Detailed Forensic Report: Complete technical evidence, byte offsets, object IDs,
   taxonomies, artifact plates, and full audit logs.
3. Export Integrity: Recalculates SHA-256 fingerprint of the output PDF and saves
   metadata to the database.
4. Immutability: Marks generated PDFs as read-only (chmod 0o444) to guarantee
   historical consistency.
5. Path Traversal & Injection Defense: HTML-escapes all untrusted text and strictly
   confines output to REPORTS_DIR.
"""

from datetime import datetime, timezone
import hashlib
import html
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pymupdf

from backend.config import REPORTS_DIR, VAULT_DIR
from backend.database import (
    generate_report_id,
    get_audit_logs,
    get_investigation,
    list_analysis_records,
    list_evidence_items,
    save_report_record,
)


def _escape(val: Any) -> str:
    """Safely escapes text for inclusion in PDF HTML/XML flowables."""
    if val is None:
        return ""
    return html.escape(str(val))


def _format_bytes(size: int) -> str:
    """Formats byte counts into human-readable strings."""
    if size < 1024:
        return f"{size} B"
    elif size < 1024 * 1024:
        return f"{size / 1024:.2f} KB"
    elif size < 1024 * 1024 * 1024:
        return f"{size / (1024 * 1024):.2f} MB"
    else:
        return f"{size / (1024 * 1024 * 1024):.2f} GB"


def _format_date(iso_str: Optional[str]) -> str:
    """Formats ISO timestamps to standard UTC forensic notation."""
    if not iso_str:
        return "—"
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(iso_str)


def _get_severity_badge_html(severity: str) -> str:
    """Returns styled HTML badge for finding severity."""
    s = str(severity or "").lower()
    if s == "high":
        return '<span style="background-color: #FEE2E2; color: #B91C1C; padding: 2px 6px; border-radius: 4px; font-weight: bold; font-size: 8pt; border: 1px solid #FECACA;">HIGH SEVERITY</span>'
    elif s == "medium":
        return '<span style="background-color: #FEF3C7; color: #B45309; padding: 2px 6px; border-radius: 4px; font-weight: bold; font-size: 8pt; border: 1px solid #FDE68A;">MEDIUM SEVERITY</span>'
    else:
        return '<span style="background-color: #DCFCE7; color: #15803D; padding: 2px 6px; border-radius: 4px; font-weight: bold; font-size: 8pt; border: 1px solid #BBF7D0;">LOW SEVERITY</span>'


def _get_taxonomy_label(category: Optional[str], finding: Dict[str, Any]) -> str:
    """Categorizes finding into one of the 5 forensic taxonomies."""
    cat = str(category or finding.get("type", "")).lower()
    name = str(finding.get("name", "")).lower()
    desc = str(finding.get("description", "")).lower()

    if "structural" in cat or "eof" in name or "zip slip" in name or "embedded" in name or "cloaked" in name:
        return "Confirmed Structural Observation"
    if "statistical" in cat or "entropy" in name or "anomaly" in name:
        return "Statistical Anomaly"
    if "ml" in cat or "model" in name or "efficientnet" in name or "neural" in name or "tamper probability" in name:
        return "Machine-Learning Prediction"
    if "inconclusive" in cat or "unsupported" in name or "skipped" in name:
        return "Inconclusive Result"
    return "Heuristic Indicator"


# Common CSS styling for ReportLab / PyMuPDF Story
REPORT_CSS = """
<style>
  body {
    font-family: Helvetica, Arial, sans-serif;
    color: #0F172A;
    font-size: 9.5pt;
    line-height: 1.45;
  }
  h1 {
    font-size: 19pt;
    color: #0F172A;
    margin-top: 0;
    margin-bottom: 4px;
    font-weight: bold;
    letter-spacing: -0.5px;
  }
  h2 {
    font-size: 13pt;
    color: #0F172A;
    margin-top: 14px;
    margin-bottom: 6px;
    border-bottom: 1.5px solid #2563EB;
    padding-bottom: 3px;
    font-weight: bold;
  }
  h3 {
    font-size: 10.5pt;
    color: #1E293B;
    margin-top: 10px;
    margin-bottom: 4px;
    font-weight: bold;
  }
  p {
    margin-top: 3px;
    margin-bottom: 6px;
    color: #334155;
  }
  .lead {
    font-size: 10pt;
    color: #475569;
    margin-bottom: 12px;
  }
  .card {
    background-color: #F8FAFC;
    border: 1px solid #E2E8F0;
    border-radius: 6px;
    padding: 8px 10px;
    margin-bottom: 10px;
  }
  .card-danger {
    background-color: #FEF2F2;
    border: 1px solid #FECACA;
    border-radius: 6px;
    padding: 8px 10px;
    margin-bottom: 10px;
  }
  .card-warning {
    background-color: #FFFBEB;
    border: 1px solid #FDE68A;
    border-radius: 6px;
    padding: 8px 10px;
    margin-bottom: 10px;
  }
  .card-success {
    background-color: #F0FDF4;
    border: 1px solid #BBF7D0;
    border-radius: 6px;
    padding: 8px 10px;
    margin-bottom: 10px;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 6px;
    margin-bottom: 10px;
    font-size: 8.5pt;
  }
  th {
    background-color: #F1F5F9;
    color: #475569;
    border: 1px solid #CBD5E1;
    padding: 5px 6px;
    text-align: left;
    font-weight: bold;
    font-size: 7.5pt;
    text-transform: uppercase;
  }
  td {
    border: 1px solid #E2E8F0;
    padding: 5px 6px;
    vertical-align: top;
    color: #1E293B;
  }
  .mono {
    font-family: Courier, monospace;
    font-size: 8pt;
  }
  .badge-tag {
    display: inline-block;
    background-color: #F1F5F9;
    border: 1px solid #CBD5E1;
    border-radius: 3px;
    padding: 1px 4px;
    font-size: 7.5pt;
    font-family: Courier, monospace;
    margin-right: 4px;
  }
  .disclaimer {
    font-size: 7.5pt;
    color: #64748B;
    border-top: 1px solid #E2E8F0;
    padding-top: 6px;
    margin-top: 14px;
    line-height: 1.35;
  }
</style>
"""


def _build_html_executive_summary_report(
    case: Dict[str, Any],
    evidence_list: List[Dict[str, Any]],
    examination_records: List[Dict[str, Any]],
    report_id: str,
    generated_by: str,
) -> str:
    """Builds the HTML string for the Executive Summary Report."""
    now_str = _format_date(datetime.now(timezone.utc).isoformat())

    # Aggregate metrics
    total_evidence = len(evidence_list)
    tampered_count = sum(1 for e in evidence_list if e.get("integrity_status") == "tampered")
    verified_count = sum(1 for e in evidence_list if e.get("integrity_status") == "verified")

    # Find highest risk score among recent examination records
    max_risk = 0
    high_findings: List[Dict[str, Any]] = []
    for r in examination_records:
        score = r.get("risk_score", 0)
        if score > max_risk:
            max_risk = score
        for f in r.get("findings", []):
            if str(f.get("severity", "")).lower() == "high":
                high_findings.append(f)

    risk_label = "HIGH RISK" if max_risk >= 61 else "MEDIUM RISK" if max_risk >= 31 else "LOW RISK"
    risk_color = "#B91C1C" if max_risk >= 61 else "#B45309" if max_risk >= 31 else "#15803D"
    risk_card_class = "card-danger" if max_risk >= 61 else "card-warning" if max_risk >= 31 else "card-success"

    html_out = f"""
    {REPORT_CSS}
    <div style="border-bottom: 2px solid #2563EB; padding-bottom: 8px; margin-bottom: 12px;">
      <table style="border: none; margin: 0; padding: 0;">
        <tr style="border: none;">
          <td style="border: none; padding: 0;">
            <div style="font-size: 8pt; font-weight: bold; color: #2563EB; letter-spacing: 1px; text-transform: uppercase;">
              PRAMAANX DIGITAL DOCUMENT & IMAGE FORENSICS
            </div>
            <h1>Executive Forensic Summary</h1>
            <div class="lead">Concise Case Risk Assessment & Management Brief</div>
          </td>
          <td style="border: none; text-align: right; vertical-align: top; padding: 0;">
            <div style="font-size: 8pt; color: #64748B;">Report Identifier</div>
            <div style="font-size: 13pt; font-weight: bold; font-family: Courier, monospace; color: #0F172A;">{_escape(report_id)}</div>
            <div style="font-size: 8pt; color: #64748B; margin-top: 2px;">Generated: {now_str}</div>
          </td>
        </tr>
      </table>
    </div>

    <!-- Case Metadata Bar -->
    <div class="card">
      <table style="border: none; margin: 0; font-size: 8.5pt;">
        <tr style="border: none;">
          <td style="border: none; padding: 2px 4px;"><strong>Case ID:</strong> <span class="mono">{_escape(case.get("id"))}</span></td>
          <td style="border: none; padding: 2px 4px;"><strong>Case Title:</strong> {_escape(case.get("title"))}</td>
          <td style="border: none; padding: 2px 4px;"><strong>Lead Examiner:</strong> {_escape(case.get("investigator") or generated_by)}</td>
          <td style="border: none; padding: 2px 4px;"><strong>Status:</strong> <span style="text-transform: uppercase; font-weight: bold;">{_escape(case.get("status"))}</span></td>
        </tr>
      </table>
    </div>

    <!-- Executive Verdict & Overall Risk Assessment -->
    <h2>1. Executive Assessment & Risk Verdict</h2>
    <div class="{risk_card_class}">
      <table style="border: none; margin: 0;">
        <tr style="border: none;">
          <td style="border: none; width: 140px; text-align: center; vertical-align: middle;">
            <div style="font-size: 28pt; font-weight: bold; color: {risk_color};">{max_risk}<span style="font-size: 12pt; color: #64748B;">/100</span></div>
            <div style="font-size: 9pt; font-weight: bold; color: {risk_color};">{risk_label}</div>
          </td>
          <td style="border: none; padding-left: 12px; vertical-align: middle;">
            <p style="margin: 0; font-weight: bold; color: #0F172A;">
              {f"Critical forensic anomalies identified across {tampered_count} evidence item(s)." if tampered_count > 0 or max_risk >= 61 else "Evidence inspection completed with nominal baseline integrity verified."}
            </p>
            <p style="margin-top: 4px; font-size: 8.5pt; color: #475569;">
              {_escape(case.get("description")) if case.get("description") else "Digital forensic examination conducted across submitted evidence items using multi-engine structural, heuristic, and neural screening algorithms."}
            </p>
          </td>
        </tr>
      </table>
    </div>

    <!-- Scope & Evidence Overview -->
    <h2>2. Submitted Evidence Inventory</h2>
    <p>A total of <strong>{total_evidence}</strong> digital evidence item(s) were submitted and ingested into the vault:</p>
    <table>
      <thead>
        <tr>
          <th>Evidence Filename</th>
          <th>Format</th>
          <th>Size</th>
          <th>Baseline SHA-256 Digest</th>
          <th>Vault Integrity</th>
        </tr>
      </thead>
      <tbody>
    """

    for ev in evidence_list:
        status = ev.get("integrity_status", "verified")
        status_color = "#15803D" if status == "verified" else "#B91C1C" if status == "tampered" else "#64748B"
        fname = ev.get("original_filename") or ev.get("filename") or "evidence"
        fsize = ev.get("file_size_bytes") if ev.get("file_size_bytes") is not None else ev.get("file_size", 0)
        ffmt = ev.get("detected_ext") or ev.get("file_format") or "file"
        fsha = ev.get("sha256") or ev.get("sha256_hash") or "—"
        html_out += f"""
        <tr>
          <td><strong>{_escape(fname)}</strong></td>
          <td style="text-transform: uppercase;">{_escape(ffmt)}</td>
          <td>{_format_bytes(fsize)}</td>
          <td class="mono">{_escape(fsha)}</td>
          <td style="color: {status_color}; font-weight: bold; text-transform: uppercase;">{_escape(status)}</td>
        </tr>
        """

    html_out += f"""
      </tbody>
    </table>

    <!-- High-Severity Forensic Indicators -->
    <h2>3. Key Forensic Indicators & Findings</h2>
    """

    if not high_findings:
        html_out += """
        <div class="card-success">
          <p style="margin: 0; color: #15803D; font-weight: bold;">Zero High-Severity Malicious Indicators Detected</p>
          <p style="margin-top: 2px; font-size: 8.5pt; color: #475569;">
            All scanned evidence items fall within expected structural and compression tolerances. No active exploits, cloaked macros, or incremental revision tampering were detected.
          </p>
        </div>
        """
    else:
        html_out += f"""
        <p>The forensic screening pipeline detected <strong>{len(high_findings)}</strong> high-severity forensic indicator(s):</p>
        <table>
          <thead>
            <tr>
              <th style="width: 130px;">Finding</th>
              <th style="width: 90px;">Severity</th>
              <th>Description & Forensic Impact</th>
              <th style="width: 140px;">Traceability</th>
            </tr>
          </thead>
          <tbody>
        """
        for hf in high_findings[:8]:
            trace = []
            if hf.get("offset"):
                trace.append(f"Offset: {_escape(hf['offset'])}")
            if hf.get("object_id"):
                trace.append(f"Obj: {_escape(hf['object_id'])}")
            if hf.get("container_path"):
                trace.append(f"Path: {_escape(hf['container_path'])}")
            trace_str = "<br/>".join(trace) if trace else "Document-level"

            html_out += f"""
            <tr>
              <td><strong>{_escape(hf.get("name"))}</strong></td>
              <td>{_get_severity_badge_html(hf.get("severity", "high"))}</td>
              <td>
                <div>{_escape(hf.get("description"))}</div>
                {f'<div style="color: #64748B; font-size: 8pt; margin-top: 2px;"><em>Impact: {_escape(hf.get("why_it_matters"))}</em></div>' if hf.get("why_it_matters") else ''}
              </td>
              <td class="mono" style="font-size: 7.5pt;">{trace_str}</td>
            </tr>
            """
        html_out += """
          </tbody>
        </table>
        """

    # Recommendations & Next Steps
    html_out += f"""
    <h2>4. Executive Recommendations</h2>
    <div class="card">
      <ul style="margin: 0; padding-left: 18px; font-size: 8.5pt; color: #1E293B;">
        <li><strong>Quarantine Flagged Documents:</strong> Isolate any evidence with risk score exceeding 60 from production networks and employee workstations.</li>
        <li><strong>Chain-of-Custody Preservation:</strong> Ensure raw disk images or email headers matching the SHA-256 baselines above are preserved in tamper-evident storage.</li>
        <li><strong>Detailed Examination:</strong> For legal or formal proceedings, review the full Detailed Forensic Examination Report (ID: {_escape(report_id)}).</li>
      </ul>
    </div>

    <!-- Forensic Disclaimer -->
    <div class="disclaimer">
      <strong>SCIENTIFIC LIMITATIONS & DISCLAIMER:</strong> This executive summary is generated by automated algorithmic screening engines (PRAMAANX).
      Risk scoring uses a calibrated probabilistic Noisy-OR formulation. Machine learning tamper probability is indicative and should be corroborated with manual bitstream analysis before legal submission.
    </div>
    """
    return html_out


def _build_html_detailed_forensic_report(
    case: Dict[str, Any],
    evidence_list: List[Dict[str, Any]],
    examination_records: List[Dict[str, Any]],
    audit_logs: List[Dict[str, Any]],
    report_id: str,
    generated_by: str,
) -> str:
    """Builds the comprehensive HTML string for the Detailed Forensic Examination Report."""
    now_str = _format_date(datetime.now(timezone.utc).isoformat())

    # Collect all findings across examination records with evidence associations
    all_findings_by_taxonomy: Dict[str, List[Tuple[Dict[str, Any], str]]] = {
        "Confirmed Structural Observation": [],
        "Statistical Anomaly": [],
        "Heuristic Indicator": [],
        "Machine-Learning Prediction": [],
        "Inconclusive Result": [],
    }

    # Map evidence_id -> filename
    ev_map = {e.get("id"): (e.get("original_filename") or e.get("filename") or "evidence") for e in evidence_list}

    for r in examination_records:
        ev_id = r.get("evidence_id")
        fname = ev_map.get(ev_id, "evidence")
        for f in r.get("findings", []):
            tax = _get_taxonomy_label(f.get("category"), f)
            if tax in all_findings_by_taxonomy:
                all_findings_by_taxonomy[tax].append((f, fname))

    # Calculate overall risk
    max_risk = max([r.get("risk_score", 0) for r in examination_records], default=0)
    risk_label = "HIGH RISK" if max_risk >= 61 else "MEDIUM RISK" if max_risk >= 31 else "LOW RISK"

    html_out = f"""
    {REPORT_CSS}
    <div style="border-bottom: 2.5px solid #2563EB; padding-bottom: 8px; margin-bottom: 12px;">
      <table style="border: none; margin: 0; padding: 0;">
        <tr style="border: none;">
          <td style="border: none; padding: 0;">
            <div style="font-size: 8pt; font-weight: bold; color: #2563EB; letter-spacing: 1px; text-transform: uppercase;">
              PRAMAANX FORENSIC EXAMINATION DOSSIER
            </div>
            <h1>Comprehensive Forensic Report</h1>
            <div class="lead">Complete Bitstream Dissection, Structural Anomalies & Evidence Verification</div>
          </td>
          <td style="border: none; text-align: right; vertical-align: top; padding: 0;">
            <div style="font-size: 8pt; color: #64748B;">Report Identifier</div>
            <div style="font-size: 14pt; font-weight: bold; font-family: Courier, monospace; color: #0F172A;">{_escape(report_id)}</div>
            <div style="font-size: 8pt; color: #64748B; margin-top: 2px;">Executed: {now_str}</div>
          </td>
        </tr>
      </table>
    </div>

    <!-- Section 1: Case Identification & Scope -->
    <h2>1. Case Identification & Investigation Scope</h2>
    <div class="card">
      <table style="border: none; margin: 0; font-size: 8.5pt;">
        <tr style="border: none;">
          <td style="border: none; width: 50%; padding: 3px 4px;"><strong>Case Reference:</strong> <span class="mono">{_escape(case.get("id"))}</span></td>
          <td style="border: none; width: 50%; padding: 3px 4px;"><strong>Case Status:</strong> <span style="text-transform: uppercase; font-weight: bold;">{_escape(case.get("status"))}</span></td>
        </tr>
        <tr style="border: none;">
          <td style="border: none; padding: 3px 4px;"><strong>Investigation Title:</strong> {_escape(case.get("title"))}</td>
          <td style="border: none; padding: 3px 4px;"><strong>Lead Investigator:</strong> {_escape(case.get("investigator") or generated_by)}</td>
        </tr>
        <tr style="border: none;">
          <td style="border: none; padding: 3px 4px;"><strong>Case Opened At:</strong> {_format_date(case.get("created_at"))}</td>
          <td style="border: none; padding: 3px 4px;"><strong>Report Compiled By:</strong> {_escape(generated_by)}</td>
        </tr>
      </table>
      {f'<p style="margin-top: 6px; font-size: 8.5pt; color: #475569; border-top: 1px solid #E2E8F0; padding-top: 4px;"><strong>Investigation Objective:</strong> {_escape(case.get("description"))}</p>' if case.get("description") else ''}
    </div>

    <!-- Section 2: Evidence Inventory & Hash Integrity -->
    <h2>2. Digital Evidence Inventory & Integrity Verification</h2>
    <p>All items acquired into the read-only evidence vault with baseline cryptographic digests:</p>
    <table>
      <thead>
        <tr>
          <th>Evidence Filename</th>
          <th>Size</th>
          <th>Format / MIME</th>
          <th>Baseline SHA-256 Digest</th>
          <th>Acquired Timestamp</th>
          <th>Integrity Status</th>
        </tr>
      </thead>
      <tbody>
    """

    for ev in evidence_list:
        status = ev.get("integrity_status", "verified")
        status_color = "#15803D" if status == "verified" else "#B91C1C" if status == "tampered" else "#64748B"
        fname = ev.get("original_filename") or ev.get("filename") or "evidence"
        fsize = ev.get("file_size_bytes") if ev.get("file_size_bytes") is not None else ev.get("file_size", 0)
        ffmt = ev.get("detected_ext") or ev.get("file_format") or "file"
        fmime = ev.get("detected_mime") or ev.get("mime_type") or "application/octet-stream"
        fsha = ev.get("sha256") or ev.get("sha256_hash") or "—"
        html_out += f"""
        <tr>
          <td><strong>{_escape(fname)}</strong></td>
          <td>{_format_bytes(fsize)}</td>
          <td><span style="text-transform: uppercase;">{_escape(ffmt)}</span><br/><span style="font-size: 7.5pt; color: #64748B;">{_escape(fmime)}</span></td>
          <td class="mono">{_escape(fsha)}</td>
          <td class="mono" style="font-size: 7.5pt;">{_format_date(ev.get("acquired_at"))}</td>
          <td style="color: {status_color}; font-weight: bold; text-transform: uppercase;">{_escape(status)}</td>
        </tr>
        """

    html_out += """
      </tbody>
    </table>

    <!-- Section 3: Scientific Methodology & Risk Formulation -->
    <h2>3. Scientific Examination Methodology</h2>
    <div class="card">
      <p style="margin: 0; font-size: 8.5pt; color: #334155;">
        Inspection was conducted across multi-layer parsing engines:
      </p>
      <ul style="margin: 4px 0 0 0; padding-left: 18px; font-size: 8pt; color: #475569;">
        <li><strong>Structural Bitstream Inspection:</strong> Parsing trailer cross-reference tables (PDF %%EOF revisions), OpenXML OPC relationship graphs, and PKWare ZIP headers to identify cloaked structures, path traversal (Zip Slip), and hidden streams.</li>
        <li><strong>Information Entropy:</strong> Evaluating sliding-window Shannon entropy (8.00-bit scale) to detect packed binaries, encrypted shellcode, and anomalous stream density.</li>
        <li><strong>Neural Tampering & Localization:</strong> CASIA 2.0-trained EfficientNet-B0 evaluating spatial splice patterns combined with Error Level Analysis (ELA) compression variance.</li>
        <li><strong>Probabilistic Risk Compounding:</strong> Calibrated Noisy-OR formulation combining discrete detection weights: <em>P(Risk) = 1 - &prod; (1 - w_i)</em>, de-duplicating correlated findings without probability inflation.</li>
      </ul>
    </div>

    <!-- Section 4: Detailed Findings by Forensic Taxonomy -->
    <h2>4. Detailed Technical Findings & Traceability</h2>
    """

    total_findings_count = sum(len(flist) for flist in all_findings_by_taxonomy.values())
    if total_findings_count == 0:
        html_out += """
        <div class="card-success">
          <p style="margin: 0; color: #15803D; font-weight: bold;">Zero Anomalies Detected Across All Examined Evidence</p>
          <p style="margin-top: 2px; font-size: 8.5pt; color: #475569;">
            All structural elements, magic signatures, entropy levels, and revision records align with authentic specifications.
          </p>
        </div>
        """
    else:
        for taxonomy_title, findings_list in all_findings_by_taxonomy.items():
            if not findings_list:
                continue

            html_out += f"""
            <h3>{taxonomy_title} ({len(findings_list)})</h3>
            <table>
              <thead>
                <tr>
                  <th style="width: 140px;">Finding & Evidence File</th>
                  <th style="width: 80px;">Severity</th>
                  <th>Observed Technical Detail</th>
                  <th style="width: 140px;">Traceability & Offsets</th>
                </tr>
              </thead>
              <tbody>
            """

            for f, fname in findings_list:
                trace_badges = []
                if f.get("offset"):
                    trace_badges.append(f'<span class="badge-tag">Offset: {_escape(f["offset"])}</span>')
                if f.get("object_id"):
                    trace_badges.append(f'<span class="badge-tag">Object: {_escape(f["object_id"])}</span>')
                if f.get("container_path"):
                    trace_badges.append(f'<span class="badge-tag">Path: {_escape(f["container_path"])}</span>')
                if f.get("metadata_key"):
                    trace_badges.append(f'<span class="badge-tag">Key: {_escape(f["metadata_key"])}</span>')
                if f.get("model_confidence") is not None:
                    trace_badges.append(f'<span class="badge-tag">Prob: {f["model_confidence"]:.2f}</span>')

                trace_html = "<br/>".join(trace_badges) if trace_badges else '<span style="color: #94A3B8; font-size: 7.5pt;">Document-Level</span>'

                html_out += f"""
                <tr>
                  <td>
                    <strong>{_escape(f.get("name"))}</strong><br/>
                    <span style="font-size: 7.5pt; color: #2563EB;">{_escape(fname)}</span>
                  </td>
                  <td>{_get_severity_badge_html(f.get("severity", "medium"))}</td>
                  <td>
                    <div>{_escape(f.get("description"))}</div>
                    {f'<div style="color: #475569; font-size: 8pt; margin-top: 2px;"><strong>Impact:</strong> {_escape(f.get("why_it_matters"))}</div>' if f.get("why_it_matters") else ''}
                    {f'<div style="color: #64748B; font-size: 7.5pt; margin-top: 2px;"><em>Recommendation:</em> {_escape(f.get("recommended_action"))}</div>' if f.get("recommended_action") else ''}
                  </td>
                  <td>{trace_html}</td>
                </tr>
                """

            html_out += """
              </tbody>
            </table>
            """

    # Section 5: Computer Vision & Generated Artifact References
    html_out += """
    <h2>5. Generated Forensic Artifacts & Visual Evidence</h2>
    <div class="card">
      <table style="border: none; margin: 0; font-size: 8pt;">
        <thead>
          <tr style="background: none;">
            <th style="background: none; border: none; padding: 2px 4px;">Artifact Type</th>
            <th style="background: none; border: none; padding: 2px 4px;">Target Evidence</th>
            <th style="background: none; border: none; padding: 2px 4px;">Vault Storage Reference</th>
            <th style="background: none; border: none; padding: 2px 4px;">Methodology</th>
          </tr>
        </thead>
        <tbody>
    """

    has_artifacts = False
    for r in examination_records:
        vis = r.get("visual_evidence", {})
        if vis and isinstance(vis, dict):
            for art_name, art_path in vis.items():
                has_artifacts = True
                html_out += f"""
                <tr style="border-top: 1px solid #E2E8F0;">
                  <td style="border: none; padding: 3px 4px;"><strong>{_escape(art_name.upper())}</strong></td>
                  <td style="border: none; padding: 3px 4px;">{_escape(ev_map.get(r.get("evidence_id"), "image"))}</td>
                  <td style="border: none; padding: 3px 4px;" class="mono">{_escape(os.path.basename(str(art_path)))}</td>
                  <td style="border: none; padding: 3px 4px;">Grad-CAM / ELA Saliency Layer</td>
                </tr>
                """

    if not has_artifacts:
        html_out += """
        <tr style="border-top: 1px solid #E2E8F0;">
          <td colspan="4" style="border: none; padding: 6px 4px; color: #64748B;">
            No visual computer vision artifacts generated for this examination (text documents or clean non-tampered images).
          </td>
        </tr>
        """

    html_out += """
        </tbody>
      </table>
    </div>

    <!-- Section 6: Auditable Activity Trail -->
    <h2>6. Chain of Custody & Examination Audit Trail</h2>
    <p>Chronological record of forensic events logged in the immutable audit registry:</p>
    <table>
      <thead>
        <tr>
          <th style="width: 130px;">Event Timestamp</th>
          <th style="width: 140px;">Action</th>
          <th style="width: 100px;">Examiner / Actor</th>
          <th>Action Details</th>
        </tr>
      </thead>
      <tbody>
    """

    for log in audit_logs[:15]:
        details_str = json.dumps(log.get("details", {})) if isinstance(log.get("details"), dict) else str(log.get("details", ""))
        html_out += f"""
        <tr>
          <td class="mono" style="font-size: 7.5pt;">{_format_date(log.get("timestamp"))}</td>
          <td style="font-weight: bold; text-transform: uppercase; font-size: 8pt;">{_escape(str(log.get("action", "")).replace("_", " "))}</td>
          <td>{_escape(log.get("actor", "Analyst"))}</td>
          <td class="mono" style="font-size: 7.5pt;">{_escape(details_str)}</td>
        </tr>
        """

    html_out += f"""
      </tbody>
    </table>

    <!-- Section 7: Conclusion & Remediation Action Plan -->
    <h2>7. Technical Conclusion & Remediation Plan</h2>
    <div class="card">
      <p style="margin: 0; font-size: 8.5pt; color: #1E293B;">
        <strong>Forensic Finding Summary:</strong> Overall risk evaluated at <strong>{max_risk}/100 ({risk_label})</strong>.
      </p>
      <ol style="margin: 6px 0 0 0; padding-left: 18px; font-size: 8pt; color: #475569;">
        <li>Correlate detected incremental revision timestamps against server access logs.</li>
        <li>Review any flagged macro or JavaScript streams in an isolated sandbox environment.</li>
        <li>Preserve the generated PDF report alongside original evidence in cold storage.</li>
      </ol>
    </div>

    <!-- Forensic Disclaimer -->
    <div class="disclaimer">
      <strong>SCIENTIFIC LIMITATIONS & LEGAL DISCLAIMER:</strong> This report represents an automated technical examination produced by PRAMAANX.
      Structural findings, SHA-256 baselines, and byte offsets are deterministic observations of the digital bitstream.
      Machine learning scores and tamper probabilities reflect heuristic evaluations and should be verified through manual laboratory analysis prior to formal evidentiary introduction in judicial proceedings.
    </div>
    """
    return html_out


def generate_case_report(
    case_id: str,
    report_type: str = "detailed",
    title: Optional[str] = None,
    generated_by: str = "Forensic Analyst",
) -> Dict[str, Any]:
    """
    Compiles, renders, stamps, hashes, and persists a PDF forensic report.
    Returns the report record dictionary.
    """
    case = get_investigation(case_id)
    if not case:
        raise ValueError(f"Investigation '{case_id}' does not exist.")

    evidence_list, _ = list_evidence_items(investigation_id=case_id, limit=200)
    audit_logs = get_audit_logs(investigation_id=case_id, limit=100)

    # Collect latest examination record for each evidence item
    examination_records: List[Dict[str, Any]] = []
    included_record_ids: List[str] = []

    for ev in evidence_list:
        history = list_analysis_records(ev["id"])
        if history:
            # Most recent record
            latest = history[0]
            examination_records.append(latest)
            included_record_ids.append(latest["id"])

    # Determine report title and ID
    clean_type = "executive" if str(report_type).lower().strip() == "executive" else "detailed"
    report_id = generate_report_id()
    report_title = (
        title.strip()
        if title and title.strip()
        else f"{'Executive Summary' if clean_type == 'executive' else 'Detailed Forensic Report'} - {case['title']}"
    )

    # Build HTML content based on report type
    if clean_type == "executive":
        html_content = _build_html_executive_summary_report(
            case=case,
            evidence_list=evidence_list,
            examination_records=examination_records,
            report_id=report_id,
            generated_by=generated_by,
        )
    else:
        html_content = _build_html_detailed_forensic_report(
            case=case,
            evidence_list=evidence_list,
            examination_records=examination_records,
            audit_logs=audit_logs,
            report_id=report_id,
            generated_by=generated_by,
        )

    # File paths
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    filename = f"{report_id}_{clean_type}.pdf"
    final_pdf_path = REPORTS_DIR / filename

    # Render multi-page flowables via in-memory PyMuPDF Story
    import io
    story = pymupdf.Story(html=html_content)
    buf = io.BytesIO()
    writer = pymupdf.DocumentWriter(buf)
    # A4 printable rectangle with margins: left=40, top=55, right=555, bottom=785
    page_rect = pymupdf.paper_rect("a4")
    body_rect = pymupdf.Rect(40, 55, 555, 785)

    more = 1
    while more:
        device = writer.begin_page(page_rect)
        more, _ = story.place(body_rect)
        story.draw(device)
        writer.end_page()

    writer.close()

    # Post-process with PyMuPDF: stamp running headers, footers, page numbers, and confidentiality line
    doc = pymupdf.open(stream=buf.getvalue(), filetype="pdf")
    total_pages = len(doc)
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    for idx, page in enumerate(doc):
        page_num = idx + 1
        # Running Top Header
        page.insert_text(
            pymupdf.Point(40, 38),
            "PRAMAANX DIGITAL FORENSICS | CONFIDENTIAL INVESTIGATION RECORD",
            fontsize=7,
            color=(0.39, 0.45, 0.55),
            fontname="helv",
        )
        page.insert_text(
            pymupdf.Point(400, 38),
            f"Case: {case_id} • {report_id}",
            fontsize=7,
            color=(0.39, 0.45, 0.55),
            fontname="helv",
        )
        page.draw_line(
            pymupdf.Point(40, 44),
            pymupdf.Point(555, 44),
            color=(0.85, 0.88, 0.92),
            width=0.6,
        )

        # Running Bottom Footer
        page.draw_line(
            pymupdf.Point(40, 800),
            pymupdf.Point(555, 800),
            color=(0.85, 0.88, 0.92),
            width=0.6,
        )
        page.insert_text(
            pymupdf.Point(40, 814),
            f"Report ID: {report_id} • Export Timestamp: {now_utc}",
            fontsize=7,
            color=(0.39, 0.45, 0.55),
            fontname="helv",
        )
        page.insert_text(
            pymupdf.Point(485, 814),
            f"Page {page_num} of {total_pages}",
            fontsize=7,
            color=(0.39, 0.45, 0.55),
            fontname="helv",
        )

    # Save finalized PDF
    doc.save(str(final_pdf_path))
    doc.close()

    # Calculate cryptographic SHA-256 digest of the exported PDF
    hasher = hashlib.sha256()
    with open(final_pdf_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    pdf_sha256 = hasher.hexdigest()
    pdf_size = final_pdf_path.stat().st_size

    # Enforce read-only file permissions (0o444)
    try:
        os.chmod(final_pdf_path, 0o444)
    except Exception:
        pass

    # Save to database
    summary_text = (
        f"{'Executive' if clean_type == 'executive' else 'Detailed'} report generated with {len(evidence_list)} evidence file(s) and {len(included_record_ids)} examination record(s)."
    )

    record = save_report_record(
        report_id=report_id,
        investigation_id=case_id,
        report_type=clean_type,
        title=report_title,
        summary=summary_text,
        sha256_hash=pdf_sha256,
        file_size_bytes=pdf_size,
        stored_filename=filename,
        included_records=included_record_ids,
        generated_by=generated_by,
    )

    return record
