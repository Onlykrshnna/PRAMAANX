"""
PRAMAANX - PDF Forensic Analyzer (Phase 2)
==========================================
Comprehensive static forensic inspection of PDF files:
- Document metadata extraction & timestamp chronology analysis
- Incremental update & revision history detection
- Structural exploit screening:
  * Embedded JavaScript (/JavaScript, /JS)
  * Launch actions (/Launch)
  * Automated execution triggers (/OpenAction, /AA)
  * Embedded file attachments (/EmbeddedFiles, /EF)
  * Suspicious hyperlinks (/URI: IP addresses, phishing schemes)
  * Encryption & permission restrictions (/Encrypt)
  * Dynamic form architectures (/AcroForm, /XFA)
- Visual & textual anomaly heuristics:
  * Font family diversity per page (overlay / certificate tampering)
  * Microscopic / hidden text detection (font size < 2.0 pt)

Defensive Guarantee:
--------------------
Treats all PDF structures as untrusted data. Employs dual-layer inspection
(PyMuPDF object parser + raw binary token scanner) without executing any code.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import io
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import pymupdf

from backend.analyzers.common import Finding


@dataclass
class PdfForensicReport:
    """Standardized output of the PDF forensic analyzer."""
    findings: List[Finding] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    page_count: int = 0
    is_encrypted: bool = False
    has_javascript: bool = False
    has_launch_actions: bool = False
    has_embedded_files: bool = False
    has_suspicious_uris: bool = False
    revision_count: int = 1
    fonts_detected: List[str] = field(default_factory=list)


def parse_pdf_date(date_str: Optional[str]) -> Optional[datetime]:
    """
    Parses PDF date strings formatted per PDF 1.7 spec:
    Format: D:YYYYMMDDHHmmSS[+-]HH'mm' or variations.
    """
    if not date_str or not isinstance(date_str, str):
        return None

    cleaned = date_str.strip()
    if cleaned.startswith("D:"):
        cleaned = cleaned[2:]

    # Remove apostrophes in timezone offset e.g. +05'30' -> +0530
    cleaned = cleaned.replace("'", "")

    # Match YYYYMMDDHHmmss or YYYYMMDD
    pattern = r"^(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?(?:([+-Z])(\d{2})?(\d{2})?)?"
    match = re.match(pattern, cleaned)
    if not match:
        return None

    groups = match.groups()
    year = int(groups[0])
    month = int(groups[1]) if groups[1] else 1
    day = int(groups[2]) if groups[2] else 1
    hour = int(groups[3]) if groups[3] else 0
    minute = int(groups[4]) if groups[4] else 0
    second = int(groups[5]) if groups[5] else 0

    tz_sign = groups[6]
    tz_hr = int(groups[7]) if groups[7] else 0
    tz_min = int(groups[8]) if groups[8] else 0

    tz = timezone.utc
    if tz_sign in ("+", "-"):
        offset_minutes = tz_hr * 60 + tz_min
        if tz_sign == "-":
            offset_minutes = -offset_minutes
        from datetime import timedelta
        tz = timezone(timedelta(minutes=offset_minutes))

    try:
        return datetime(year, month, day, hour, minute, second, tzinfo=tz)
    except (ValueError, OverflowError):
        return None


def _scan_raw_pdf_tokens(raw_bytes: bytes) -> Dict[str, Any]:
    """
    Performs raw binary token scanning across the entire PDF byte stream.
    
    Why this is critical in Forensics:
    ---------------------------------
    Attackers often construct malformed xref tables or hide objects in unreferenced
    streams specifically to bypass DOM-level parsers (Parser Differential Evasion).
    A raw regex pass guarantees that hidden `/JavaScript` or `/Launch` actions
    cannot hide behind corrupt header structures.
    """
    eof_offsets = [m.start() for m in re.finditer(b"%%EOF", raw_bytes)]
    startxref_offsets = [m.start() for m in re.finditer(b"startxref", raw_bytes)]
    js_offsets = [m.start() for m in re.finditer(rb"/(?:JavaScript|JS)\b", raw_bytes)]
    launch_offsets = [m.start() for m in re.finditer(rb"/Launch\b", raw_bytes)]
    openaction_offsets = [m.start() for m in re.finditer(rb"/(?:OpenAction|AA)\b", raw_bytes)]
    ef_offsets = [m.start() for m in re.finditer(rb"/(?:EmbeddedFiles|EF)\b", raw_bytes)]
    acroform_offsets = [m.start() for m in re.finditer(rb"/AcroForm\b", raw_bytes)]
    xfa_offsets = [m.start() for m in re.finditer(rb"/XFA\b", raw_bytes)]
    encrypt_offsets = [m.start() for m in re.finditer(rb"/Encrypt\b", raw_bytes)]

    results: Dict[str, Any] = {
        "eof_count": len(eof_offsets),
        "eof_offsets": eof_offsets,
        "startxref_count": len(startxref_offsets),
        "startxref_offsets": startxref_offsets,
        "javascript_count": len(js_offsets),
        "javascript_offsets": js_offsets,
        "launch_count": len(launch_offsets),
        "launch_offsets": launch_offsets,
        "openaction_count": len(openaction_offsets),
        "openaction_offsets": openaction_offsets,
        "embedded_files_count": len(ef_offsets),
        "embedded_files_offsets": ef_offsets,
        "acroform_count": len(acroform_offsets),
        "xfa_count": len(xfa_offsets),
        "encrypt_count": len(encrypt_offsets),
        "encrypt_offsets": encrypt_offsets,
        "raw_uris": [],
    }

    # Extract raw URI string references
    uri_matches = re.findall(rb"/URI\s*\(([^)]+)\)", raw_bytes)
    for u in uri_matches[:20]:
        try:
            results["raw_uris"].append(u.decode("utf-8", errors="ignore"))
        except Exception:
            pass

    return results


def analyze_pdf(file_path: Union[str, Path]) -> PdfForensicReport:
    """
    Executes deep static forensic analysis on a PDF document.

    Args:
        file_path: Path to the target PDF file.

    Returns:
        PdfForensicReport containing findings, metadata, timeline, and structural metrics.
    """
    path = Path(file_path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"PDF file not found: {path}")

    report = PdfForensicReport()
    findings: List[Finding] = []
    timeline: List[Dict[str, Any]] = []

    raw_bytes = path.read_bytes()
    raw_tokens = _scan_raw_pdf_tokens(raw_bytes)

    # --------------------------------------------------------------------------
    # 1. Incremental Revisions & Update History
    # --------------------------------------------------------------------------
    # In PDF architecture, incremental updates append a new xref table and %%EOF
    # instead of overwriting the original file. Multiple %%EOF markers reveal
    # that the document was modified and re-saved.
    report.revision_count = max(1, raw_tokens["eof_count"])
    if report.revision_count > 1:
        findings.append(
            Finding(
                title="Multiple PDF Revisions Detected (Incremental Updates)",
                detail=(
                    f"The PDF contains {report.revision_count} distinct document revisions (%%EOF markers). "
                    "Incremental updates indicate the file was altered and re-saved after its initial creation. "
                    "In forensic investigations, earlier revisions can be examined to recover overwritten text, "
                    "modified financial figures, or replaced signatures."
                ),
                severity="medium" if report.revision_count > 2 else "low",
                weight=0.40 if report.revision_count > 2 else 0.25,
                evidence={
                    "revision_count": report.revision_count,
                    "eof_marker_count": raw_tokens["eof_count"],
                    "startxref_count": raw_tokens["startxref_count"],
                    "eof_byte_offsets": raw_tokens["eof_offsets"],
                },
                category="structural",
            )
        )
        timeline.append({
            "event": "Incremental Revisions Detected",
            "details": f"File underwent {report.revision_count} save cycles",
        })

    # --------------------------------------------------------------------------
    # 2. Raw Structural Exploit Indicators
    # --------------------------------------------------------------------------
    # A. Embedded JavaScript
    if raw_tokens["javascript_count"] > 0:
        report.has_javascript = True
        findings.append(
            Finding(
                title="Embedded JavaScript Detected (/JavaScript, /JS)",
                detail=(
                    f"Found {raw_tokens['javascript_count']} JavaScript token(s) inside PDF streams. "
                    "While JavaScript can be used for dynamic forms, it is the primary vector for PDF-based "
                    "heap-spraying, sandbox escapes, and vulnerability exploitation (e.g. CVE-2021-28550)."
                ),
                severity="high",
                weight=0.85,
                evidence={
                    "token_count": raw_tokens["javascript_count"],
                    "byte_offsets": raw_tokens["javascript_offsets"][:10],
                },
                category="structural",
            )
        )

    # B. Launch Actions
    if raw_tokens["launch_count"] > 0:
        report.has_launch_actions = True
        findings.append(
            Finding(
                title="Suspicious Launch Action Detected (/Launch)",
                detail=(
                    f"Found {raw_tokens['launch_count']} /Launch directive(s). "
                    "Launch actions instruct the PDF viewer to execute an external application, script, "
                    "or operating system command. This is an extremely high-risk exploit mechanism."
                ),
                severity="high",
                weight=0.95,
                evidence={
                    "token_count": raw_tokens["launch_count"],
                    "byte_offsets": raw_tokens["launch_offsets"][:10],
                },
                category="structural",
            )
        )

    # C. Automatic Actions (/OpenAction, /AA)
    if raw_tokens["openaction_count"] > 0:
        findings.append(
            Finding(
                title="Automatic Execution Trigger Detected (/OpenAction, /AA)",
                detail=(
                    f"Found {raw_tokens['openaction_count']} automated action trigger(s). "
                    "These directives cause actions to run automatically when the document or a page is opened, "
                    "without requiring explicit user interaction."
                ),
                severity="high" if (report.has_javascript or report.has_launch_actions) else "medium",
                weight=0.85 if (report.has_javascript or report.has_launch_actions) else 0.50,
                evidence={
                    "token_count": raw_tokens["openaction_count"],
                    "byte_offsets": raw_tokens["openaction_offsets"][:10],
                },
                category="structural",
            )
        )

    # D. Embedded Files (/EmbeddedFiles, /EF)
    if raw_tokens["embedded_files_count"] > 0:
        report.has_embedded_files = True
        findings.append(
            Finding(
                title="Embedded File Attachment Detected (/EmbeddedFiles)",
                detail=(
                    f"Found {raw_tokens['embedded_files_count']} embedded file reference(s). "
                    "Embedded files can serve as second-stage droppers concealing executable binaries, scripts, "
                    "or malicious archives inside a seemingly benign PDF container."
                ),
                severity="medium",
                weight=0.55,
                evidence={
                    "token_count": raw_tokens["embedded_files_count"],
                    "byte_offsets": raw_tokens["embedded_files_offsets"][:10],
                },
                category="structural",
            )
        )

    # E. Dynamic XML Forms Architecture (XFA)
    if raw_tokens["xfa_count"] > 0:
        findings.append(
            Finding(
                title="Dynamic XML Forms Architecture (XFA) Detected",
                detail=(
                    "Document utilizes dynamic XFA forms. XFA forms allow complex scripting and external data "
                    "bindings that have historically been targeted for parser exploitation."
                ),
                severity="low",
                weight=0.25,
                evidence={
                    "token_count": raw_tokens["xfa_count"],
                },
                category="structural",
            )
        )

    # --------------------------------------------------------------------------
    # 3. PyMuPDF DOM-Level Parsing
    # --------------------------------------------------------------------------
    doc = None
    try:
        doc = pymupdf.open(path)
        report.page_count = doc.page_count
        report.is_encrypted = doc.is_encrypted

        # Extract Document Metadata
        meta = doc.metadata or {}
        xml_meta = ""
        try:
            xml_meta = doc.get_xml_metadata() or ""
        except Exception:
            pass

        report.metadata = {
            "format": meta.get("format", ""),
            "title": meta.get("title", ""),
            "author": meta.get("author", ""),
            "subject": meta.get("subject", ""),
            "keywords": meta.get("keywords", ""),
            "creator": meta.get("creator", ""),
            "producer": meta.get("producer", ""),
            "creation_date_raw": meta.get("creationDate", ""),
            "mod_date_raw": meta.get("modDate", ""),
            "has_xmp": bool(xml_meta and len(xml_meta.strip()) > 0),
            "xmp_metadata": xml_meta if xml_meta else None,
            "page_count": report.page_count,
            "is_encrypted": report.is_encrypted,
        }

        # Timestamp chronology analysis
        dt_created = parse_pdf_date(meta.get("creationDate"))
        dt_modified = parse_pdf_date(meta.get("modDate"))

        if dt_created:
            report.metadata["creation_date_iso"] = dt_created.isoformat()
            timeline.append({
                "event": "PDF Created",
                "timestamp": dt_created.isoformat(),
                "actor": meta.get("author", "Unknown"),
                "tool": meta.get("creator", "Unknown"),
            })

        if dt_modified:
            report.metadata["mod_date_iso"] = dt_modified.isoformat()
            timeline.append({
                "event": "PDF Last Modified",
                "timestamp": dt_modified.isoformat(),
                "producer": meta.get("producer", "Unknown"),
            })

        # Inverted Timestamp Check (Tampering Indicator)
        if dt_created and dt_modified and dt_modified < dt_created:
            findings.append(
                Finding(
                    title="Inverted Metadata Timestamps (Modification Precedes Creation)",
                    detail=(
                        f"Document modification timestamp ({dt_modified.isoformat()}) is earlier than "
                        f"its creation timestamp ({dt_created.isoformat()}). Chronological inversion is a classic "
                        "hallmark of metadata manipulation, forged certificates, or synthetic document generation."
                    ),
                    severity="medium",
                    weight=0.60,
                    evidence={
                        "creation_timestamp": dt_created.isoformat(),
                        "modification_timestamp": dt_modified.isoformat(),
                    },
                    category="heuristic",
                )
            )

        # Suspicious Producer Anomaly (Graphic design tools used for official documents)
        producer_str = (meta.get("producer", "") + " " + meta.get("creator", "")).lower()
        graphic_tools = ["photoshop", "canva", "illustrator", "gimp", "inkscape", "coreldraw"]
        matched_tools = [tool for tool in graphic_tools if tool in producer_str]
        if matched_tools:
            findings.append(
                Finding(
                    title="Graphic Design Software Used as PDF Producer",
                    detail=(
                        f"PDF was generated or modified using graphic design software ({', '.join(matched_tools)}). "
                        "Official certificates, academic marksheets, and bank statements are typically generated by "
                        "automated enterprise reporting systems or LaTeX/Acrobat engines, not graphic editing tools."
                    ),
                    severity="low",
                    weight=0.30,
                    evidence={"tools_identified": matched_tools, "producer": meta.get("producer", "")},
                    category="heuristic",
                )
            )

        # Check for completely stripped metadata
        meaningful_meta = [
            meta.get("author"), meta.get("creator"), meta.get("producer"),
            meta.get("title"), meta.get("creationDate")
        ]
        if not any(bool(m and str(m).strip()) for m in meaningful_meta):
            findings.append(
                Finding(
                    title="Completely Stripped Document Metadata",
                    detail=(
                        "All standard metadata fields (Author, Creator, Producer, Title, Creation Date) are empty. "
                        "While occasionally occurring in privacy-scrubbed files, stripped metadata is often used "
                        "by adversaries to obscure attribution."
                    ),
                    severity="low",
                    weight=0.0,
                    evidence={"empty_fields": ["author", "creator", "producer", "title", "creationDate"]},
                    category="inconclusive",
                )
            )

        # ----------------------------------------------------------------------
        # 4. Page-Level Inspection: Links, Fonts, Microscopic Text
        # ----------------------------------------------------------------------
        all_uris: Set[str] = set(raw_tokens["raw_uris"])
        detected_fonts: Set[str] = set()
        suspicious_uris: List[str] = []
        microscopic_text_detected = False

        ip_regex = re.compile(r"https?://(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::\d+)?(?:/|$)")

        for page_idx in range(report.page_count):
            page = doc[page_idx]

            # Inspect Hyperlinks
            links = page.get_links() or []
            for link in links:
                uri = link.get("uri")
                if uri:
                    all_uris.add(uri)

            # Inspect Page Fonts (for overlay / marksheet alteration detection)
            fonts = page.get_fonts() or []
            page_font_names = set()
            for f_info in fonts:
                # f_info tuple: (xref, ext, type, basefont, name, encoding)
                if len(f_info) > 3 and f_info[3]:
                    clean_font = f_info[3].split("+")[-1]  # remove subset prefix e.g. ABCDEF+Arial
                    page_font_names.add(clean_font)
                    detected_fonts.add(clean_font)

            # High Font Diversity on a single page
            if len(page_font_names) > 8:
                findings.append(
                    Finding(
                        title=f"Anomalously High Font Diversity on Page {page_idx + 1}",
                        detail=(
                            f"Page {page_idx + 1} contains {len(page_font_names)} distinct font families. "
                            "In academic marksheets or identity documents, sudden font switches often indicate "
                            "text overlay tampering (pasting forged numbers or names into existing templates)."
                        ),
                        severity="medium",
                        weight=0.45,
                        evidence={"page": page_idx + 1, "font_count": len(page_font_names), "fonts": list(page_font_names)[:10]},
                        category="heuristic",
                    )
                )

            # Inspect Text Blocks for Microscopic or Invisible Text
            text_instances = page.get_text("blocks") or []
            # Each block: (x0, y0, x1, y1, text, block_no, block_type)
            # Inspect detailed span sizes
            text_dict = page.get_text("dict") or {}
            for block in text_dict.get("blocks", []):
                for line in block.get("lines", []):
                    for span in line.get("spans", []):
                        size = span.get("size", 0.0)
                        text_val = span.get("text", "").strip()
                        if 0.1 <= size < 2.0 and len(text_val) > 1:
                            microscopic_text_detected = True

        report.fonts_detected = sorted(list(detected_fonts))

        if microscopic_text_detected:
            findings.append(
                Finding(
                    title="Microscopic / Hidden Text Layer Detected (Size < 2.0 pt)",
                    detail=(
                        "Document contains rendered text with font size under 2.0 points. Microscopic text is "
                        "commonly used for search-engine spamming, hiding steganographic keywords, or inserting "
                        "hidden clauses in contracts that are unreadable to human eyes."
                    ),
                    severity="medium",
                    weight=0.55,
                    evidence={"microscopic_font_detected": True},
                    category="heuristic",
                )
            )

        # Classify URIs
        for uri in all_uris:
            # Check for raw IP address URL (phishing / C2 beacon)
            if ip_regex.match(uri):
                suspicious_uris.append(uri)
            # Check for non-standard URI schemes
            elif any(uri.lower().startswith(s) for s in ("javascript:", "file:", "data:", "shell:")):
                suspicious_uris.append(uri)

        if suspicious_uris:
            report.has_suspicious_uris = True
            findings.append(
                Finding(
                    title="Suspicious Hyperlink / Phishing URI Detected",
                    detail=(
                        f"Found {len(suspicious_uris)} suspicious hyperlink(s) pointing to raw IP addresses or "
                        "non-standard URI schemes (e.g. javascript:, file:). These are characteristic of phishing, "
                        "local file inclusion, or Command & Control (C2) communication."
                    ),
                    severity="high",
                    weight=0.80,
                    evidence={"suspicious_uris": suspicious_uris[:5]},
                    category="heuristic",
                )
            )

    except Exception as e:
        # If PyMuPDF encounters a corrupt PDF, note the parsing failure
        findings.append(
            Finding(
                title="PDF Parser Error / Corrupted Structure",
                detail=f"PyMuPDF encountered an error while parsing document objects: {str(e)}",
                severity="medium",
                weight=0.40,
                evidence={"error": str(e)},
                category="inconclusive",
            )
        )
    finally:
        if doc is not None:
            doc.close()

    report.findings = findings
    report.timeline = timeline
    return report
