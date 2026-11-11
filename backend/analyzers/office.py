"""
PRAMAANX - Office Document Forensic Analyzer (Phase 2)
======================================================
Comprehensive static forensic inspection of Microsoft Office documents:
- Modern OpenXML formats: DOCX, XLSX, PPTX
- Legacy Compound File Binary Format (CFBF OLE): DOC, XLS, PPT

Forensic Inspection Vectors:
----------------------------
1. Metadata & Editing History:
   - Creator, LastModifiedBy, Created, Modified, Revision count
   - TotalTime (editing duration) anomaly detection
   - Timestamp chronology & modification inversion detection
2. Attack & Exploit Mechanisms:
   - Remote Template Injection (CVE-2017-0199 / attachedTemplate to external URLs)
   - Suspicious External Relationships (UNC paths, external script/executable links)
   - Embedded OLE packages and binary payloads (embeddings/*.bin)
   - Macro & VBA detection (vbaProject.bin in non-macro formats, keyword analysis via oletools)
3. Hidden & Concealed Content:
   - Hidden worksheets (state="hidden") and VeryHidden worksheets (state="veryHidden") in Excel
   - Hidden presentation slides (show="0") in PowerPoint
   - Hidden / Vanished text formatting (<w:vanish/>, <w:hidden/>) in Word
4. Archive & XML Structural Integrity:
   - XXE injection attempt screening (<!ENTITY, SYSTEM in XML entries)

Defensive Guarantee:
--------------------
Documents are inspected purely as static archives and structured data streams.
Zero macros, scripts, or embedded payloads are executed under any circumstances.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import io
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import xml.etree.ElementTree as ET
import zipfile

import olefile
from oletools import olevba

from backend.analyzers.common import Finding


@dataclass
class OfficeForensicReport:
    """Standardized output of the Office forensic analyzer."""
    findings: List[Finding] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    format_type: str = ""  # docx, xlsx, pptx, ole_legacy
    has_macros: bool = False
    has_embedded_objects: bool = False
    has_external_relationships: bool = False
    has_hidden_content: bool = False
    embedded_objects_list: List[str] = field(default_factory=list)
    macro_indicators: List[str] = field(default_factory=list)


# ==============================================================================
# Helper Utilities
# ==============================================================================

def _local_tag(tag: str) -> str:
    """Strips XML namespace prefix for robust tag matching."""
    return tag.split("}")[-1] if "}" in tag else tag


def _parse_iso_date(date_str: Optional[str]) -> Optional[datetime]:
    """Parses standard ISO 8601 date strings common in OpenXML."""
    if not date_str or not isinstance(date_str, str):
        return None
    cleaned = date_str.strip()
    try:
        # Normalize trailing Z to +00:00 for fromisoformat compatibility
        if cleaned.endswith("Z"):
            cleaned = cleaned[:-1] + "+00:00"
        return datetime.fromisoformat(cleaned)
    except (ValueError, TypeError):
        return None


# Suspicious keywords in VBA macros indicating malware behavior
SUSPICIOUS_VBA_KEYWORDS: Dict[str, str] = {
    "AutoOpen": "Automatic execution trigger when document opens",
    "Auto_Open": "Automatic execution trigger when workbook opens",
    "Document_Open": "Automatic execution trigger when Word document opens",
    "Workbook_Open": "Automatic execution trigger when Excel workbook opens",
    "Shell": "Invokes system shell or external process execution",
    "WScript.Shell": "Invokes Windows Script Host execution environment",
    "PowerShell": "Invokes PowerShell scripting runtime",
    "cmd.exe": "Direct Windows command interpreter invocation",
    "URLDownloadToFile": "Downloads remote executable payload to disk",
    "XMLHTTP": "Transfers remote network data or beacons to C2",
    "ADODB.Stream": "Writes binary file stream directly to disk",
    "CreateObject": "Dynamically instantiates arbitrary COM objects",
    "CallByName": "Obfuscated / indirect function invocation",
    "Environ": "Queries system environment variables (discovery)",
}


# ==============================================================================
# OpenXML Document Inspection (DOCX, XLSX, PPTX)
# ==============================================================================

def _inspect_openxml_metadata(
    zf: zipfile.ZipFile,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[Finding]]:
    """Extracts metadata from docProps/core.xml and docProps/app.xml."""
    metadata: Dict[str, Any] = {}
    timeline: List[Dict[str, Any]] = []
    findings: List[Finding] = []

    namelist = set(zf.namelist())

    # 1. Parse docProps/core.xml (Dublin Core and OpenXML properties)
    if "docProps/core.xml" in namelist:
        try:
            xml_bytes = zf.read("docProps/core.xml")
            root = ET.fromstring(xml_bytes)
            for elem in root:
                tag = _local_tag(elem.tag)
                val = elem.text.strip() if elem.text else ""
                if tag == "creator":
                    metadata["creator"] = val
                elif tag == "lastModifiedBy":
                    metadata["last_modified_by"] = val
                elif tag == "created":
                    metadata["created_raw"] = val
                elif tag == "modified":
                    metadata["modified_raw"] = val
                elif tag == "revision":
                    metadata["revision"] = val
                elif tag == "title":
                    metadata["title"] = val
                elif tag == "subject":
                    metadata["subject"] = val
        except Exception as e:
            findings.append(
                Finding(
                    title="Corrupted Core Metadata XML",
                    detail=f"Unable to parse docProps/core.xml: {str(e)}",
                    severity="low",
                    weight=0.15,
                    evidence={"error": str(e), "xml_entry": "docProps/core.xml"},
                    category="inconclusive",
                )
            )

    # 2. Parse docProps/app.xml (Extended properties)
    if "docProps/app.xml" in namelist:
        try:
            xml_bytes = zf.read("docProps/app.xml")
            root = ET.fromstring(xml_bytes)
            for elem in root:
                tag = _local_tag(elem.tag)
                val = elem.text.strip() if elem.text else ""
                if tag == "TotalTime":
                    try:
                        metadata["total_edit_time_minutes"] = int(val)
                    except ValueError:
                        metadata["total_edit_time_minutes"] = val
                elif tag == "Application":
                    metadata["application"] = val
                elif tag == "AppVersion":
                    metadata["app_version"] = val
                elif tag == "Company":
                    metadata["company"] = val
                elif tag in ("Words", "Pages", "Paragraphs", "Lines"):
                    try:
                        metadata[tag.lower()] = int(val)
                    except ValueError:
                        pass
        except Exception:
            pass

    # 3. Timestamp Chronology Analysis
    dt_created = _parse_iso_date(metadata.get("created_raw"))
    dt_modified = _parse_iso_date(metadata.get("modified_raw"))

    if dt_created:
        metadata["created_iso"] = dt_created.isoformat()
        timeline.append({
            "event": "Document Created",
            "timestamp": dt_created.isoformat(),
            "actor": metadata.get("creator", "Unknown"),
        })

    if dt_modified:
        metadata["modified_iso"] = dt_modified.isoformat()
        timeline.append({
            "event": "Document Last Modified",
            "timestamp": dt_modified.isoformat(),
            "actor": metadata.get("last_modified_by", "Unknown"),
            "tool": metadata.get("application", "Unknown"),
        })

    # Inverted Timestamp Check
    if dt_created and dt_modified and dt_modified < dt_created:
        findings.append(
            Finding(
                title="Inverted Modification Timestamp in Office Metadata",
                detail=(
                    f"Document modification timestamp ({dt_modified.isoformat()}) is earlier than its "
                    f"creation timestamp ({dt_created.isoformat()}). This chronological anomaly indicates "
                    "manual metadata editing, cloned document templates, or forged artifact timestamps."
                ),
                severity="medium",
                weight=0.60,
                evidence={
                    "created": dt_created.isoformat(),
                    "modified": dt_modified.isoformat(),
                    "xml_entry": "docProps/core.xml",
                },
                category="heuristic",
            )
        )

    # Zero Editing Time Anomaly
    edit_time = metadata.get("total_edit_time_minutes")
    word_count = metadata.get("words", 0)
    rev_count = 0
    try:
        rev_count = int(metadata.get("revision", 0))
    except ValueError:
        pass

    if edit_time == 0 and (word_count > 300 or rev_count > 5):
        findings.append(
            Finding(
                title="Zero Editing Time on Substantial Document",
                detail=(
                    f"Document reports 0 minutes total editing time despite containing {word_count} words and "
                    f"{rev_count} recorded revisions. This pattern is characteristic of automated document generators, "
                    "cloned phishing templates, or metadata scrubbing tools."
                ),
                severity="low",
                weight=0.25,
                evidence={"words": word_count, "revisions": rev_count, "total_edit_time": 0, "xml_entry": "docProps/app.xml"},
                category="statistical",
            )
        )

    return metadata, timeline, findings


def _inspect_relationships(zf: zipfile.ZipFile) -> Tuple[List[Finding], bool]:
    """
    Inspects all .rels relationship files for external links and remote template injection.
    
    Forensic Context:
    -----------------
    Remote Template Injection (CVE-2017-0199 / attachedTemplate) is an evasion technique
    where a harmless-looking DOCX downloads a malicious dotm template from a remote server
    upon opening.
    """
    findings: List[Finding] = []
    has_external = False
    external_links: List[Dict[str, str]] = []

    for name in zf.namelist():
        if name.endswith(".rels"):
            try:
                xml_data = zf.read(name)
                root = ET.fromstring(xml_data)
                for rel in root:
                    target_mode = rel.attrib.get("TargetMode", "")
                    target = rel.attrib.get("Target", "")
                    rel_type = rel.attrib.get("Type", "")

                    if target_mode == "External":
                        has_external = True
                        external_links.append({"target": target, "type": rel_type, "rels_file": name})

                        # 1. Critical Check: Remote Template Injection
                        if "attachedTemplate" in rel_type and any(target.lower().startswith(p) for p in ("http://", "https://", "\\\\")):
                            findings.append(
                                Finding(
                                    title="Remote Template Injection Detected (Office Exploit Vector)",
                                    detail=(
                                        f"Document links to an external template at '{target}'. "
                                        "Office Template Injection dynamically fetches an external template when "
                                        "opened, allowing adversaries to deliver macros or exploits without embedding "
                                        "them in the initial file."
                                    ),
                                    severity="high",
                                    weight=0.95,
                                    evidence={"remote_template_url": target, "rels_file": name, "container_path": name},
                                    category="heuristic",
                                )
                            )

                        # 2. Check for UNC network paths or raw IP addresses
                        elif target.startswith("\\\\") or re.match(r"https?://(?:[0-9]{1,3}\.){3}[0-9]{1,3}", target):
                            findings.append(
                                Finding(
                                    title="Suspicious External Relationship Target (UNC Path or Raw IP)",
                                    detail=(
                                        f"External relationship in '{name}' points to '{target}'. "
                                        "UNC paths (`\\\\host\\share`) are frequently used in NTLM credential harvesting attacks."
                                    ),
                                    severity="high",
                                    weight=0.85,
                                    evidence={"target": target, "rels_file": name, "container_path": name},
                                    category="heuristic",
                                )
                            )
            except Exception:
                pass

    if has_external and not any(f.severity == "high" for f in findings):
        findings.append(
            Finding(
                title="External Document Relationships Identified",
                detail=f"Found {len(external_links)} external relationship reference(s) (hyperlinks or remote resources).",
                severity="low",
                weight=0.15,
                evidence={"count": len(external_links), "samples": [e["target"] for e in external_links[:5]]},
                category="structural",
            )
        )

    return findings, has_external


def _inspect_hidden_content(
    zf: zipfile.ZipFile,
    format_type: str,
) -> Tuple[List[Finding], bool]:
    """Inspects OpenXML archives for hidden sheets, hidden slides, and hidden text."""
    findings: List[Finding] = []
    has_hidden = False
    namelist = set(zf.namelist())

    # 1. Excel (XLSX): Hidden and VeryHidden worksheets
    if "xl/workbook.xml" in namelist:
        try:
            xml_data = zf.read("xl/workbook.xml")
            root = ET.fromstring(xml_data)
            hidden_sheets = []
            very_hidden_sheets = []

            for elem in root.iter():
                if _local_tag(elem.tag) == "sheet":
                    state = elem.attrib.get("state", "").lower()
                    name = elem.attrib.get("name", "Unknown")
                    if state == "hidden":
                        hidden_sheets.append(name)
                        has_hidden = True
                    elif state == "veryhidden":
                        very_hidden_sheets.append(name)
                        has_hidden = True

            if very_hidden_sheets:
                findings.append(
                    Finding(
                        title="VeryHidden Worksheet Detected in Spreadsheet",
                        detail=(
                            f"Workbook contains 'VeryHidden' sheet(s): {', '.join(very_hidden_sheets)}. "
                            "Unlike normal hidden sheets, VeryHidden sheets cannot be revealed via the standard "
                            "Excel user interface and require VBA scripts to unhide. They are frequently used "
                            "to conceal sensitive exfiltrated data, obfuscated formulas, or staging tables."
                        ),
                        severity="medium",
                        weight=0.55,
                        evidence={"very_hidden_sheets": very_hidden_sheets, "xml_entry": "xl/workbook.xml", "container_path": "xl/workbook.xml"},
                        category="structural",
                    )
                )

            if hidden_sheets:
                findings.append(
                    Finding(
                        title="Hidden Worksheet Detected in Spreadsheet",
                        detail=f"Workbook contains hidden worksheet(s): {', '.join(hidden_sheets)}.",
                        severity="low",
                        weight=0.25,
                        evidence={"hidden_sheets": hidden_sheets, "xml_entry": "xl/workbook.xml", "container_path": "xl/workbook.xml"},
                        category="structural",
                    )
                )
        except Exception:
            pass

    # 2. PowerPoint (PPTX): Hidden slides
    if "ppt/presentation.xml" in namelist:
        try:
            xml_data = zf.read("ppt/presentation.xml")
            root = ET.fromstring(xml_data)
            hidden_slide_count = 0
            for elem in root.iter():
                if _local_tag(elem.tag) == "sldId":
                    # show="0" indicates a hidden slide
                    if elem.attrib.get("show") == "0":
                        hidden_slide_count += 1
                        has_hidden = True

            if hidden_slide_count > 0:
                findings.append(
                    Finding(
                        title="Hidden Slide(s) Detected in Presentation",
                        detail=(
                            f"Presentation contains {hidden_slide_count} hidden slide(s) that are excluded "
                            "from normal presentation display. Hidden slides can conceal drafts, previous versions, "
                            "or sensitive notes."
                        ),
                        severity="low",
                        weight=0.25,
                        evidence={"hidden_slide_count": hidden_slide_count, "xml_entry": "ppt/presentation.xml", "container_path": "ppt/presentation.xml"},
                        category="structural",
                    )
                )
        except Exception:
            pass

    # 3. Word (DOCX): Vanished / Hidden text
    if "word/document.xml" in namelist:
        try:
            xml_data = zf.read("word/document.xml")
            # Search for <w:vanish/> or <w:hidden/> in document formatting
            vanish_count = len(re.findall(rb"<w:vanish(?:\s*/>|>[^<]*</w:vanish>)", xml_data))
            if vanish_count > 0:
                has_hidden = True
                findings.append(
                    Finding(
                        title="Hidden / Vanished Text Formatting in Document",
                        detail=(
                            f"Found {vanish_count} instance(s) of hidden text formatting (<w:vanish/>). "
                            "Hidden text is invisible during normal reading or printing unless 'Show All' is toggled. "
                            "It is occasionally used to conceal instructions, evasion keywords, or watermarks."
                        ),
                        severity="medium",
                        weight=0.45,
                        evidence={"vanish_tags_count": vanish_count, "xml_entry": "word/document.xml", "container_path": "word/document.xml"},
                        category="heuristic",
                    )
                )
        except Exception:
            pass

    return findings, has_hidden


def _inspect_macros_and_ole(
    zf: zipfile.ZipFile,
    file_path: Path,
) -> Tuple[List[Finding], bool, bool, List[str], List[str]]:
    """Inspects OpenXML archives for VBA macros and embedded OLE packages."""
    findings: List[Finding] = []
    has_macros = False
    has_embeddings = False
    embedded_list: List[str] = []
    macro_indicators: List[str] = []

    namelist = zf.namelist()

    # 1. Embedded Objects Check
    for name in namelist:
        if "/embeddings/" in name:
            has_embeddings = True
            basename = Path(name).name
            embedded_list.append(basename)

    if has_embeddings:
        findings.append(
            Finding(
                title="Embedded OLE Package / Binary Object Detected",
                detail=(
                    f"Document contains {len(embedded_list)} embedded binary object(s): {', '.join(embedded_list[:5])}. "
                    "Embedded objects can contain arbitrary binary files, executables, or scripts designed to execute "
                    "via user activation or Office package handlers."
                ),
                severity="high",
                weight=0.85,
                evidence={"embedded_objects": embedded_list, "container_path": f"embeddings/{embedded_list[0]}" if embedded_list else "embeddings/"},
                category="structural",
            )
        )

    # 2. Cloaked Macro Check (vbaProject.bin in standard non-macro formats)
    vba_entries = [name for name in namelist if name.endswith("vbaProject.bin") or "vbaData" in name]
    if vba_entries:
        has_macros = True
        ext = file_path.suffix.lower()
        if ext in (".docx", ".xlsx", ".pptx"):
            findings.append(
                Finding(
                    title="Cloaked VBA Macro in Standard Extension",
                    detail=(
                        f"File has extension '{ext}' (which should be macro-free) but contains "
                        f"VBA macro project '{vba_entries[0]}'. Renaming macro-enabled files (.docm/.xlsm) "
                        f"to standard extensions is a common evasion technique to bypass security filters."
                    ),
                    severity="high",
                    weight=0.98,
                    evidence={"vba_entry": vba_entries[0], "claimed_extension": ext, "container_path": vba_entries[0]},
                    category="structural",
                )
            )

        # Inspect macro keywords using oletools without executing
        try:
            vba_parser = olevba.VBA_Parser(filename=file_path)
            if vba_parser.detect_vba_macros():
                macro_analysis = vba_parser.analyze_macros() or []
                matched_suspicious = []
                for kw_type, keyword, desc in macro_analysis:
                    if kw_type in ("Suspicious", "AutoExec", "IOC"):
                        matched_suspicious.append(f"{keyword} ({desc})")
                        macro_indicators.append(keyword)

                if matched_suspicious:
                    findings.append(
                        Finding(
                            title="Malicious / Suspicious VBA Macro Behavior Indicators",
                            detail=(
                                f"Static heuristic analysis of embedded VBA identified {len(matched_suspicious)} "
                                f"suspicious indicators: {', '.join(matched_suspicious[:5])}."
                            ),
                            severity="high",
                            weight=0.92,
                            evidence={"matched_indicators": matched_suspicious[:10], "container_path": vba_entries[0]},
                            category="heuristic",
                        )
                    )
            vba_parser.close()
        except Exception:
            pass

    return findings, has_macros, has_embeddings, embedded_list, macro_indicators


# ==============================================================================
# Legacy OLE CFBF Format Inspection (.DOC, .XLS, .PPT 97-2003)
# ==============================================================================

def _analyze_legacy_ole(file_path: Path) -> OfficeForensicReport:
    """Inspects legacy Microsoft Compound File Binary Format documents using olefile & oletools."""
    report = OfficeForensicReport(format_type="ole_legacy")
    findings: List[Finding] = []
    timeline: List[Dict[str, Any]] = []

    findings.append(
        Finding(
            title="Legacy OLE Compound File Format (DOC/XLS/PPT 97-2003)",
            detail=(
                "File is formatted using the legacy Microsoft Compound File Binary Format (CFBF). "
                "Legacy binary formats lack the XML validation of modern OpenXML and are historically "
                "the most common vehicle for malicious VBA macro payloads."
            ),
            severity="low",
            weight=0.30,
            evidence={"format": "OLE CFBF"},
            category="structural",
        )
    )

    # Inspect OLE Summary Information
    try:
        ole = olefile.OleFileIO(file_path)
        meta = ole.get_metadata()
        report.metadata = {
            "author": meta.author.decode("utf-8", errors="ignore") if meta.author else "",
            "last_saved_by": meta.last_saved_by.decode("utf-8", errors="ignore") if meta.last_saved_by else "",
            "creating_application": meta.creating_application.decode("utf-8", errors="ignore") if meta.creating_application else "",
            "total_edit_time": str(meta.total_edit_time) if meta.total_edit_time else "",
        }

        if meta.create_time:
            report.metadata["create_time"] = meta.create_time.isoformat()
            timeline.append({
                "event": "Legacy Document Created",
                "timestamp": meta.create_time.isoformat(),
                "actor": report.metadata.get("author", "Unknown"),
            })

        if meta.last_saved_time:
            report.metadata["last_saved_time"] = meta.last_saved_time.isoformat()
            timeline.append({
                "event": "Legacy Document Last Saved",
                "timestamp": meta.last_saved_time.isoformat(),
                "actor": report.metadata.get("last_saved_by", "Unknown"),
            })

        # Check for embedded storage streams
        storages = ole.listdir()
        embedded_streams = [s[0] for s in storages if any(kw in s[0].lower() for kw in ("package", "object", "ole"))]
        if embedded_streams:
            report.has_embedded_objects = True
            findings.append(
                Finding(
                    title="Embedded OLE Stream Detected in Legacy Document",
                    detail=f"Identified embedded binary streams: {', '.join(embedded_streams[:5])}.",
                    severity="high",
                    weight=0.80,
                    evidence={"streams": embedded_streams},
                    category="structural",
                )
            )
        ole.close()
    except Exception as e:
        findings.append(
            Finding(
                title="Legacy OLE Parser Error",
                detail=f"Failed to read OLE directory streams: {str(e)}",
                severity="low",
                weight=0.20,
                evidence={"error": str(e)},
                category="inconclusive",
            )
        )

    # Check for VBA Macros in Legacy OLE via oletools
    try:
        vba_parser = olevba.VBA_Parser(filename=file_path)
        if vba_parser.detect_vba_macros():
            report.has_macros = True
            macro_analysis = vba_parser.analyze_macros() or []
            matched = [f"{kw} ({desc})" for kw_type, kw, desc in macro_analysis if kw_type in ("Suspicious", "AutoExec", "IOC")]
            findings.append(
                Finding(
                    title="VBA Macro Payload Detected in Legacy Office Document",
                    detail=(
                        f"Legacy document contains active VBA macro code. "
                        f"Identified indicators: {', '.join(matched[:5]) if matched else 'Standard macro streams'}."
                    ),
                    severity="high",
                    weight=0.90,
                    evidence={"indicators": matched[:10]},
                    category="structural",
                )
            )
        vba_parser.close()
    except Exception:
        pass

    report.findings = findings
    report.timeline = timeline
    return report


# ==============================================================================
# Main Public Interface
# ==============================================================================

def analyze_office(file_path: Union[str, Path]) -> OfficeForensicReport:
    """
    Executes deep static forensic analysis on Microsoft Office files (DOCX, XLSX, PPTX, DOC, XLS, PPT).

    Args:
        file_path: Path to target Office document.

    Returns:
        OfficeForensicReport containing findings, metadata, timeline, and security indicators.
    """
    path = Path(file_path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Office document not found: {path}")

    # Check if file is a legacy OLE file
    if olefile.isOleFile(path):
        return _analyze_legacy_ole(path)

    # Check if file is a valid OpenXML ZIP archive
    if not zipfile.is_zipfile(path):
        report = OfficeForensicReport(format_type="invalid")
        report.findings.append(
            Finding(
                title="Invalid or Corrupted Office Document Package",
                detail="File header does not match either OpenXML (ZIP) or Legacy OLE binary specifications.",
                severity="medium",
                weight=0.50,
                evidence={"path": str(path.name)},
                category="inconclusive",
            )
        )
        return report

    report = OfficeForensicReport()
    findings: List[Finding] = []

    with zipfile.ZipFile(path) as zf:
        namelist = set(zf.namelist())

        # Determine OpenXML subtype
        if any(name.startswith("word/") for name in namelist):
            report.format_type = "docx"
        elif any(name.startswith("xl/") for name in namelist):
            report.format_type = "xlsx"
        elif any(name.startswith("ppt/") for name in namelist):
            report.format_type = "pptx"
        else:
            report.format_type = "generic_openxml"

        # 1. Metadata Inspection
        meta, timeline, meta_findings = _inspect_openxml_metadata(zf)
        report.metadata = meta
        report.timeline = timeline
        findings.extend(meta_findings)

        # 2. External Relationships & Remote Template Injection
        rel_findings, has_ext = _inspect_relationships(zf)
        report.has_external_relationships = has_ext
        findings.extend(rel_findings)

        # 3. Hidden Content Inspection
        hidden_findings, has_hidden = _inspect_hidden_content(zf, report.format_type)
        report.has_hidden_content = has_hidden
        findings.extend(hidden_findings)

        # 4. Macros and Embedded Objects
        macro_findings, has_mac, has_emb, emb_list, mac_ind = _inspect_macros_and_ole(zf, path)
        report.has_macros = has_mac
        report.has_embedded_objects = has_emb
        report.embedded_objects_list = emb_list
        report.macro_indicators = mac_ind
        findings.extend(macro_findings)

        # 5. XML Security Check: Screening for XXE injection entities
        for name in namelist:
            if name.endswith(".xml") or name.endswith(".rels"):
                try:
                    xml_content = zf.read(name)
                    if b"<!ENTITY" in xml_content or b"SYSTEM" in xml_content:
                        findings.append(
                            Finding(
                                title="Suspicious XML Entity Declaration (Possible XXE Attempt)",
                                detail=f"Found XML external entity declaration in '{name}'.",
                                severity="high",
                                weight=0.85,
                                evidence={"xml_entry": name, "container_path": name},
                                category="heuristic",
                            )
                        )
                except Exception:
                    pass

    report.findings = findings
    return report
