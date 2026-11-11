"""
PRAMAANX - Phase 2 PDF Forensic Analyzer Unit Tests
===================================================
Tests metadata extraction, timestamp chronology, incremental revisions,
structural exploit tokens (JS, Launch, OpenAction, EmbeddedFiles, URIs),
and textual/font anomaly detection.
"""

from datetime import datetime, timezone
import io
from pathlib import Path
import pytest
import pymupdf

from backend.analyzers.pdf import analyze_pdf, parse_pdf_date
from backend.pipeline import ForensicPipeline


# ==============================================================================
# 1. Date Parsing Tests
# ==============================================================================

def test_parse_pdf_date_standard():
    """Parses standard PDF 1.7 timestamp D:20240315143000+05'30'."""
    raw = "D:20240315143000+05'30'"
    dt = parse_pdf_date(raw)
    assert dt is not None
    assert dt.year == 2024
    assert dt.month == 3
    assert dt.day == 15
    assert dt.hour == 14
    assert dt.minute == 30


def test_parse_pdf_date_utc_z():
    """Parses UTC PDF timestamp D:20231104120000Z."""
    raw = "D:20231104120000Z"
    dt = parse_pdf_date(raw)
    assert dt is not None
    assert dt.year == 2023
    assert dt.month == 11
    assert dt.day == 4


def test_parse_pdf_date_invalid():
    """Returns None on invalid strings."""
    assert parse_pdf_date("") is None
    assert parse_pdf_date("NotADate") is None


# ==============================================================================
# 2. Benign PDF Metadata & Analysis
# ==============================================================================

def test_analyze_benign_pdf(tmp_path: Path):
    """Creates a benign standard PDF and verifies clean metadata extraction."""
    pdf_path = tmp_path / "benign.pdf"
    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((72, 72), "Official Statement of Account")
    doc.set_metadata({
        "title": "Account Statement",
        "author": "National Bank",
        "creator": "Enterprise Report Generator",
        "producer": "Adobe PDF Library 15.0",
        "creationDate": "D:20240101100000Z",
        "modDate": "D:20240101100500Z",
    })
    doc.save(pdf_path)
    doc.close()

    report = analyze_pdf(pdf_path)
    assert report.page_count == 1
    assert report.metadata["author"] == "National Bank"
    assert report.metadata["title"] == "Account Statement"
    assert report.has_javascript is False
    assert report.has_launch_actions is False
    assert report.has_embedded_files is False
    assert len(report.timeline) == 2


# ==============================================================================
# 3. Inverted Timestamps Detection (Tampering Indicator)
# ==============================================================================

def test_analyze_inverted_timestamps(tmp_path: Path):
    """Detects when modification timestamp precedes creation timestamp."""
    pdf_path = tmp_path / "inverted_time.pdf"
    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((72, 72), "Certificate of Completion")
    doc.set_metadata({
        "creationDate": "D:20250601120000Z",
        "modDate": "D:20220101120000Z",  # 3 years BEFORE creation!
    })
    doc.save(pdf_path)
    doc.close()

    report = analyze_pdf(pdf_path)
    assert any("Inverted Metadata Timestamps" in f.title for f in report.findings)
    inverted_finding = next(f for f in report.findings if "Inverted Metadata Timestamps" in f.title)
    assert inverted_finding.severity == "medium"
    assert inverted_finding.weight == 0.60


# ==============================================================================
# 4. Incremental Revisions Detection
# ==============================================================================

def test_analyze_incremental_revisions(tmp_path: Path):
    """Simulates multi-save incremental revisions by appending objects and %%EOF."""
    pdf_path = tmp_path / "revisions.pdf"
    # First save
    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((72, 72), "Original Grade: B")
    doc.save(pdf_path)
    doc.close()

    # Second save (incremental update)
    doc2 = pymupdf.open(pdf_path)
    page2 = doc2[0]
    page2.insert_text((72, 120), "Altered Grade: A+")
    doc2.save(pdf_path, incremental=True, encryption=pymupdf.PDF_ENCRYPT_KEEP)
    doc2.close()

    report = analyze_pdf(pdf_path)
    assert report.revision_count >= 2
    assert any("Multiple PDF Revisions Detected" in f.title for f in report.findings)


# ==============================================================================
# 5. Exploit Actions: JavaScript & Launch Detection
# ==============================================================================

def test_analyze_javascript_detection(tmp_path: Path):
    """Detects embedded JavaScript objects in PDF stream."""
    pdf_path = tmp_path / "js_exploit.pdf"
    # Raw stream with /JavaScript action
    pdf_content = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Action /S /JavaScript /JS (app.alert('XSS');) >>\nendobj\n"
        b"xref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000074 00000 n \n0000000120 00000 n \n"
        b"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n190\n%%EOF"
    )
    pdf_path.write_bytes(pdf_content)

    report = analyze_pdf(pdf_path)
    assert report.has_javascript is True
    assert any("Embedded JavaScript Detected" in f.title for f in report.findings)
    assert any("Automatic Execution Trigger" in f.title for f in report.findings)


def test_analyze_launch_action(tmp_path: Path):
    """Detects /Launch actions designed to execute external commands."""
    pdf_path = tmp_path / "launch.pdf"
    pdf_content = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Action /S /Launch /F (cmd.exe) >>\nendobj\n"
        b"xref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000104 00000 n \n"
        b"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n165\n%%EOF"
    )
    pdf_path.write_bytes(pdf_content)

    report = analyze_pdf(pdf_path)
    assert report.has_launch_actions is True
    assert any("Suspicious Launch Action Detected" in f.title for f in report.findings)


# ==============================================================================
# 6. Embedded Files & Suspicious URI Detection
# ==============================================================================

def test_analyze_embedded_files(tmp_path: Path):
    """Detects embedded file declarations (/EmbeddedFiles)."""
    pdf_path = tmp_path / "embedded.pdf"
    pdf_content = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles 3 0 R >> >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n"
        b"3 0 obj\n<< /Names [(payload.exe) 4 0 R] >>\nendobj\n"
        b"xref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000085 00000 n \n0000000131 00000 n \n"
        b"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n175\n%%EOF"
    )
    pdf_path.write_bytes(pdf_content)

    report = analyze_pdf(pdf_path)
    assert report.has_embedded_files is True
    assert any("Embedded File Attachment Detected" in f.title for f in report.findings)


def test_analyze_suspicious_ip_uri(tmp_path: Path):
    """Detects hyperlinks pointing to raw IP addresses or non-standard schemes."""
    pdf_path = tmp_path / "phish.pdf"
    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((72, 72), "Click here to verify your account")
    page.insert_link({
        "kind": pymupdf.LINK_URI,
        "from": pymupdf.Rect(72, 72, 200, 90),
        "uri": "http://198.51.100.45/login.php",
    })
    doc.save(pdf_path)
    doc.close()

    report = analyze_pdf(pdf_path)
    assert report.has_suspicious_uris is True
    assert any("Suspicious Hyperlink / Phishing URI" in f.title for f in report.findings)


# ==============================================================================
# 7. Microscopic / Hidden Text Layer
# ==============================================================================

def test_analyze_microscopic_text(tmp_path: Path):
    """Detects microscopic text layer with font size < 2.0 pt."""
    pdf_path = tmp_path / "microscopic.pdf"
    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((72, 72), "Normal legible text on contract", fontsize=12.0)
    page.insert_text((72, 100), "hidden steganographic terms and conditions", fontsize=1.2)
    doc.save(pdf_path)
    doc.close()

    report = analyze_pdf(pdf_path)
    assert any("Microscopic / Hidden Text Layer" in f.title for f in report.findings)


# ==============================================================================
# 8. Pipeline Integration
# ==============================================================================

def test_pipeline_integration_malicious_pdf(tmp_path: Path):
    """Tests pipeline end-to-end evaluation of a PDF containing JS exploit."""
    pdf_path = tmp_path / "exploit.pdf"
    pdf_content = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Action /S /JavaScript /JS (util.printd();) >>\nendobj\n"
        b"xref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000074 00000 n \n0000000120 00000 n \n"
        b"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n190\n%%EOF"
    )
    pdf_path.write_bytes(pdf_content)

    pipeline = ForensicPipeline()
    result = pipeline.analyze_file(pdf_path, "exploit.pdf")

    assert result.detected_mime == "application/pdf"
    assert result.risk_band == "High"
    assert any("JavaScript" in f.title for f in result.findings)


def test_pdf_findings_byte_offsets_and_categories(tmp_path: Path):
    """Verify that PDF findings contain exact byte offsets and proper taxonomy categories."""
    pdf_path = tmp_path / "offsets_test.pdf"
    content = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Action /S /JavaScript /JS (app.alert(1);) >>\nendobj\n"
        b"xref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000074 00000 n \n0000000120 00000 n \n"
        b"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n190\n%%EOF\n"
        b"%%EOF"
    )
    pdf_path.write_bytes(content)
    report = analyze_pdf(pdf_path)

    # Check for incremental revisions finding
    revision_findings = [f for f in report.findings if "Revisions" in f.title]
    assert len(revision_findings) == 1
    rf = revision_findings[0]
    assert rf.category == "structural"
    assert "eof_byte_offsets" in rf.evidence
    assert len(rf.evidence["eof_byte_offsets"]) == 2

    # Check for JavaScript finding
    js_findings = [f for f in report.findings if "JavaScript" in f.title]
    assert len(js_findings) == 1
    jf = js_findings[0]
    assert jf.category == "structural"
    assert "byte_offsets" in jf.evidence
    assert len(jf.evidence["byte_offsets"]) >= 1
    # Check that the byte offset matches the actual location of /JavaScript or /JS
    first_offset = jf.evidence["byte_offsets"][0]
    assert content[first_offset:first_offset + 3] in (b"/JS", b"/Ja")

