"""
PRAMAANX - Phase 1 Forensic Core Unit Tests
============================================
Tests cryptographic hashing, Shannon entropy calculation, magic byte detection,
extension mismatch detection, Noisy-OR risk score aggregation, and ZIP safety verification.
"""

import io
import os
from pathlib import Path
import tempfile
import zipfile
import pytest
from pydantic import ValidationError

from backend.analyzers.common import (
    Finding,
    MagicDetectionResult,
    check_extension_mismatch,
    compute_risk_score,
    compute_sha256,
    compute_shannon_entropy,
    detect_magic_bytes,
    safe_extract_zip,
    validate_zip_safety,
)
from backend.pipeline import ForensicPipeline


# ==============================================================================
# 1. SHA-256 Hashing Tests
# ==============================================================================

def test_sha256_known_vector_empty():
    """Verify standard empty string SHA-256 hash."""
    empty_bytes = b""
    expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert compute_sha256(empty_bytes) == expected


def test_sha256_known_vector_text():
    """Verify SHA-256 of standard known text string."""
    text_bytes = b"hello world"
    expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    assert compute_sha256(text_bytes) == expected


def test_sha256_from_file_path(tmp_path: Path):
    """Verify SHA-256 calculation from an actual file on disk."""
    sample_file = tmp_path / "sample.txt"
    sample_file.write_bytes(b"PRAMAANX Forensic Engine Test")
    # Python hashlib sha256 of b"PRAMAANX Forensic Engine Test"
    import hashlib
    expected = hashlib.sha256(b"PRAMAANX Forensic Engine Test").hexdigest().lower()
    assert compute_sha256(sample_file) == expected


def test_sha256_from_stream():
    """Verify SHA-256 calculation from an io.BytesIO stream."""
    stream = io.BytesIO(b"streaming evidence data")
    import hashlib
    expected = hashlib.sha256(b"streaming evidence data").hexdigest().lower()
    assert compute_sha256(stream) == expected


# ==============================================================================
# 2. Shannon Entropy Tests
# ==============================================================================

def test_shannon_entropy_empty():
    """Empty data should yield 0.0 entropy."""
    assert compute_shannon_entropy(b"") == 0.0


def test_shannon_entropy_single_repeated_byte():
    """A stream of identical bytes has zero uncertainty (H=0.0)."""
    data = b"\x00" * 4096
    assert compute_shannon_entropy(data) == 0.0


def test_shannon_entropy_uniform_distribution():
    """
    All 256 byte values represented with equal probability should
    achieve theoretical maximum entropy of 8.0 bits per byte.
    """
    data = bytes(range(256)) * 16  # 4096 bytes, exactly uniform
    entropy = compute_shannon_entropy(data)
    assert pytest.approx(entropy, 0.0001) == 8.0


def test_shannon_entropy_text_file(tmp_path: Path):
    """Standard English prose typically exhibits entropy between 3.5 and 5.0."""
    text_content = b"The quick brown fox jumps over the lazy dog. Digital forensics investigation."
    sample_file = tmp_path / "prose.txt"
    sample_file.write_bytes(text_content)
    entropy = compute_shannon_entropy(sample_file)
    assert 3.5 <= entropy <= 5.0


# ==============================================================================
# 3. Magic Byte Detection Tests
# ==============================================================================

def test_detect_jpeg_magic_bytes():
    """Identify JPEG image by FF D8 FF header."""
    jpeg_header = b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00"
    res = detect_magic_bytes(jpeg_header)
    assert res.detected_mime == "image/jpeg"
    assert res.detected_ext == ".jpg"
    assert res.is_supported is True
    assert res.is_archive is False


def test_detect_png_magic_bytes():
    """Identify PNG image by 89 50 4E 47 0D 0A 1A 0A header."""
    png_header = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
    res = detect_magic_bytes(png_header)
    assert res.detected_mime == "image/png"
    assert res.detected_ext == ".png"
    assert res.is_supported is True


def test_detect_pdf_magic_bytes():
    """Identify PDF file starting with %PDF-."""
    pdf_header = b"%PDF-1.7\n1 0 obj\n<<>>\nendobj"
    res = detect_magic_bytes(pdf_header)
    assert res.detected_mime == "application/pdf"
    assert res.detected_ext == ".pdf"
    assert res.is_supported is True


def test_detect_pdf_with_scanner_preamble():
    """Identify PDF file with BOM or comments preceding %PDF- within 1024 bytes."""
    preamble = b"\xef\xbb\xbf% Scanner Pre-header comment\n" * 3 + b"%PDF-1.4\n"
    res = detect_magic_bytes(preamble)
    assert res.detected_mime == "application/pdf"
    assert res.detected_ext == ".pdf"


def test_detect_standard_zip():
    """Identify generic ZIP archive."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("notes.txt", "Some text")
    buf.seek(0)
    res = detect_magic_bytes(buf.getvalue())
    assert res.detected_mime == "application/zip"
    assert res.detected_ext == ".zip"
    assert res.is_archive is True
    assert res.is_supported is True


def test_detect_docx_openxml():
    """Identify DOCX based on Word OpenXML structure inside the ZIP."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types></Types>")
        zf.writestr("word/document.xml", "<w:document></w:document>")
    buf.seek(0)
    res = detect_magic_bytes(buf.getvalue())
    assert res.detected_mime == "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    assert res.detected_ext == ".docx"
    assert res.is_archive is True


def test_detect_xlsx_openxml():
    """Identify XLSX based on Excel OpenXML structure inside the ZIP."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types></Types>")
        zf.writestr("xl/workbook.xml", "<workbook></workbook>")
    buf.seek(0)
    res = detect_magic_bytes(buf.getvalue())
    assert res.detected_mime == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    assert res.detected_ext == ".xlsx"


def test_detect_pptx_openxml():
    """Identify PPTX based on PowerPoint OpenXML structure inside the ZIP."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types></Types>")
        zf.writestr("ppt/presentation.xml", "<presentation></presentation>")
    buf.seek(0)
    res = detect_magic_bytes(buf.getvalue())
    assert res.detected_mime == "application/vnd.openxmlformats-officedocument.presentationml.presentation"
    assert res.detected_ext == ".pptx"


def test_detect_executable_mz():
    """Identify Windows PE executable and flag it as unsupported / dangerous."""
    exe_data = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff"
    res = detect_magic_bytes(exe_data)
    assert res.detected_mime == "application/x-dosexec"
    assert res.detected_ext == ".exe"
    assert res.is_supported is False


def test_detect_empty_file():
    """Identify empty file."""
    res = detect_magic_bytes(b"")
    assert res.detected_mime == "application/x-empty"
    assert res.is_supported is False


# ==============================================================================
# 4. Extension Mismatch Tests
# ==============================================================================

def test_extension_match_success():
    """Matching extension and magic bytes produces no finding."""
    magic = MagicDetectionResult(
        detected_mime="application/pdf",
        detected_ext=".pdf",
        description="Portable Document Format",
        is_supported=True,
        is_archive=False,
    )
    finding = check_extension_mismatch("statement.pdf", magic)
    assert finding is None


def test_extension_jpeg_jpg_alias_match():
    """Normalizes .jpeg and .jpg so no false positive mismatch is raised."""
    magic = MagicDetectionResult(
        detected_mime="image/jpeg",
        detected_ext=".jpg",
        description="JPEG Image",
        is_supported=True,
        is_archive=False,
    )
    finding = check_extension_mismatch("passport_photo.jpeg", magic)
    assert finding is None


def test_extension_mismatch_executable_disguised_as_pdf():
    """Critical test: PE executable disguised as a PDF document."""
    magic = MagicDetectionResult(
        detected_mime="application/x-dosexec",
        detected_ext=".exe",
        description="Windows Executable / DLL (MZ PE)",
        is_supported=False,
        is_archive=False,
    )
    finding = check_extension_mismatch("salary_hike.pdf", magic)
    assert finding is not None
    assert finding.severity == "high"
    assert finding.weight >= 0.90
    assert "salary_hike.pdf" in finding.evidence["claimed_extension"] or finding.evidence["claimed_extension"] == ".pdf"


def test_extension_mismatch_pdf_disguised_as_jpg():
    """PDF file disguised with .jpg extension."""
    magic = MagicDetectionResult(
        detected_mime="application/pdf",
        detected_ext=".pdf",
        description="Portable Document Format",
        is_supported=True,
        is_archive=False,
    )
    finding = check_extension_mismatch("invoice.jpg", magic)
    assert finding is not None
    assert finding.severity == "high"
    assert finding.weight == 0.80


def test_extension_missing():
    """File without extension raises medium finding."""
    magic = MagicDetectionResult(
        detected_mime="image/png",
        detected_ext=".png",
        description="PNG Image",
        is_supported=True,
        is_archive=False,
    )
    finding = check_extension_mismatch("unknown_file", magic)
    assert finding is not None
    assert finding.severity == "medium"


# ==============================================================================
# 5. Finding Schema & Noisy-OR Risk Scoring Tests
# ==============================================================================

def test_finding_schema_validation():
    """Finding must validate severity values and weight boundaries [0.0, 1.0]."""
    # Valid finding
    f = Finding(
        title="Test Finding",
        detail="Explanation",
        severity="low",
        weight=0.25,
        evidence={"score": 10},
    )
    assert f.weight == 0.25

    # Weight < 0.0 must raise ValidationError
    with pytest.raises(ValidationError):
        Finding(title="T", detail="D", severity="low", weight=-0.1)

    # Weight > 1.0 must raise ValidationError
    with pytest.raises(ValidationError):
        Finding(title="T", detail="D", severity="high", weight=1.1)

    # Invalid severity string
    with pytest.raises(ValidationError):
        Finding(title="T", detail="D", severity="critical", weight=0.5)


def test_risk_score_empty_findings():
    """No findings should yield score 0 and band Low."""
    score, band = compute_risk_score([])
    assert score == 0
    assert band == "Low"


def test_risk_score_single_low():
    """Single low-weight finding (weight = 0.20 -> score 20, Low)."""
    findings = [Finding(title="F1", detail="D1", severity="low", weight=0.20)]
    score, band = compute_risk_score(findings)
    assert score == 20
    assert band == "Low"


def test_risk_score_single_medium():
    """Single medium-weight finding (weight = 0.50 -> score 50, Medium)."""
    findings = [Finding(title="F1", detail="D1", severity="medium", weight=0.50)]
    score, band = compute_risk_score(findings)
    assert score == 50
    assert band == "Medium"


def test_risk_score_single_high():
    """Single high-weight finding (weight = 0.85 -> score 85, High)."""
    findings = [Finding(title="F1", detail="D1", severity="high", weight=0.85)]
    score, band = compute_risk_score(findings)
    assert score == 85
    assert band == "High"


def test_risk_score_noisy_or_compounding():
    """
    Verify mathematical Noisy-OR compounding:
    Three medium findings with weight 0.40 each:
    1 - (1 - 0.40)^3 = 1 - (0.60)^3 = 1 - 0.216 = 0.784
    round(78.4) = 78 -> Risk Band: High.
    """
    findings = [
        Finding(title="F1", detail="D1", severity="medium", weight=0.40),
        Finding(title="F2", detail="D2", severity="medium", weight=0.40),
        Finding(title="F3", detail="D3", severity="medium", weight=0.40),
    ]
    score, band = compute_risk_score(findings)
    assert score == 78
    assert band == "High"


def test_risk_score_max_certainty():
    """A finding with weight 1.0 immediately guarantees risk score 100."""
    findings = [
        Finding(title="Minor", detail="D", severity="low", weight=0.10),
        Finding(title="Definite Tamper", detail="D", severity="high", weight=1.0),
    ]
    score, band = compute_risk_score(findings)
    assert score == 100
    assert band == "High"


# ==============================================================================
# 6. ZIP Safety Validation Tests (Zip Slip & Zip Bomb)
# ==============================================================================

def test_zip_safety_benign_archive():
    """A valid, safe archive with allowable files passes validation."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("document.pdf", b"%PDF-1.4\n benign content")
        zf.writestr("photo.png", b"\x89PNG\r\n\x1a\n benign content")
    buf.seek(0)

    is_safe, findings, safe_entries = validate_zip_safety(buf)
    assert is_safe is True
    assert len(findings) == 0
    assert "document.pdf" in safe_entries
    assert "photo.png" in safe_entries


def test_zip_safety_zip_slip_traversal():
    """Detects and blocks Zip Slip directory traversal sequences (../../)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../etc/cron.d/evil", b"* * * * * root /bin/sh")
    buf.seek(0)

    is_safe, findings, safe_entries = validate_zip_safety(buf)
    assert is_safe is False
    assert any("Zip Slip" in f.title or "Path Traversal" in f.title for f in findings)


def test_zip_safety_entry_flood():
    """Rejects archives containing more than 200 entries (entry flooding DoS)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for i in range(205):
            zf.writestr(f"item_{i}.txt", b"x")
    buf.seek(0)

    is_safe, findings, safe_entries = validate_zip_safety(buf)
    assert is_safe is False
    assert any("ZIP Entry Limit Exceeded" in f.title for f in findings)


def test_zip_safety_dangerous_executable_entry():
    """Flags archives containing dangerous executable/script extensions."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("payload.bat", b"@echo off\ncalc.exe")
    buf.seek(0)

    is_safe, findings, safe_entries = validate_zip_safety(buf)
    assert any("Executable / Dangerous File" in f.title for f in findings)


def test_zip_safety_suspicious_compression_ratio():
    """Flags archives containing members with abnormal compression ratios (>10:1)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("ratio_bomb.txt", b"\x00" * 1_000_000)
    buf.seek(0)

    is_safe, findings, safe_entries = validate_zip_safety(buf)
    assert any("Compression Ratio" in f.title for f in findings)


def test_zip_safety_total_uncompressed_limit():
    """Rejects archives exceeding total uncompressed limit of 100 MB."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("bomb_105mb.txt", b"\x00" * (105 * 1024 * 1024))
    buf.seek(0)

    is_safe, findings, safe_entries = validate_zip_safety(buf)
    assert is_safe is False
    assert any("Decompression Bomb" in f.title or "Compression Ratio" in f.title for f in findings)


def test_safe_extract_zip(tmp_path: Path):
    """Verifies that safe_extract_zip unpacks safe entries to the destination directory."""
    zip_path = tmp_path / "valid.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("doc1.pdf", b"%PDF-1.4 content")
        zf.writestr("pic1.jpg", b"\xFF\xD8\xFF content")

    dest_dir = tmp_path / "extracted"
    extracted = safe_extract_zip(zip_path, dest_dir)
    assert len(extracted) == 2
    assert (dest_dir / "doc1.pdf").is_file()
    assert (dest_dir / "pic1.jpg").is_file()


# ==============================================================================
# 7. Pipeline Integration Test
# ==============================================================================

def test_pipeline_integration_benign_png(tmp_path: Path):
    """Tests the complete end-to-end Phase 1 pipeline on a benign PNG."""
    png_path = tmp_path / "sample.png"
    # Valid PNG header + benign data
    png_path.write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\x00" * 100)

    pipeline = ForensicPipeline()
    result = pipeline.analyze_file(png_path, "sample.png")

    assert len(result.sha256) == 64
    assert result.detected_mime == "image/png"
    assert result.detected_ext == ".png"
    assert result.risk_score <= 30
    assert result.risk_band == "Low"


def test_pipeline_integration_executable_spoof(tmp_path: Path):
    """Tests pipeline detection when an executable is named report.pdf."""
    fake_pdf = tmp_path / "report.pdf"
    # Windows PE header (MZ)
    fake_pdf.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00" + b"\x00" * 200)

    pipeline = ForensicPipeline()
    result = pipeline.analyze_file(fake_pdf, "report.pdf")

    assert result.detected_mime == "application/x-dosexec"
    assert result.detected_ext == ".exe"
    assert any("Disguise" in f.title or "Mismatch" in f.title for f in result.findings)
    assert result.risk_score >= 61
    assert result.risk_band == "High"

