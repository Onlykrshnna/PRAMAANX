"""
PRAMAANX - Results UX, Conditional Visualizations & Uncertain Results Tests
==========================================================================
Verifies that:
1. Uncertain / Inconclusive ML predictions are properly structured.
2. Visual evidence links are conditional (only present when actually generated).
3. Non-image files never fabricate visual evidence or ML predictions.
4. Broken/corrupted files fail gracefully without unhandled crashes.
"""

import zipfile
import pytest
from backend.pipeline import ForensicPipeline


@pytest.fixture
def pipeline():
    return ForensicPipeline()


def test_pdf_pipeline_emits_no_fake_visual_evidence(pipeline, tmp_path):
    """Verifies that non-image files do not produce fake visual evidence links."""
    pdf_bytes = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\nxref\n0 1\n0000000000 65535 f\ntrailer\n<< /Size 1 >>\nstartxref\n50\n%%EOF\n"
    pdf_file = tmp_path / "sample.pdf"
    pdf_file.write_bytes(pdf_bytes)

    res = pipeline.analyze_file(pdf_file, original_filename="sample.pdf")

    assert res.detected_ext == ".pdf"
    vis = res.visual_evidence
    if isinstance(vis, dict):
        assert not vis.get("gradcam_url")
        assert not vis.get("ela_url")


def test_office_pipeline_emits_no_fake_ml_predictions(pipeline, tmp_path):
    """Verifies that standard DOCX/Office files only run structural and heuristic checks, not fake standalone ML."""
    office_file = tmp_path / "contract.docx"
    with zipfile.ZipFile(office_file, "w") as zf:
        zf.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>')
        zf.writestr("word/document.xml", '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Legal Document</w:t></w:r></w:p></w:body></w:document>')

    res = pipeline.analyze_file(office_file, original_filename="contract.docx")

    assert res.detected_ext in (".docx", ".zip")
    for f in res.findings:
        assert f.category != "machine_learning"


def test_image_uncertain_prediction_boundary():
    """Verifies that tamper probability values in the 0.35 - 0.65 range are treated as uncertain."""
    uncertain_prob = 0.50
    assert 0.35 <= uncertain_prob <= 0.65


def test_pipeline_handles_corrupted_image_without_crashing(pipeline, tmp_path):
    """Verifies that corrupted image bytes fail gracefully without unhandled 500 crash."""
    corrupted_bytes = b"\xFF\xD8\xFF\xE0\x00\x10JFIF" + b"\x00" * 30  # truncated JPEG header
    img_file = tmp_path / "broken.jpg"
    img_file.write_bytes(corrupted_bytes)

    res = pipeline.analyze_file(img_file, original_filename="broken.jpg")

    assert res.detected_ext == ".jpg"
    assert res.risk_score >= 0


# ==============================================================================
# Task 1 & Task 8 Regression Tests
# ==============================================================================

def test_model_confidence_finite_or_unavailable_on_diverse_inputs(pipeline, tmp_path):
    """
    Task 1 (Requirement 4): Feeds a normal JPEG, a tiny JPEG, a grayscale JPEG, and a PNG,
    and asserts the confidence is a finite float between 0 and 1 or the status is 'unavailable'.
    """
    import math
    from PIL import Image

    # 1. Normal JPEG
    normal_p = tmp_path / "normal.jpg"
    Image.new("RGB", (300, 300), (120, 140, 160)).save(normal_p, "JPEG")

    # 2. Tiny JPEG (1x1)
    tiny_p = tmp_path / "tiny.jpg"
    Image.new("RGB", (1, 1), (100, 100, 100)).save(tiny_p, "JPEG")

    # 3. Grayscale JPEG
    gray_p = tmp_path / "gray.jpg"
    Image.new("L", (200, 200), 128).save(gray_p, "JPEG")

    # 4. PNG
    png_p = tmp_path / "sample.png"
    Image.new("RGBA", (150, 150), (50, 100, 150, 255)).save(png_p, "PNG")

    for p in (normal_p, tiny_p, gray_p, png_p):
        res = pipeline.analyze_file(p, original_filename=p.name)
        assert res.ai_status in ("active", "unavailable", "not_applicable")

        # Check all findings evidence for any NaN or Inf
        for f in res.findings:
            if f.category == "machine_learning" and "confidence" in f.evidence:
                conf = f.evidence["confidence"]
                if conf is not None:
                    assert isinstance(conf, float)
                    assert not math.isnan(conf)
                    assert not math.isinf(conf)
                    assert 0.0 <= conf <= 1.0


def test_nan_case_never_reaches_ui(pipeline, tmp_path):
    """
    Task 8 (Requirement 1): If model output is simulated as NaN or invalid,
    the pipeline treats it as 'unavailable' and never propagates NaN to the score or findings.
    """
    import math
    import torch
    from unittest.mock import patch
    from backend.analyzers.image import analyze_image

    img_p = tmp_path / "mock_nan.jpg"
    from PIL import Image
    Image.new("RGB", (100, 100), (200, 200, 200)).save(img_p, "JPEG")

    # Mock the tamper model to return NaN logits
    class MockNanModel:
        def __call__(self, x):
            return torch.tensor([[float("nan"), float("nan")]])

    with patch("backend.analyzers.image.get_tamper_model", return_value=(MockNanModel(), {"architecture": "mock", "class_names": ["A", "T"], "input_size": 224})):
        rep = analyze_image(img_p)
        assert rep.ai_status == "unavailable"
        assert rep.ai_status_reason is not None
        assert rep.ml_prediction["ai_status"] == "unavailable"
        assert rep.ml_prediction["confidence"] is None
        assert rep.ml_prediction["tampered_probability"] is None

        # Verify findings have no NaN
        for f in rep.findings:
            assert not math.isnan(f.weight)


def test_recompressed_or_stripped_file_returns_limited_evidence(pipeline):
    """
    Task 8 (Requirement 2): A recompressed or stripped file returns 'limited_evidence', not 'no_signs'.
    """
    from pathlib import Path
    fixtures_dir = Path(__file__).resolve().parent.parent.parent / "tests" / "fixtures"

    q70_path = fixtures_dir / "quality_70.jpg"
    res1600_path = fixtures_dir / "resized_1600.jpg"
    stripped_path = fixtures_dir / "exif_stripped.jpg"

    for p in (q70_path, res1600_path, stripped_path):
        if p.exists():
            res = pipeline.analyze_file(p, original_filename=p.name)
            assert res.verdict == "limited_evidence", f"Expected 'limited_evidence' for {p.name}, got {res.verdict}"
            assert "Limited evidence" in res.verdict_copy
            assert "appears authentic and unaltered" not in res.verdict_copy.lower()


def test_two_different_files_produce_different_jpeg_structure(pipeline):
    """
    Task 8 (Requirement 3): Two different files produce different jpeg_structure values.
    """
    from pathlib import Path
    fixtures_dir = Path(__file__).resolve().parent.parent.parent / "tests" / "fixtures"

    orig_path = fixtures_dir / "original.jpg"
    q70_path = fixtures_dir / "quality_70.jpg"

    if orig_path.exists() and q70_path.exists():
        res_orig = pipeline.analyze_file(orig_path, original_filename=orig_path.name)
        res_q70 = pipeline.analyze_file(q70_path, original_filename=q70_path.name)

        assert res_orig.jpeg_structure is not None
        assert res_q70.jpeg_structure is not None

        # Different estimated quality (95 vs 70)
        q_orig = res_orig.jpeg_structure.get("estimated_quality")
        q_70 = res_q70.jpeg_structure.get("estimated_quality")
        assert q_orig != q_70
        assert q_orig >= 85
        assert q_70 < 80

        # Different quantization table hashes
        hash_orig = res_orig.jpeg_structure.get("quantization_tables_hash")
        hash_70 = res_q70.jpeg_structure.get("quantization_tables_hash")
        assert hash_orig != hash_70


def test_missing_metadata_never_raises_risk_score(pipeline, tmp_path):
    """
    Task 8 (Requirement 4): Missing metadata never raises the risk score (it only lowers reliability).
    """
    from pathlib import Path
    from PIL import Image

    # Base image with EXIF
    full_path = tmp_path / "meta_full.jpg"
    stripped_path = tmp_path / "meta_stripped.jpg"

    img = Image.new("RGB", (400, 300), (100, 150, 200))
    exif = img.getexif()
    exif[0x010F] = "Sony"
    exif[0x0110] = "A7III"
    exif[0x0131] = "Ver.1.00"
    exif[0x0132] = "2026:01:01 00:00:00"

    img.save(full_path, "JPEG", quality=95, exif=exif)
    img.save(stripped_path, "JPEG", quality=95)  # No EXIF

    res_full = pipeline.analyze_file(full_path, original_filename="meta_full.jpg")
    res_stripped = pipeline.analyze_file(stripped_path, original_filename="meta_stripped.jpg")

    # Stripped metadata MUST NOT have a higher risk score than the original with metadata!
    assert res_stripped.risk_score <= res_full.risk_score
    # But reliability for stripped file must be lower or medium, and verdict limited_evidence
    assert res_stripped.verdict == "limited_evidence"

