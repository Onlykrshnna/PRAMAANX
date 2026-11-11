"""
PRAMAANX - Phase 4 Image Forensics & ML Integration Unit Tests
==============================================================
Tests EfficientNet-B0 model loading, CASIA 2.0 preprocessing, inference,
Grad-CAM attention heatmap generation, ELA error level analysis, EXIF metadata,
trailing steganography detection, pipeline routing, and static PDF ML feature extraction.
"""

import io
from pathlib import Path
from unittest.mock import patch
import numpy as np
from PIL import Image, ExifTags
import pytest
import torch

from backend.analyzers.image import (
    IMAGE_TRANSFORM,
    analyze_image,
    compute_ela,
    generate_gradcam_overlay,
    get_tamper_model,
    GradCAM,
)
from backend.analyzers.malpdf import extract_pdf_features, analyze_malicious_pdf
from backend.pipeline import ForensicPipeline
import pymupdf


# ==============================================================================
# 1. Model Loading & Preprocessing Tests (Using Authentic Checkpoint)
# ==============================================================================

def test_model_loading_and_metadata():
    """Verifies that the authentic CASIA 2.0 EfficientNet-B0 weights load properly."""
    model, meta = get_tamper_model()
    assert model is not None
    assert meta["architecture"] == "efficientnet_b0"
    assert meta["class_names"] == ["Authentic", "Tampered"]
    assert meta["input_size"] == 224
    assert pytest.approx(meta["test_accuracy"], 0.01) == 0.7137
    assert model.classifier[1].out_features == 2


def test_model_singleton_identity():
    """Verifies the model is loaded as a memory singleton (not reloaded repeatedly)."""
    m1, _ = get_tamper_model()
    m2, _ = get_tamper_model()
    assert m1 is m2


def test_preprocessing_transform_dimensions():
    """Verifies input image preprocessing transforms to (1, 3, 224, 224)."""
    img = Image.new("RGB", (640, 480), color=(100, 150, 200))
    tensor = IMAGE_TRANSFORM(img).unsqueeze(0)
    assert tensor.shape == (1, 3, 224, 224)
    assert tensor.dtype == torch.float32


# ==============================================================================
# 2. Inference & Response Structure Tests
# ==============================================================================

def test_inference_response_structure(tmp_path: Path):
    """Executes full inference on a test image and validates the response schema."""
    img_path = tmp_path / "test_sample.jpg"
    img = Image.new("RGB", (300, 300), color=(180, 180, 180))
    img.save(img_path, format="JPEG")

    report = analyze_image(img_path)
    assert report.ml_prediction is not None
    pred = report.ml_prediction

    assert pred["architecture"] == "efficientnet_b0"
    assert "CASIA 2.0" in pred["dataset"]
    assert pred["predicted_class"] in ("Authentic", "Tampered", "Inconclusive")
    assert 0.0 <= pred["confidence"] <= 1.0
    assert 0.0 <= pred["authentic_probability"] <= 1.0
    assert 0.0 <= pred["tampered_probability"] <= 1.0
    assert pytest.approx(pred["authentic_probability"] + pred["tampered_probability"], 0.001) == 1.0


# ==============================================================================
# 3. Grad-CAM Attention Heatmap Tests
# ==============================================================================

def test_gradcam_heatmap_computation():
    """Verifies Grad-CAM generates a normalized 224x224 float array."""
    model, _ = get_tamper_model()
    grad_cam = GradCAM(model)

    x = torch.randn(1, 3, 224, 224, requires_grad=True)
    try:
        cam_2d = grad_cam.generate_heatmap(x, target_class=1)
        assert cam_2d.shape == (224, 224)
        assert np.min(cam_2d) >= 0.0
        assert np.max(cam_2d) <= 1.0
    finally:
        grad_cam.release()


def test_gradcam_overlay_file_generation(tmp_path: Path):
    """Verifies that generate_gradcam_overlay writes a valid PNG overlay."""
    model, _ = get_tamper_model()
    img = Image.new("RGB", (250, 250), color=(120, 120, 120))
    x = IMAGE_TRANSFORM(img).unsqueeze(0)
    out_path = tmp_path / "gradcam_overlay.png"

    saved_path = generate_gradcam_overlay(img, model, x, out_path, target_class=1)
    assert saved_path.is_file()
    assert saved_path.stat().st_size > 0

    with Image.open(saved_path) as overlay_img:
        assert overlay_img.format == "PNG"
        assert overlay_img.size == img.size


# ==============================================================================
# 4. Error Level Analysis (ELA) Tests
# ==============================================================================

def test_ela_computation_and_metrics(tmp_path: Path):
    """Verifies ELA produces numerical statistics and an enhanced difference visualization."""
    img = Image.new("RGB", (200, 200), color=(220, 100, 50))
    ela_out = tmp_path / "ela.png"

    stats, path_out = compute_ela(img, ela_out, quality=95)
    assert path_out.is_file()
    assert "mean_error" in stats
    assert "max_error" in stats
    assert "std_error" in stats
    assert stats["quality_level"] == 95


# ==============================================================================
# 5. EXIF Metadata & Software Detection Tests
# ==============================================================================

def test_exif_editing_software_detection(tmp_path: Path):
    """Detects graphic editing software (e.g. Adobe Photoshop) embedded in EXIF."""
    img_path = tmp_path / "photoshop_sample.jpg"
    img = Image.new("RGB", (150, 150), color=(255, 255, 255))

    # Inject EXIF Software tag (0x0131 is Software)
    exif = img.getexif()
    exif[0x0131] = "Adobe Photoshop 2024 (Windows)"
    exif[0x0110] = "Canon EOS 5D"
    img.save(img_path, format="JPEG", exif=exif)

    report = analyze_image(img_path, generate_gradcam=False, generate_ela=False)
    assert any("Image Editing Software Signature" in f.title for f in report.findings)
    assert report.exif_data.get("Software") == "Adobe Photoshop 2024 (Windows)"
    assert report.exif_data.get("Model") == "Canon EOS 5D"


# ==============================================================================
# 6. Trailing Appended Data (Steganography / Payload Overlay) Tests
# ==============================================================================

def test_trailing_data_detection_jpeg(tmp_path: Path):
    """Detects trailing data injected past the JPEG EOI marker (FF D9)."""
    jpg_path = tmp_path / "stego.jpg"
    img = Image.new("RGB", (100, 100), color=(50, 50, 50))
    img.save(jpg_path, format="JPEG")

    # Append 512 bytes of disguised payload after EOI
    with open(jpg_path, "ab") as f:
        f.write(b"PK\x03\x04HIDDEN_PAYLOAD_ARCHIVE" * 16)

    report = analyze_image(jpg_path, generate_gradcam=False, generate_ela=False)
    assert any("Appended Data Beyond JPEG EOI" in f.title for f in report.findings)
    trailing_finding = next(f for f in report.findings if "Appended Data Beyond JPEG EOI" in f.title)
    assert trailing_finding.severity == "high"
    assert trailing_finding.weight >= 0.75


# ==============================================================================
# 7. Corrupted & Oversized Image Handling Tests
# ==============================================================================

def test_corrupted_image_handling(tmp_path: Path):
    """Safely handles corrupted image files without unhandled exceptions."""
    bad_img = tmp_path / "corrupt.png"
    # Valid PNG header followed by garbage
    bad_img.write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\xff" * 50)

    report = analyze_image(bad_img)
    assert any("Decoding Failure" in f.title for f in report.findings)


def test_oversized_image_rejection(tmp_path: Path):
    """Rejects images exceeding the maximum 20 MB ceiling."""
    big_img = tmp_path / "big.jpg"
    big_img.write_bytes(b"\xFF\xD8\xFF\xE0" + b"\x00" * (21 * 1024 * 1024))

    report = analyze_image(big_img)
    assert any("Size Exceeds Maximum Limit" in f.title for f in report.findings)


# ==============================================================================
# 8. Pipeline Integration & Image Routing Tests
# ==============================================================================

def test_pipeline_image_routing(tmp_path: Path):
    """Verifies that ForensicPipeline correctly routes image files to the image analyzer."""
    img_path = tmp_path / "pipeline_test.png"
    img = Image.new("RGB", (200, 200), color=(100, 200, 100))
    img.save(img_path, format="PNG")

    pipeline = ForensicPipeline()
    result = pipeline.analyze_file(img_path, "pipeline_test.png")

    assert result.detected_mime == "image/png"
    assert result.detected_ext == ".png"
    assert len(result.findings) > 0
    assert result.risk_band in ("Low", "Medium", "High")


# ==============================================================================
# 9. Malicious PDF ML Feature Extractor Tests (Section 6)
# ==============================================================================

def test_pdf_ml_feature_extraction(tmp_path: Path):
    """Verifies extraction of all 22 static structural features from a PDF."""
    pdf_path = tmp_path / "sample_features.pdf"
    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((72, 72), "Sample text for feature vector calculation")
    doc.save(pdf_path)
    doc.close()

    features = extract_pdf_features(pdf_path)
    assert len(features) == 22
    assert "entropy" in features
    assert "obj_count" in features
    assert "javascript_count" in features
    assert "page_count" in features
    assert features["page_count"] == 1.0


def test_pdf_ml_analyzer_training_pending(tmp_path: Path):
    """
    Verifies that when malpdf_xgb.json is not present, the analyzer extracts features
    and documents that model training is pending (no fake predictions).
    """
    pdf_path = tmp_path / "test.pdf"
    doc = pymupdf.open()
    doc.new_page()
    doc.save(pdf_path)
    doc.close()

    report = analyze_malicious_pdf(pdf_path)
    assert report.is_model_available is False
    assert len(report.features) == 22
    assert any("Training Pending" in f.title for f in report.findings)
    pending_finding = next(f for f in report.findings if "Training Pending" in f.title)
    assert pending_finding.weight == 0.0  # Zero artificial risk weight

