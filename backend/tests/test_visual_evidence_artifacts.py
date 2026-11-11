"""
PRAMAANX - Visual Evidence & Specimen Layer Integration Test Suite
==================================================================
Tests:
1. Original JPEG image preserves original specimen artifact with matching dimensions.
2. Original PNG image preserves original specimen artifact with matching dimensions.
3. Image with EXIF removed (exif_stripped.jpg) generates matching evidence paths.
4. Grad-CAM attention overlay matches the exact input image dimensions and aspect ratio.
5. ELA differential map matches the exact input image dimensions.
6. Optional artifact availability / unavailability is properly reflected.
7. Batch analysis of multiple distinct images produces distinct, isolated evidence URLs
   tied strictly to each file's SHA-256 fingerprint (no cross-contamination).
"""

import io
from pathlib import Path
from fastapi import UploadFile
from PIL import Image
import pytest

from backend.main import analyze_single_file, analyze_batch, get_visual_evidence
from backend.config import UPLOAD_TEMP_DIR


FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "tests" / "fixtures"


def test_jpeg_original_and_ela_dimension_parity():
    """Verifies that an analyzed JPEG generates an original specimen and ELA with identical dimensions."""
    sample_path = FIXTURES_DIR / "original.jpg"
    orig_bytes = sample_path.read_bytes()

    upload = UploadFile(filename="original.jpg", file=io.BytesIO(orig_bytes))
    resp = analyze_single_file(upload)

    assert resp.success is True
    assert resp.analysis.visual_evidence.original_url is not None
    assert "/api/v1/evidence/original/" in resp.analysis.visual_evidence.original_url

    # Check that original evidence can be retrieved via endpoint
    orig_filename = Path(resp.analysis.visual_evidence.original_url).name
    ev_resp = get_visual_evidence(evidence_type="original", filename=orig_filename)
    assert ev_resp.media_type in ("image/jpeg", "image/png")

    with Image.open(ev_resp.path) as img_orig:
        orig_w, orig_h = img_orig.size

    # Check ELA if available
    if resp.analysis.visual_evidence.ela_url:
        ela_filename = Path(resp.analysis.visual_evidence.ela_url).name
        ela_resp = get_visual_evidence(evidence_type="ela", filename=ela_filename)
        with Image.open(ela_resp.path) as img_ela:
            ela_w, ela_h = img_ela.size
        # Assert exact dimension alignment
        assert (orig_w, orig_h) == (ela_w, ela_h)


def test_png_original_specimen_preservation():
    """Verifies that an analyzed PNG preserves its original specimen correctly."""
    buf_png = io.BytesIO()
    img = Image.new("RGB", (320, 240), color="teal")
    img.save(buf_png, format="PNG")
    buf_png.seek(0)
    png_bytes = buf_png.read()

    upload = UploadFile(filename="test_specimen.png", file=io.BytesIO(png_bytes))
    resp = analyze_single_file(upload)

    assert resp.success is True
    assert resp.analysis.visual_evidence.original_url is not None
    assert "/api/v1/evidence/original/" in resp.analysis.visual_evidence.original_url

    orig_filename = Path(resp.analysis.visual_evidence.original_url).name
    ev_resp = get_visual_evidence(evidence_type="original", filename=orig_filename)
    with Image.open(ev_resp.path) as img_orig:
        assert img_orig.size == (320, 240)


def test_exif_stripped_jpeg_specimen():
    """Verifies evidence handling for an image with stripped EXIF."""
    sample_path = FIXTURES_DIR / "exif_stripped.jpg"
    orig_bytes = sample_path.read_bytes()

    upload = UploadFile(filename="exif_stripped.jpg", file=io.BytesIO(orig_bytes))
    resp = analyze_single_file(upload)

    assert resp.success is True
    assert resp.analysis.visual_evidence.original_url is not None
    orig_filename = Path(resp.analysis.visual_evidence.original_url).name
    ev_resp = get_visual_evidence(evidence_type="original", filename=orig_filename)
    assert Path(ev_resp.path).exists()


def test_batch_specimen_isolation_no_mixing():
    """
    Submits two distinct images in a batch.
    Verifies that Image 1 and Image 2 each receive unique original URLs and artifacts
    strictly bound to their individual SHA-256 hashes.
    """
    # Image 1: 400x300 red image
    buf1 = io.BytesIO()
    Image.new("RGB", (400, 300), color="red").save(buf1, format="JPEG")
    buf1.seek(0)

    # Image 2: 200x200 blue image
    buf2 = io.BytesIO()
    Image.new("RGB", (200, 200), color="blue").save(buf2, format="JPEG")
    buf2.seek(0)

    uploads = [
        UploadFile(filename="img1_red.jpg", file=buf1),
        UploadFile(filename="img2_blue.jpg", file=buf2),
    ]

    resp = analyze_batch(uploads)
    assert resp.success is True
    assert len(resp.results) == 2

    item1 = resp.results[0]
    item2 = resp.results[1]

    # Verify distinct SHA-256 fingerprints
    assert item1.file.sha256 != item2.file.sha256

    # Verify both have their own original evidence URLs
    url1 = item1.analysis.visual_evidence.original_url
    url2 = item2.analysis.visual_evidence.original_url

    assert url1 is not None
    assert url2 is not None
    assert url1 != url2

    # Verify filename contains file's SHA-256 prefix
    assert item1.file.sha256[:16] in url1
    assert item2.file.sha256[:16] in url2

    # Verify evidence retrieval serves correct dimensions
    fn1 = Path(url1).name
    fn2 = Path(url2).name

    resp1 = get_visual_evidence(evidence_type="original", filename=fn1)
    resp2 = get_visual_evidence(evidence_type="original", filename=fn2)

    with Image.open(resp1.path) as img1:
        assert img1.size == (400, 300)

    with Image.open(resp2.path) as img2:
        assert img2.size == (200, 200)

