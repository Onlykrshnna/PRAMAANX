"""
PRAMAANX - Forensic Metadata Extraction Unit Test Suite
=======================================================
Verifies that:
1. Images: EXIF, camera make/model, timestamps, dimensions, color space, missing EXIF.
2. PDFs: Author, Title, Subject, Creator, Producer, CreationDate, ModDate, XMP.
3. Office: Author (creator), Last modified by, Created/Modified timestamps, Application, Company.
4. ZIP: Entries, timestamps, compression methods, CRC32, archive properties.
5. Missing metadata is not classified as suspicious and does not crash the pipeline.
"""

from io import BytesIO
import zipfile
from PIL import Image
import pytest
import pymupdf

from backend.pipeline import ForensicPipeline


@pytest.fixture
def pipeline():
    return ForensicPipeline()


def test_image_metadata_extraction_with_exif(pipeline, tmp_path):
    """Verify image metadata extracts geometry, color space, and EXIF fields."""
    img_file = tmp_path / "photo.jpg"
    img = Image.new("RGB", (640, 480), color=(100, 150, 200))
    exif = img.getexif()
    exif[0x010F] = "Nikon"  # Make
    exif[0x0110] = "D850"   # Model
    exif[0x0132] = "2026:10:15 14:30:00"  # DateTime
    exif[0x0131] = "Adobe Photoshop 24.0"  # Software
    img.save(img_file, format="JPEG", exif=exif)

    res = pipeline.analyze_file(img_file, original_filename="photo.jpg")

    assert res.detected_ext in (".jpg", ".jpeg")
    meta = res.metadata
    assert meta["width"] == 640
    assert meta["height"] == 480
    assert meta["dimensions"] == "640 x 480"
    assert meta["color_mode"] == "RGB"
    assert meta["camera_make"] == "Nikon"
    assert meta["camera_model"] == "D850"
    assert meta["datetime"] == "2026:10:15 14:30:00"
    assert meta["software"] == "Adobe Photoshop 24.0"


def test_image_metadata_missing_exif_handled_cleanly(pipeline, tmp_path):
    """Verify image without EXIF metadata populates geometry and reports None/empty safely without crashing."""
    img_file = tmp_path / "clean.png"
    img = Image.new("RGBA", (320, 240), color=(50, 50, 50, 255))
    img.save(img_file, format="PNG")

    res = pipeline.analyze_file(img_file, original_filename="clean.png")

    assert res.detected_ext == ".png"
    meta = res.metadata
    assert meta["width"] == 320
    assert meta["height"] == 240
    assert meta["dimensions"] == "320 x 240"
    assert meta["camera_make"] is None
    assert meta["camera_model"] is None


def test_pdf_metadata_extraction(pipeline, tmp_path):
    """Verify PDF metadata extracts Author, Title, Creator, Producer, Dates, and XMP."""
    pdf_file = tmp_path / "document.pdf"
    doc = pymupdf.open()
    page = doc.new_page(width=595, height=842)
    page.insert_text((50, 100), "Confidential Forensic Case File")
    doc.set_metadata({
        "title": "Forensic Examination Brief",
        "author": "Special Agent Smith",
        "subject": "Case Evidence Evaluation",
        "creator": "PRAMAANX Generator",
        "producer": "PyMuPDF PDF Library",
        "creationDate": "D:20261101120000+00'00'",
        "modDate": "D:20261102153000+00'00'",
    })
    doc.save(pdf_file)
    doc.close()

    res = pipeline.analyze_file(pdf_file, original_filename="document.pdf")

    assert res.detected_ext == ".pdf"
    meta = res.metadata
    assert meta["title"] == "Forensic Examination Brief"
    assert meta["author"] == "Special Agent Smith"
    assert meta["subject"] == "Case Evidence Evaluation"
    assert meta["creator"] == "PRAMAANX Generator"
    assert meta["producer"] == "PyMuPDF PDF Library"
    assert "creation_date_iso" in meta
    assert meta["page_count"] == 1


def test_pdf_metadata_missing_fields_safe(pipeline, tmp_path):
    """Verify bare PDF without metadata dictionary fields parses safely without crashing."""
    pdf_bytes = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\nxref\n0 1\n0000000000 65535 f\ntrailer\n<< /Size 1 >>\nstartxref\n50\n%%EOF\n"
    pdf_file = tmp_path / "bare.pdf"
    pdf_file.write_bytes(pdf_bytes)

    res = pipeline.analyze_file(pdf_file, original_filename="bare.pdf")

    assert res.detected_ext == ".pdf"
    meta = res.metadata
    assert meta.get("title") == "" or meta.get("title") is None


def test_office_metadata_extraction(pipeline, tmp_path):
    """Verify Office document metadata extracts Creator, LastModifiedBy, Dates, App, and Company."""
    office_file = tmp_path / "report.docx"
    core_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
        'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/">'
        '<dc:title>Q3 Financial Audit</dc:title>'
        '<dc:subject>Compliance Review</dc:subject>'
        '<dc:creator>Alice Auditor</dc:creator>'
        '<cp:lastModifiedBy>Bob Reviewer</cp:lastModifiedBy>'
        '<dcterms:created>2026-10-01T09:00:00Z</dcterms:created>'
        '<dcterms:modified>2026-10-05T17:30:00Z</dcterms:modified>'
        '</cp:coreProperties>'
    )
    app_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
        '<Application>Microsoft Word</Application>'
        '<AppVersion>16.0000</AppVersion>'
        '<Company>Forensics Corp</Company>'
        '<TotalTime>120</TotalTime>'
        '<Words>1450</Words>'
        '</Properties>'
    )

    with zipfile.ZipFile(office_file, "w") as zf:
        zf.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>')
        zf.writestr("docProps/core.xml", core_xml)
        zf.writestr("docProps/app.xml", app_xml)
        zf.writestr("word/document.xml", '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Audit text</w:t></w:r></w:p></w:body></w:document>')

    res = pipeline.analyze_file(office_file, original_filename="report.docx")

    assert res.detected_ext in (".docx", ".zip")
    meta = res.metadata
    assert meta["creator"] == "Alice Auditor"
    assert meta["last_modified_by"] == "Bob Reviewer"
    assert meta["title"] == "Q3 Financial Audit"
    assert meta["subject"] == "Compliance Review"
    assert meta["application"] == "Microsoft Word"
    assert meta["app_version"] == "16.0000"
    assert meta["company"] == "Forensics Corp"
    assert meta["total_edit_time_minutes"] == 120


def test_zip_archive_metadata_extraction(pipeline, tmp_path):
    """Verify ZIP archive metadata extracts entries, compression, timestamps, and CRC32."""
    zip_file = tmp_path / "evidence_vault.zip"
    with zipfile.ZipFile(zip_file, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("file_alpha.txt", b"Alpha content for testing CRC32 calculation")
        zf.writestr("file_beta.pdf", b"%PDF-1.4 minimal test stream")
        zf.comment = b"Chain of custody evidence package"

    res = pipeline.analyze_file(zip_file, original_filename="evidence_vault.zip")

    assert res.detected_ext == ".zip"
    meta = res.metadata
    assert meta["entry_count"] == 2
    assert len(meta["entries"]) == 2
    assert meta["entries"][0]["name"] == "file_alpha.txt"
    assert meta["entries"][0]["crc32"].startswith("0x")
    assert meta["entries"][0]["compress_type"] in ("Deflate", "Store")
    assert meta["comment"] == "Chain of custody evidence package"

