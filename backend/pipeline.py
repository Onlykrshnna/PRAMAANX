"""
PRAMAANX - Core Forensic Pipeline Orchestrator
==============================================
Coordinates the multi-phase forensic evaluation pipeline for incoming files:
1. Size and format guardrails.
2. Cryptographic SHA-256 calculation for chain of custody.
3. Shannon entropy analysis.
4. Header signature (magic byte) detection.
5. Extension mismatch / spoofing detection.
6. Archive safety screening (if ZIP).
7. Format-specific deep forensic analyzers:
   - PDF forensic analyzer (metadata, revisions, exploits, fonts, links)
   - Malicious PDF ML interface (22-feature structural vector extraction)
   - Office forensic analyzer (OpenXML, OLE, macros, template injection, hidden sheets)
   - Image forensic analyzer (EfficientNet-B0 ML inference, Grad-CAM, ELA, EXIF)
   - Recursive embedded image screening (PDF and Office documents)
8. Cumulative risk scoring via Noisy-OR combination.
"""

from pathlib import Path
import tempfile
from typing import Any, Dict, List, Optional, Union
import zipfile

import pymupdf

from backend.config import MAX_UPLOAD_SIZE_BYTES, UPLOAD_TEMP_DIR
from backend.analyzers.common import (
    AnalysisResult,
    Finding,
    check_extension_mismatch,
    compute_risk_score,
    compute_sha256,
    compute_shannon_entropy,
    detect_magic_bytes,
    determine_verdict_and_reliability,
    validate_zip_safety,
)
from backend.analyzers.pdf import analyze_pdf
from backend.analyzers.malpdf import analyze_malicious_pdf
from backend.analyzers.office import analyze_office
from backend.analyzers.image import analyze_image


class ForensicPipeline:
    """Orchestrates forensic inspections across file formats."""

    def __init__(self, max_upload_size: int = MAX_UPLOAD_SIZE_BYTES):
        self.max_upload_size = max_upload_size

    def _screen_pdf_embedded_images(
        self,
        pdf_path: Path,
        max_images: int = 3,
    ) -> List[Finding]:
        """Safely extracts and screens embedded images in a PDF using the ML tamper model."""
        findings: List[Finding] = []
        doc = None
        try:
            doc = pymupdf.open(pdf_path)
            images_checked = 0

            with tempfile.TemporaryDirectory(dir=UPLOAD_TEMP_DIR) as tmp_dir:
                for page_idx in range(doc.page_count):
                    if images_checked >= max_images:
                        break
                    page = doc[page_idx]
                    img_list = page.get_images() or []

                    for img_info in img_list:
                        if images_checked >= max_images:
                            break
                        xref = img_info[0]
                        base_img = doc.extract_image(xref)
                        if not base_img:
                            continue

                        img_bytes = base_img.get("image")
                        img_ext = base_img.get("ext", "png")
                        if not img_bytes or len(img_bytes) < 1024:
                            continue  # Skip tiny icons / bullets

                        temp_img_path = Path(tmp_dir) / f"embed_p{page_idx+1}_{xref}.{img_ext}"
                        temp_img_path.write_bytes(img_bytes)
                        images_checked += 1

                        try:
                            img_report = analyze_image(
                                temp_img_path, generate_gradcam=False, generate_ela=False
                            )
                            if (
                                img_report.ml_prediction
                                and img_report.ml_prediction.get("predicted_class") == "Tampered"
                                and img_report.ml_prediction.get("confidence", 0) >= 0.70
                            ):
                                conf = img_report.ml_prediction["confidence"]
                                findings.append(
                                    Finding(
                                        title=f"Tampered Embedded Image Detected (Page {page_idx + 1})",
                                        detail=(
                                            f"An embedded image on page {page_idx + 1} was evaluated by the "
                                            f"EfficientNet-B0 classifier as tampered ({conf * 100:.1f}% confidence). "
                                            "Tampered embedded photos are common indicators of forged ID cards, certificates, or marksheets."
                                        ),
                                        severity="high" if conf >= 0.85 else "medium",
                                        weight=0.70 if conf >= 0.85 else 0.50,
                                        evidence={"page": page_idx + 1, "ml_evidence": img_report.ml_prediction},
                                        category="machine_learning",
                                    )
                                )
                        except Exception:
                            pass
        except Exception:
            pass
        finally:
            if doc is not None:
                doc.close()

        return findings

    def _screen_office_embedded_images(
        self,
        office_path: Path,
        max_images: int = 3,
    ) -> List[Finding]:
        """Safely extracts and screens embedded media inside an Office document."""
        findings: List[Finding] = []
        try:
            if not zipfile.is_zipfile(office_path):
                return findings

            with zipfile.ZipFile(office_path) as zf:
                media_entries = [
                    n for n in zf.namelist()
                    if any(n.startswith(p) for p in ("word/media/", "xl/media/", "ppt/media/"))
                    and any(n.lower().endswith(ext) for ext in (".jpg", ".jpeg", ".png", ".bmp"))
                ]

                if not media_entries:
                    return findings

                with tempfile.TemporaryDirectory(dir=UPLOAD_TEMP_DIR) as tmp_dir:
                    for entry in media_entries[:max_images]:
                        img_data = zf.read(entry)
                        if len(img_data) < 2048:
                            continue

                        temp_img = Path(tmp_dir) / Path(entry).name
                        temp_img.write_bytes(img_data)

                        try:
                            img_report = analyze_image(
                                temp_img, generate_gradcam=False, generate_ela=False
                            )
                            if (
                                img_report.ml_prediction
                                and img_report.ml_prediction.get("predicted_class") == "Tampered"
                                and img_report.ml_prediction.get("confidence", 0) >= 0.70
                            ):
                                conf = img_report.ml_prediction["confidence"]
                                findings.append(
                                    Finding(
                                        title=f"Tampered Embedded Image in Document ({Path(entry).name})",
                                        detail=(
                                            f"Embedded document image '{Path(entry).name}' was classified as "
                                            f"tampered by EfficientNet-B0 with {conf * 100:.1f}% confidence."
                                        ),
                                        severity="high" if conf >= 0.85 else "medium",
                                        weight=0.70 if conf >= 0.85 else 0.50,
                                        evidence={"media_entry": entry, "container_path": entry, "ml_evidence": img_report.ml_prediction},
                                        category="machine_learning",
                                    )
                                )
                        except Exception:
                            pass
        except Exception:
            pass

        return findings

    def analyze_file(
        self,
        file_path: Union[str, Path],
        original_filename: Optional[str] = None,
    ) -> AnalysisResult:
        """
        Executes the integrated forensic analysis pipeline on a file.

        Args:
            file_path: Path to the target file.
            original_filename: Declared original filename (for extension spoof checks).

        Returns:
            AnalysisResult containing SHA-256, detected type, entropy, findings,
            metadata timeline, visual evidence, and cumulative tamper risk score.
        """
        path = Path(file_path).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"Target file does not exist: {path}")

        file_size = path.stat().st_size
        filename = original_filename if original_filename else path.name
        findings: List[Finding] = []
        metadata_timeline: List[Dict[str, Any]] = []
        metadata: Dict[str, Any] = {}
        visual_evidence: Dict[str, str] = {}

        # 1. Size Guardrail Check
        if file_size > self.max_upload_size:
            findings.append(
                Finding(
                    title="File Size Exceeded Security Limit",
                    detail=(
                        f"File size ({file_size / (1024*1024):.2f} MB) exceeds maximum permitted upload limit "
                        f"of {self.max_upload_size / (1024*1024):.0f} MB."
                    ),
                    severity="high",
                    weight=0.90,
                    evidence={"file_size": file_size, "limit": self.max_upload_size},
                    category="structural",
                )
            )

        # 2. Cryptographic SHA-256 Hashing (Chain of Custody)
        sha256_hash = compute_sha256(path)

        # 3. Header Magic Byte Signature Detection (Early File Identification)
        magic_result = detect_magic_bytes(path)

        # 4. Extension Mismatch / Spoofing Analysis
        mismatch_finding = check_extension_mismatch(filename, magic_result)
        if mismatch_finding:
            findings.append(mismatch_finding)

        # 5. Shannon Entropy Measurement & Contextual Assessment
        entropy = compute_shannon_entropy(path)
        is_compressed_media = (
            magic_result.detected_ext in (".jpg", ".jpeg", ".png", ".zip", ".docx", ".xlsx", ".pptx")
            or magic_result.detected_mime.startswith("image/")
            or magic_result.is_archive
        )

        # High entropy alone is normal for compressed formats (JPEG, PNG, ZIP, etc.).
        # Only flag high entropy on uncompressed files, plain streams, or executable spoofs.
        if entropy >= 7.92 and not is_compressed_media:
            findings.append(
                Finding(
                    title="Anomalously High Shannon Entropy",
                    detail=(
                        f"Calculated Shannon entropy is {entropy:.4f} (maximum 8.0). "
                        "High entropy near 8.0 in an uncompressed container indicates near-random byte distribution, "
                        "which is characteristic of heavily encrypted payloads, packed code, or hidden encrypted segments."
                    ),
                    severity="medium",
                    weight=0.45,
                    evidence={"entropy": entropy, "scale_max": 8.0, "is_compressed_media": False},
                    category="statistical",
                )
            )
        elif entropy <= 0.10 and file_size > 512:
            findings.append(
                Finding(
                    title="Anomalously Low Shannon Entropy",
                    detail=(
                        f"Calculated Shannon entropy is {entropy:.4f}. "
                        "Extremely low entropy in a non-trivial file indicates repetitive byte padding or corrupted content."
                    ),
                    severity="low",
                    weight=0.20,
                    evidence={"entropy": entropy},
                    category="statistical",
                )
            )

        # 6. Archive Safety Screening if file is a generic ZIP archive
        if magic_result.is_archive and magic_result.detected_ext == ".zip":
            is_safe, zip_findings, _ = validate_zip_safety(path)
            findings.extend(zip_findings)
            try:
                with zipfile.ZipFile(path, "r") as zf:
                    entries_list = []
                    total_uncompressed = 0
                    total_compressed = 0
                    for info in zf.infolist():
                        total_uncompressed += info.file_size
                        total_compressed += info.compress_size
                        date_str = (
                            f"{info.date_time[0]:04d}-{info.date_time[1]:02d}-{info.date_time[2]:02d} "
                            f"{info.date_time[3]:02d}:{info.date_time[4]:02d}:{info.date_time[5]:02d}"
                        )
                        entries_list.append({
                            "name": info.filename,
                            "timestamp": date_str,
                            "compress_type": "Deflate" if info.compress_type == 8 else "Store" if info.compress_type == 0 else str(info.compress_type),
                            "crc32": f"0x{info.CRC:08X}",
                            "file_size": info.file_size,
                            "compress_size": info.compress_size,
                        })
                    metadata.update({
                        "entry_count": len(entries_list),
                        "entries": entries_list,
                        "total_uncompressed_bytes": total_uncompressed,
                        "total_compressed_bytes": total_compressed,
                        "comment": zf.comment.decode("utf-8", errors="ignore") if zf.comment else None,
                    })
            except Exception:
                pass

        ai_status = "not_applicable"
        ai_status_reason = None
        jpeg_structure = None

        # 7. Format-Specific Deep Forensic Analyzers
        # Only run deep analyzers if the file is not an outright executable disguise
        if magic_result.detected_mime not in ("application/x-dosexec", "application/x-executable"):
            # A. Images (JPG, JPEG, PNG, BMP, TIFF)
            if (
                magic_result.detected_ext in (".jpg", ".jpeg", ".png", ".bmp", ".tiff")
                or magic_result.detected_mime.startswith("image/")
            ):
                try:
                    img_report = analyze_image(path)
                    findings.extend(img_report.findings)
                    metadata_timeline.extend(img_report.timeline)
                    visual_evidence.update(img_report.visual_evidence)
                    if hasattr(img_report, "metadata") and img_report.metadata:
                        metadata.update(img_report.metadata)
                    ai_status = getattr(img_report, "ai_status", "active")
                    ai_status_reason = getattr(img_report, "ai_status_reason", None)
                    jpeg_structure = getattr(img_report, "jpeg_structure", None)
                except Exception as e:
                    ai_status = "unavailable"
                    ai_status_reason = str(e)
                    findings.append(
                        Finding(
                            title="Image Forensic Engine Failure",
                            detail=f"An error occurred during image forensic evaluation: {str(e)}",
                            severity="low",
                            weight=0.0,
                            evidence={"error": str(e), "ai_status": "unavailable"},
                            category="inconclusive",
                        )
                    )

            # B. PDF Analysis & ML Structural Features
            elif magic_result.detected_ext == ".pdf":
                # Static PDF Rule Analysis
                try:
                    pdf_report = analyze_pdf(path)
                    findings.extend(pdf_report.findings)
                    metadata_timeline.extend(pdf_report.timeline)
                    if hasattr(pdf_report, "metadata") and pdf_report.metadata:
                        metadata.update(pdf_report.metadata)
                except Exception as e:
                    findings.append(
                        Finding(
                            title="PDF Forensic Engine Failure",
                            detail=f"An error occurred while inspecting PDF structure: {str(e)}",
                            severity="low",
                            weight=0.0,
                            evidence={"error": str(e)},
                            category="inconclusive",
                        )
                    )

                # ML Structural Feature Extraction & XGBoost Check
                try:
                    malpdf_report = analyze_malicious_pdf(path)
                    findings.extend(malpdf_report.findings)
                except Exception:
                    pass

                # Recursive Embedded Image Screening in PDF
                embedded_img_findings = self._screen_pdf_embedded_images(path)
                findings.extend(embedded_img_findings)

            # C. Office OpenXML & OLE Analysis (DOCX, XLSX, PPTX, DOC, XLS, PPT)
            elif (
                magic_result.detected_ext in (".docx", ".xlsx", ".pptx", ".ole")
                or magic_result.detected_mime == "application/x-ole-storage"
            ):
                try:
                    office_report = analyze_office(path)
                    findings.extend(office_report.findings)
                    metadata_timeline.extend(office_report.timeline)
                    if hasattr(office_report, "metadata") and office_report.metadata:
                        metadata.update(office_report.metadata)
                except Exception as e:
                    findings.append(
                        Finding(
                            title="Office Forensic Engine Failure",
                            detail=f"An error occurred while inspecting Office package: {str(e)}",
                            severity="low",
                            weight=0.0,
                            evidence={"error": str(e)},
                            category="inconclusive",
                        )
                    )

                # Recursive Embedded Image Screening in Office Documents
                office_img_findings = self._screen_office_embedded_images(path)
                findings.extend(office_img_findings)

        # 8. Cumulative Tamper Risk Score Computation (Noisy-OR with Missing-Metadata Safety & ML Capping)
        risk_score, risk_band = compute_risk_score(findings)

        # 9. Standardized 4-State Verdict & Specimen Reliability (Tasks 2 & 3)
        verdict, verdict_copy, reliability = determine_verdict_and_reliability(
            risk_score=risk_score,
            risk_band=risk_band,
            findings=findings,
            detected_mime=magic_result.detected_mime,
            metadata=metadata,
            ai_status=ai_status,
            jpeg_structure=jpeg_structure,
        )

        # 10. Compile Comprehensive Analysis Result
        return AnalysisResult(
            sha256=sha256_hash,
            filename=filename,
            file_size_bytes=file_size,
            detected_mime=magic_result.detected_mime,
            detected_ext=magic_result.detected_ext,
            entropy=entropy,
            risk_score=risk_score,
            risk_band=risk_band,
            findings=findings,
            metadata_timeline=metadata_timeline,
            metadata=metadata,
            visual_evidence=visual_evidence,
            plain_summary=verdict_copy,
            verdict=verdict,
            verdict_copy=verdict_copy,
            reliability=reliability,
            ai_status=ai_status,
            ai_status_reason=ai_status_reason,
            jpeg_structure=jpeg_structure,
        )
