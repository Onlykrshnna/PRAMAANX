"""
PRAMAANX - Core Forensic Pipeline Orchestrator
==============================================
Coordinates the forensic evaluation pipeline for incoming files:
1. Size and format guardrails.
2. Cryptographic SHA-256 calculation for chain of custody.
3. Header signature (magic byte) detection.
4. Extension mismatch / spoofing detection.
5. Shannon entropy analysis.
6. Archive safety screening (if ZIP).
7. Cumulative risk scoring via Noisy-OR combination.

As future phases are approved, format-specific analyzers (PDF, Office, Image, ML)
plug into this orchestrator cleanly.
"""

from pathlib import Path
from typing import List, Optional, Union
import io

from backend.config import MAX_UPLOAD_SIZE_BYTES
from backend.analyzers.common import (
    AnalysisResult,
    Finding,
    check_extension_mismatch,
    compute_risk_score,
    compute_sha256,
    compute_shannon_entropy,
    detect_magic_bytes,
    validate_zip_safety,
)


class ForensicPipeline:
    """Orchestrates forensic inspections across file formats."""

    def __init__(self, max_upload_size: int = MAX_UPLOAD_SIZE_BYTES):
        self.max_upload_size = max_upload_size

    def analyze_file(
        self,
        file_path: Union[str, Path],
        original_filename: Optional[str] = None,
    ) -> AnalysisResult:
        """
        Executes the Phase 1 forensic baseline analysis on a file.

        Args:
            file_path: Path to the stored file.
            original_filename: Original user-declared filename (for extension spoof checks).

        Returns:
            AnalysisResult containing SHA-256, detected type, entropy, findings, and risk score.
        """
        path = Path(file_path).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"Target file does not exist: {path}")

        file_size = path.stat().st_size
        filename = original_filename if original_filename else path.name
        findings: List[Finding] = []

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
                )
            )

        # 2. Cryptographic SHA-256 Hashing
        sha256_hash = compute_sha256(path)

        # 3. Shannon Entropy Measurement
        entropy = compute_shannon_entropy(path)
        if entropy >= 7.90:
            findings.append(
                Finding(
                    title="Anomalously High Shannon Entropy",
                    detail=(
                        f"Calculated Shannon entropy is {entropy:.4f} (maximum 8.0). "
                        "An entropy score near 8.0 signifies near-random byte distribution, which is characteristic "
                        "of heavily encrypted data, packed malicious code, or high-density steganographic payloads."
                    ),
                    severity="medium",
                    weight=0.50,
                    evidence={"entropy": entropy, "scale_max": 8.0},
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
                )
            )

        # 4. Header Magic Byte Signature Detection
        magic_result = detect_magic_bytes(path)

        # 5. Extension Mismatch / Spoofing Analysis
        mismatch_finding = check_extension_mismatch(filename, magic_result)
        if mismatch_finding:
            findings.append(mismatch_finding)

        # 6. Archive Safety Screening if file is a ZIP archive
        if magic_result.is_archive and magic_result.detected_ext == ".zip":
            is_safe, zip_findings, _ = validate_zip_safety(path)
            findings.extend(zip_findings)

        # 7. Tamper Risk Score Computation (Noisy-OR)
        risk_score, risk_band = compute_risk_score(findings)

        # 8. Compile Comprehensive Analysis Result
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
            metadata_timeline=[],
            visual_evidence={},
            plain_summary="",
        )

