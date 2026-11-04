"""
PRAMAANX Forensic Analyzers Package
===================================
Contains modular analysis engines for common metadata/binary heuristics,
images, PDFs, Office documents, and malicious structures.
"""

from .common import (
    Finding,
    AnalysisResult,
    compute_sha256,
    compute_shannon_entropy,
    detect_magic_bytes,
    check_extension_mismatch,
    compute_risk_score,
    validate_zip_safety,
    safe_extract_zip,
)

__all__ = [
    "Finding",
    "AnalysisResult",
    "compute_sha256",
    "compute_shannon_entropy",
    "detect_magic_bytes",
    "check_extension_mismatch",
    "compute_risk_score",
    "validate_zip_safety",
    "safe_extract_zip",
]

