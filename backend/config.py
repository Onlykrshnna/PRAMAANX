"""
PRAMAANX - Configuration Module
================================
Defines system-wide security limits, forensic file format specifications,
risk scoring boundaries, and operational paths.

Learning Notes for Student:
---------------------------
1. Centralized Configuration: Storing all limits (e.g. file sizes, risk thresholds)
   in a single configuration file prevents hardcoded 'magic numbers' across your code.
   If security policy changes (e.g. upload limit lowered), you only update it here.
2. Defense-in-Depth: Setting limits like MAX_UPLOAD_SIZE and MAX_ZIP_ENTRIES at the
   backend configuration layer stops resource exhaustion attacks (DoS) before deep
   parsing logic begins.
"""

from pathlib import Path
import os
import tempfile
from typing import Dict, Set


# ==============================================================================
# Security Limits
# ==============================================================================
# Maximum allowed size for a single uploaded file (20 Megabytes)
# Mitigates denial-of-service via huge file ingestion.
MAX_UPLOAD_SIZE_BYTES: int = 20 * 1024 * 1024  # 20 MB

# Maximum number of entries allowed inside a single ZIP archive.
# Mitigates inode/file exhaustion and entry-flooding attacks.
MAX_ZIP_ENTRIES: int = 200

# Maximum total uncompressed size permitted when extracting a ZIP archive.
# Mitigates ZIP bombs (e.g., small 50KB archive expanding into 50GB).
MAX_ZIP_UNCOMPRESSED_BYTES: int = 100 * 1024 * 1024  # 100 MB

# Maximum allowed compression ratio (uncompressed_size / compressed_size)
# Normal documents rarely exceed 5:1 or 8:1. A ratio > 10:1 on large archives indicates a bomb.
MAX_ZIP_COMPRESSION_RATIO: float = 10.0

# Maximum number of files in a single batch request
MAX_BATCH_FILES: int = 10

# Maximum aggregate size for a batch upload (100 MB)
MAX_BATCH_TOTAL_BYTES: int = 100 * 1024 * 1024


# ==============================================================================
# File Format Specifications
# ==============================================================================
# Canonical set of extensions supported by PRAMAANX
ALLOWED_EXTENSIONS: Set[str] = {
    ".jpg",
    ".jpeg",
    ".png",
    ".bmp",
    ".tiff",
    ".tif",
    ".pdf",
    ".docx",
    ".xlsx",
    ".pptx",
    ".doc",
    ".xls",
    ".ppt",
    ".zip",
}

# Mapping of canonical extensions to primary MIME types
MIME_TYPE_MAPPING: Dict[str, str] = {
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".bmp": "image/bmp",
    ".tiff": "image/tiff",
    ".tif": "image/tiff",
    ".pdf": "application/pdf",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ".doc": "application/msword",
    ".xls": "application/vnd.ms-excel",
    ".ppt": "application/vnd.ms-powerpoint",
    ".zip": "application/zip",
}

# Inverted mapping: MIME type to canonical extension
MIME_TO_CANONICAL_EXT: Dict[str, str] = {
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/bmp": ".bmp",
    "image/tiff": ".tiff",
    "application/pdf": ".pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": ".pptx",
    "application/msword": ".doc",
    "application/vnd.ms-excel": ".xls",
    "application/vnd.ms-powerpoint": ".ppt",
    "application/x-ole-storage": ".ole",
    "application/zip": ".zip",
}


# ==============================================================================
# Risk Scoring Parameters
# ==============================================================================
# Risk bands define how a 0-100 score maps to human-readable forensic severity
# Low: 0 - 30
# Medium: 31 - 60
# High: 61 - 100
RISK_BAND_LOW_MAX: int = 30
RISK_BAND_MEDIUM_MAX: int = 60
RISK_BAND_HIGH_MAX: int = 100


# ==============================================================================
# Directory and Operational Paths
# ==============================================================================
BASE_DIR: Path = Path(__file__).resolve().parent
MODELS_DIR: Path = BASE_DIR / "models"

# Safe temporary directory for processing untrusted uploads
# Uses OS temporary folder or configured environment variable
UPLOAD_TEMP_DIR: Path = Path(os.getenv("PRAMAANX_TEMP_DIR", tempfile.gettempdir())) / "pramaanx_uploads"
UPLOAD_TEMP_DIR.mkdir(parents=True, exist_ok=True)

# Persistent Evidence Vault and Database Storage (Milestone D)
DATA_DIR: Path = Path(os.getenv("PRAMAANX_DATA_DIR", BASE_DIR / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

VAULT_DIR: Path = DATA_DIR / "vault"
VAULT_DIR.mkdir(parents=True, exist_ok=True)

EVIDENCE_DIR: Path = VAULT_DIR / "evidence"
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

ARTIFACTS_DIR: Path = VAULT_DIR / "artifacts"
ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

REPORTS_DIR: Path = VAULT_DIR / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH: Path = Path(os.getenv("PRAMAANX_DB_PATH", DATA_DIR / "pramaanx.db"))

