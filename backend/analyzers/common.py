r"""
PRAMAANX - Common Forensic Utilities and Data Models
====================================================
Contains core forensic primitives:
- Finding and AnalysisResult data schemas
- Noisy-OR tamper risk score calculation
- Cryptographic SHA-256 calculation
- Shannon entropy measurement
- Pure-Python deterministic magic-byte detection
- Extension spoofing / mismatch detection
- ZIP archive safety validation (Zip Slip, Zip Bomb, and nested hazards)

================================================================================
CYBERSECURITY STUDENT LEARNING GUIDE
================================================================================
1. Why Magic Bytes instead of File Extensions?
   An attacker can rename `malware.exe` to `invoice.pdf` or `photo.jpg`. The operating
   system or email filter might treat it harmlessly based on the name, but when an
   unsuspecting user opens it, an exploit executes. Magic bytes (file signatures)
   are fixed byte sequences located at the very start of a file header defined by
   international file format specifications. They reveal what a file *actually* is,
   regardless of what its extension claims.

2. Why Shannon Entropy?
   Claude Shannon (1948) defined entropy as the measure of information uncertainty
   or randomness in a byte stream.
   Formula: H(X) = - SUM( p(x) * log2(p(x)) )
   - For 8-bit bytes, entropy ranges from 0.0 (all bytes identical, e.g., 0x00)
     to 8.0 (perfectly uniform randomness).
   - Plain text typically has an entropy of 3.5 to 5.0.
   - Compressed files (ZIP, JPEG) usually have an entropy of 7.0 to 7.8.
   - Highly encrypted data, steganographic payloads, packed binaries, or XOR-obfuscated
     shellcode frequently push entropy to 7.9 - 8.0.
   - An unexpectedly high entropy block in an otherwise uncompressed document is an
     immediate red flag for hidden payloads.

3. Why Noisy-OR Risk Scoring?
   If an image has 3 medium findings (e.g., weights 0.4, 0.4, 0.4), simply averaging
   them would give 0.4 (40/100, medium). But in digital forensics, multiple independent
   suspicious indicators compound the probability of tampering.
   The formula: Risk = round( (1 - PRODUCT(1 - w_i)) * 100 )
   models the probability that AT LEAST ONE finding indicates genuine tampering,
   assuming each finding acts as an independent indicator.
   Example:
     w1 = 0.4, w2 = 0.4, w3 = 0.4
     Risk = 1 - (0.6 * 0.6 * 0.6) = 1 - 0.216 = 0.784 -> 78/100 (High Risk!)
   This reflects real-world forensic compounding without arbitrary hardcoded scores.

4. What is Zip Slip and a Zip Bomb?
   - Zip Slip (Path Traversal): An archive entry can have a filename like
     `../../../../etc/shadow` or `..\..\Windows\System32\evil.dll`. When a naive
     extractor unpacks it, it overwrites critical system files.
   - Zip Bomb: A tiny archive (e.g., 42 KB) that uses recursive or high-ratio
     compression to expand into 4.5 Petabytes of null bytes, crashing the host server
     (Denial of Service).
   We inspect archive metadata *before* extraction to neutralize both attacks.
================================================================================
"""

import hashlib
import io
import math
import os
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Set, Tuple, Union
import zipfile

from pydantic import BaseModel, Field, field_validator

from backend.config import (
    ALLOWED_EXTENSIONS,
    MAX_ZIP_COMPRESSION_RATIO,
    MAX_ZIP_ENTRIES,
    MAX_ZIP_UNCOMPRESSED_BYTES,
    MIME_TO_CANONICAL_EXT,
    MIME_TYPE_MAPPING,
    RISK_BAND_LOW_MAX,
    RISK_BAND_MEDIUM_MAX,
)


# ==============================================================================
# Core Finding Schema & Data Models
# ==============================================================================

class Finding(BaseModel):
    """
    Standardized forensic finding emitted by any analyzer in PRAMAANX.

    Attributes:
        title: Short descriptive title of the forensic finding.
        detail: In-depth technical explanation of what was observed.
        severity: Risk level ('low', 'medium', or 'high').
        weight: Normalized numerical weight between 0.0 and 1.0.
        evidence: Optional dictionary of raw forensic data/measurements.
    """
    title: str = Field(..., description="Short descriptive title of the finding")
    detail: str = Field(..., description="Detailed technical explanation of the finding")
    severity: Literal["low", "medium", "high"] = Field(..., description="Severity category")
    weight: float = Field(..., ge=0.0, le=1.0, description="Risk weight between 0.0 and 1.0")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Supporting forensic evidence")

    @field_validator("weight")
    @classmethod
    def validate_weight(cls, v: float) -> float:
        """Ensure weight stays strictly within [0.0, 1.0]."""
        if not (0.0 <= v <= 1.0):
            raise ValueError(f"Weight must be between 0.0 and 1.0, got {v}")
        return float(v)


class MagicDetectionResult(BaseModel):
    """Result of pure-python magic byte analysis."""
    detected_mime: str
    detected_ext: str
    description: str
    is_supported: bool
    is_archive: bool


class AnalysisResult(BaseModel):
    """Standardized top-level analysis output for a scanned file."""
    sha256: str
    filename: str
    file_size_bytes: int
    detected_mime: str
    detected_ext: str
    entropy: float
    risk_score: int
    risk_band: Literal["Low", "Medium", "High"]
    findings: List[Finding]
    metadata_timeline: List[Dict[str, Any]] = Field(default_factory=list)
    visual_evidence: Dict[str, str] = Field(default_factory=dict)
    plain_summary: str = ""


# ==============================================================================
# Cryptographic Hashing
# ==============================================================================

def compute_sha256(
    file_source: Union[str, Path, bytes, io.BytesIO, io.BufferedReader],
    chunk_size: int = 65536,
) -> str:
    """
    Computes SHA-256 cryptographic digest of a file path, byte array, or stream.

    Why this matters in Digital Forensics:
    -------------------------------------
    SHA-256 guarantees evidence integrity (Chain of Custody). If even a single
    bit of an uploaded document is altered, the SHA-256 changes completely (avalanche effect).
    Using chunked reading (64 KB) ensures large 20 MB files do not cause memory spikes.

    Args:
        file_source: Path to file, raw bytes, or readable binary stream.
        chunk_size: Block size in bytes for reading (default: 64 KB).

    Returns:
        64-character lowercase hexadecimal SHA-256 hash string.
    """
    hasher = hashlib.sha256()

    if isinstance(file_source, bytes):
        hasher.update(file_source)
        return hasher.hexdigest().lower()

    if isinstance(file_source, (str, Path)):
        path = Path(file_source)
        if not path.is_file():
            raise FileNotFoundError(f"File not found for SHA-256 calculation: {path}")
        with open(path, "rb") as f:
            while chunk := f.read(chunk_size):
                hasher.update(chunk)
        return hasher.hexdigest().lower()

    # Stream-like object
    pos = file_source.tell() if hasattr(file_source, "tell") else None
    try:
        while chunk := file_source.read(chunk_size):
            hasher.update(chunk)
    finally:
        if pos is not None and hasattr(file_source, "seek"):
            file_source.seek(pos)

    return hasher.hexdigest().lower()


# ==============================================================================
# Shannon Entropy
# ==============================================================================

def compute_shannon_entropy(
    file_source: Union[str, Path, bytes, io.BytesIO, io.BufferedReader],
    chunk_size: int = 65536,
) -> float:
    """
    Calculates Shannon Entropy over the byte distribution of the input.

    Formula:
        H(X) = - SUM_{i=0}^{255} p(i) * log2( p(i) )
        where p(i) is the relative frequency of byte value i.

    Forensic Interpretation:
        0.00 - 1.00: Extremely low entropy (e.g. repeated null padding)
        1.00 - 5.00: Uncompressed text, code, standard XML
        5.00 - 7.20: Executables, mixed structured data
        7.20 - 7.80: Standard compressed media (JPEG, PNG, Deflate streams)
        7.80 - 8.00: Near-random: high encryption, encrypted payloads, packed steganography

    Args:
        file_source: Path, bytes, or binary stream.
        chunk_size: Block size for chunked streaming.

    Returns:
        Float value between 0.0 and 8.0 rounded to 4 decimal places.
    """
    byte_counts = [0] * 256
    total_bytes = 0

    if isinstance(file_source, bytes):
        total_bytes = len(file_source)
        for b in file_source:
            byte_counts[b] += 1
    elif isinstance(file_source, (str, Path)):
        path = Path(file_source)
        if not path.is_file():
            raise FileNotFoundError(f"File not found for entropy calculation: {path}")
        with open(path, "rb") as f:
            while chunk := f.read(chunk_size):
                total_bytes += len(chunk)
                for b in chunk:
                    byte_counts[b] += 1
    else:
        pos = file_source.tell() if hasattr(file_source, "tell") else None
        try:
            while chunk := file_source.read(chunk_size):
                total_bytes += len(chunk)
                for b in chunk:
                    byte_counts[b] += 1
        finally:
            if pos is not None and hasattr(file_source, "seek"):
                file_source.seek(pos)

    if total_bytes == 0:
        return 0.0

    entropy = 0.0
    for count in byte_counts:
        if count > 0:
            p_i = count / total_bytes
            entropy -= p_i * math.log2(p_i)

    return round(float(entropy), 4)


# ==============================================================================
# Magic Byte Detection
# ==============================================================================

# Magic byte signatures for supported and high-risk formats
# Stored as (signature_bytes, offset)
JPEG_SIG = b"\xFF\xD8\xFF"
PNG_SIG = b"\x89PNG\r\n\x1a\n"
PDF_SIG = b"%PDF-"
ZIP_SIG = b"PK\x03\x04"
ZIP_EMPTY_SIG = b"PK\x05\x06"
ZIP_SPANNED_SIG = b"PK\x07\x08"

# Suspicious / Disguised formats
EXE_MZ_SIG = b"MZ"  # Windows PE binary
ELF_SIG = b"\x7FELF"  # Linux ELF binary
OLE_CFBF_SIG = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"  # Legacy MS Office (DOC/XLS/PPT 97-2003)


def _read_header_bytes(
    file_source: Union[str, Path, bytes, io.BytesIO, io.BufferedReader],
    length: int = 2048,
) -> bytes:
    """Safely reads the initial `length` bytes without consuming the whole file."""
    if isinstance(file_source, bytes):
        return file_source[:length]
    if isinstance(file_source, (str, Path)):
        path = Path(file_source)
        if not path.is_file():
            raise FileNotFoundError(f"File not found: {path}")
        with open(path, "rb") as f:
            return f.read(length)

    pos = file_source.tell() if hasattr(file_source, "tell") else None
    try:
        header = file_source.read(length)
    finally:
        if pos is not None and hasattr(file_source, "seek"):
            file_source.seek(pos)
    return header


def _inspect_openxml_archive(
    file_source: Union[str, Path, bytes, io.BytesIO, io.BufferedReader],
) -> Tuple[str, str, str]:
    """
    Inspects a ZIP-based file to differentiate generic ZIP from Microsoft Office OpenXML:
    - DOCX: contains 'word/document.xml' or 'word/'
    - XLSX: contains 'xl/workbook.xml' or 'xl/'
    - PPTX: contains 'ppt/presentation.xml' or 'ppt/'

    Returns:
        Tuple of (mime_type, canonical_ext, description)
    """
    try:
        if isinstance(file_source, bytes):
            zf = zipfile.ZipFile(io.BytesIO(file_source))
        elif isinstance(file_source, (str, Path)):
            zf = zipfile.ZipFile(file_source)
        else:
            pos = file_source.tell() if hasattr(file_source, "tell") else None
            try:
                zf = zipfile.ZipFile(file_source)
            finally:
                if pos is not None and hasattr(file_source, "seek"):
                    file_source.seek(pos)

        with zf:
            namelist = set(zf.namelist())

            # Check for Microsoft Word (.docx)
            if any(name.startswith("word/") for name in namelist) or "word/document.xml" in namelist:
                return (
                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    ".docx",
                    "Microsoft Word Document (OpenXML)",
                )

            # Check for Microsoft Excel (.xlsx)
            if any(name.startswith("xl/") for name in namelist) or "xl/workbook.xml" in namelist:
                return (
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    ".xlsx",
                    "Microsoft Excel Spreadsheet (OpenXML)",
                )

            # Check for Microsoft PowerPoint (.pptx)
            if any(name.startswith("ppt/") for name in namelist) or "ppt/presentation.xml" in namelist:
                return (
                    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                    ".pptx",
                    "Microsoft PowerPoint Presentation (OpenXML)",
                )

            return ("application/zip", ".zip", "Standard ZIP Archive")
    except Exception:
        # If ZIP inspection fails, fall back to generic ZIP
        return ("application/zip", ".zip", "Standard ZIP Archive")


def detect_magic_bytes(
    file_source: Union[str, Path, bytes, io.BytesIO, io.BufferedReader],
) -> MagicDetectionResult:
    """
    Identifies the genuine file type by inspecting file header signatures (magic bytes).

    Forensic Rationale:
    -------------------
    Attackers often disguise payloads by changing file extensions (e.g. `trojan.exe` -> `contract.pdf`).
    This detector inspects raw bytes directly at the header to determine true format.
    According to the PDF specification (ISO 32000-1), `%PDF-` may appear anywhere within
    the first 1024 bytes to accommodate scanner headers or BOM markers.

    Returns:
        MagicDetectionResult with detected MIME type, canonical extension, and support status.
    """
    header = _read_header_bytes(file_source, length=2048)

    if not header:
        return MagicDetectionResult(
            detected_mime="application/x-empty",
            detected_ext="",
            description="Empty file (zero bytes)",
            is_supported=False,
            is_archive=False,
        )

    # 1. JPEG Check: starts with FF D8 FF
    if header.startswith(JPEG_SIG):
        return MagicDetectionResult(
            detected_mime="image/jpeg",
            detected_ext=".jpg",
            description="JPEG Image",
            is_supported=True,
            is_archive=False,
        )

    # 2. PNG Check: starts with 89 50 4E 47 0D 0A 1A 0A
    if header.startswith(PNG_SIG):
        return MagicDetectionResult(
            detected_mime="image/png",
            detected_ext=".png",
            description="Portable Network Graphics (PNG)",
            is_supported=True,
            is_archive=False,
        )

    # 3. PDF Check: '%PDF-' within the first 1024 bytes (per ISO 32000-1 spec)
    if PDF_SIG in header[:1024]:
        return MagicDetectionResult(
            detected_mime="application/pdf",
            detected_ext=".pdf",
            description="Portable Document Format (PDF)",
            is_supported=True,
            is_archive=False,
        )

    # 4. ZIP or OpenXML Office Check: starts with PK\x03\x04, PK\x05\x06, or PK\x07\x08
    if header.startswith(ZIP_SIG) or header.startswith(ZIP_EMPTY_SIG) or header.startswith(ZIP_SPANNED_SIG):
        mime, ext, desc = _inspect_openxml_archive(file_source)
        return MagicDetectionResult(
            detected_mime=mime,
            detected_ext=ext,
            description=desc,
            is_supported=True,
            is_archive=True,
        )

    # 5. Legacy OLE CFBF Check: \xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1 (Old DOC/XLS/PPT 97-2003)
    if header.startswith(OLE_CFBF_SIG):
        return MagicDetectionResult(
            detected_mime="application/x-ole-storage",
            detected_ext=".ole",
            description="Legacy Microsoft Compound File Binary Format (OLE CFBF)",
            is_supported=False,
            is_archive=False,
        )

    # 6. Windows PE Executable Check: 'MZ' header
    if header.startswith(EXE_MZ_SIG):
        return MagicDetectionResult(
            detected_mime="application/x-dosexec",
            detected_ext=".exe",
            description="Windows Executable / DLL (MZ PE)",
            is_supported=False,
            is_archive=False,
        )

    # 7. Linux ELF Executable Check: '\x7FELF'
    if header.startswith(ELF_SIG):
        return MagicDetectionResult(
            detected_mime="application/x-executable",
            detected_ext=".elf",
            description="Linux ELF Executable / Shared Object",
            is_supported=False,
            is_archive=False,
        )

    # Fallback: Unknown binary or plain text
    return MagicDetectionResult(
        detected_mime="application/octet-stream",
        detected_ext="",
        description="Unknown Binary Data or Unrecognized Format",
        is_supported=False,
        is_archive=False,
    )


# ==============================================================================
# Extension Mismatch Detection
# ==============================================================================

def check_extension_mismatch(
    filename: str,
    detected: MagicDetectionResult,
) -> Optional[Finding]:
    """
    Detects if the file's declared extension contradicts its actual binary signature.

    Cybersecurity Context:
    ----------------------
    Extension spoofing is an evasion technique used by attackers to bypass gateway
    email filters or social engineer victims into double-clicking malicious payloads.
    Example: An attacker names a payload 'resume.pdf.exe' or 'resume.pdf' with MZ bytes.

    Args:
        filename: Declared original filename (e.g. 'report.pdf').
        detected: MagicDetectionResult from detect_magic_bytes.

    Returns:
        Finding object if a mismatch is detected, otherwise None.
    """
    declared_ext = Path(filename).suffix.lower()

    # Normalization: .jpeg and .jpg are functionally equivalent
    normalized_declared = ".jpg" if declared_ext == ".jpeg" else declared_ext
    normalized_detected = ".jpg" if detected.detected_ext == ".jpeg" else detected.detected_ext

    # If file has no extension at all
    if not declared_ext:
        return Finding(
            title="Missing File Extension",
            detail=f"The file '{filename}' has no extension. Binary analysis detected it as {detected.description} ({detected.detected_mime}).",
            severity="medium",
            weight=0.35,
            evidence={
                "filename": filename,
                "detected_mime": detected.detected_mime,
                "detected_extension": detected.detected_ext,
            },
        )

    # If declared is supported, but magic bytes indicate something completely different
    if normalized_declared != normalized_detected:
        # High-severity case: An executable or unknown binary masquerading as a document/image
        if detected.detected_mime in ("application/x-dosexec", "application/x-executable", "application/octet-stream"):
            return Finding(
                title="Critical File Type Disguise (Executable / Unrecognized Payload)",
                detail=(
                    f"The file claims extension '{declared_ext}', but raw header inspection reveals it is "
                    f"actually a {detected.description} ({detected.detected_mime}). "
                    "This strongly indicates an attempt to mask malicious executable code as a benign document."
                ),
                severity="high",
                weight=0.95,
                evidence={
                    "claimed_extension": declared_ext,
                    "detected_mime": detected.detected_mime,
                    "detected_extension": detected.detected_ext,
                },
            )

        # High-severity case: One document format disguised as another (e.g. PDF claiming to be JPG)
        return Finding(
            title="File Extension Mismatch Detected",
            detail=(
                f"File claims extension '{declared_ext}', but binary signature analysis identified "
                f"'{detected.detected_mime}' ({detected.detected_ext} - {detected.description}). "
                "Discrepancies between file extension and binary content are frequently associated with evasion techniques."
            ),
            severity="high",
            weight=0.80,
            evidence={
                "claimed_extension": declared_ext,
                "detected_mime": detected.detected_mime,
                "detected_extension": detected.detected_ext,
            },
        )

    return None


# ==============================================================================
# Tamper Risk Scoring (Noisy-OR Formulation)
# ==============================================================================

def compute_risk_score(findings: List[Finding]) -> Tuple[int, Literal["Low", "Medium", "High"]]:
    """
    Computes cumulative tamper risk score using the Noisy-OR probabilistic combination formula:

        Risk Score = round( (1 - PRODUCT_{i} (1 - weight_i)) * 100 )

    Mathematical Logic:
    -------------------
    Each finding represents an independent tamper or security indicator with probability `weight_i`.
    The probability that finding `i` fails to indicate tampering is `(1 - weight_i)`.
    Assuming statistical independence, the joint probability that NONE of the findings
    indicate tampering is:
        P(no tamper) = PRODUCT_{i} (1 - weight_i)
    Therefore, the probability that AT LEAST ONE finding indicates genuine tampering is:
        P(tamper) = 1 - P(no tamper) = 1 - PRODUCT_{i} (1 - weight_i)

    Risk Bands:
        0 - 30:   Low
        31 - 60:  Medium
        61 - 100: High

    Args:
        findings: List of Finding objects.

    Returns:
        Tuple of (risk_score_int, risk_band_str)
    """
    if not findings:
        return (0, "Low")

    product_no_tamper = 1.0
    for finding in findings:
        w = max(0.0, min(1.0, float(finding.weight)))
        product_no_tamper *= (1.0 - w)

    raw_score = (1.0 - product_no_tamper) * 100.0
    risk_score = int(round(raw_score))

    # Clamp safely to [0, 100]
    risk_score = max(0, min(100, risk_score))

    # Assign risk band
    if risk_score <= RISK_BAND_LOW_MAX:
        risk_band: Literal["Low", "Medium", "High"] = "Low"
    elif risk_score <= RISK_BAND_MEDIUM_MAX:
        risk_band = "Medium"
    else:
        risk_band = "High"

    return (risk_score, risk_band)


# ==============================================================================
# ZIP Safety Validation (Zip Slip & Zip Bomb Defense)
# ==============================================================================

# Executable or script extensions forbidden inside uploaded archives
DANGEROUS_ARCHIVE_EXTENSIONS: Set[str] = {
    ".exe", ".dll", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".ps1", ".psm1", ".sh", ".bash", ".elf", ".bin",
    ".scr", ".pif", ".cpl", ".hta", ".jar", ".msi", ".msp", ".reg"
}


def validate_zip_safety(
    zip_source: Union[str, Path, bytes, io.BytesIO],
) -> Tuple[bool, List[Finding], List[str]]:
    """
    Performs comprehensive pre-extraction security inspection on a ZIP archive.

    Security Defenses:
    ------------------
    1. Zip Slip (Path Traversal): Rejects archive members with '..' or absolute paths
       that attempt to escape the intended directory.
    2. Zip Bomb: Enforces maximum entry count (200), maximum uncompressed payload (100 MB),
       and flags abnormal compression ratios (> 10:1 on large files).
    3. Dangerous File Check: Scans member names for executable or scripting extensions.
    4. Corrupted Archive Defense: Catches bad ZIP headers before crash.

    Args:
        zip_source: Path, bytes, or file-like buffer of the archive.

    Returns:
        Tuple of:
          - is_safe (bool): True if safe to process, False if malicious/dangerous.
          - findings (List[Finding]): Any security violations or warnings identified.
          - safe_entry_names (List[str]): List of validated member names.
    """
    findings: List[Finding] = []
    safe_entry_names: List[str] = []

    try:
        if isinstance(zip_source, bytes):
            zf = zipfile.ZipFile(io.BytesIO(zip_source))
        elif isinstance(zip_source, (str, Path)):
            zf = zipfile.ZipFile(zip_source)
        else:
            zf = zipfile.ZipFile(zip_source)
    except Exception as e:
        findings.append(
            Finding(
                title="Corrupted or Invalid ZIP Archive",
                detail=f"Unable to read ZIP archive header: {str(e)}",
                severity="high",
                weight=0.90,
                evidence={"error": str(e)},
            )
        )
        return (False, findings, [])

    with zf:
        infolist = zf.infolist()
        entry_count = len(infolist)

        # 1. Check Maximum Entries Limit (Constraint: <= 200 entries)
        if entry_count > MAX_ZIP_ENTRIES:
            findings.append(
                Finding(
                    title="ZIP Entry Limit Exceeded (Possible Inode/File Exhaustion Attack)",
                    detail=(
                        f"Archive contains {entry_count} entries, which exceeds the permitted maximum "
                        f"of {MAX_ZIP_ENTRIES}. Excessive files can cause server denial of service."
                    ),
                    severity="high",
                    weight=0.90,
                    evidence={"entry_count": entry_count, "max_allowed": MAX_ZIP_ENTRIES},
                )
            )
            return (False, findings, [])

        total_uncompressed_bytes = 0
        total_compressed_bytes = 0

        for member in infolist:
            filename = member.filename

            # 2. Path Traversal (Zip Slip) Defense
            # Normalize path and check for traversal patterns
            normalized_parts = Path(filename).parts
            if (
                ".." in normalized_parts
                or filename.startswith("/")
                or filename.startswith("\\")
                or (len(filename) >= 2 and filename[1] == ":")  # Windows drive letter e.g. C:
                or os.path.isabs(filename)
            ):
                findings.append(
                    Finding(
                        title="Malicious Path Traversal Detected (Zip Slip)",
                        detail=(
                            f"Archive member '{filename}' contains directory traversal sequences or "
                            "absolute path references designed to escape the extraction sandbox."
                        ),
                        severity="high",
                        weight=1.0,
                        evidence={"malicious_entry": filename},
                    )
                )
                return (False, findings, [])

            # Check for Unix Symlink (external_attr mode 0o120000)
            # Symlinks can be weaponized to read arbitrary files from the server host filesystem
            mode = (member.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                findings.append(
                    Finding(
                        title="Archive Symlink Detected (Arbitrary File Read Hazard)",
                        detail=(
                            f"Archive entry '{filename}' is a symbolic link. Symlinks in archives "
                            "can be weaponized to read sensitive host files upon extraction."
                        ),
                        severity="high",
                        weight=0.95,
                        evidence={"symlink_entry": filename},
                    )
                )
                return (False, findings, [])

            total_uncompressed_bytes += member.file_size
            total_compressed_bytes += member.compress_size

            # 3. Per-Entry Decompression Bomb Ratio Check
            if member.file_size > 500_000 and member.compress_size > 0:
                entry_ratio = member.file_size / member.compress_size
                if entry_ratio > MAX_ZIP_COMPRESSION_RATIO:
                    findings.append(
                        Finding(
                            title="Suspicious Compression Ratio (Potential Zip Bomb Member)",
                            detail=(
                                f"Archive member '{filename}' has an anomalous compression ratio of "
                                f"{entry_ratio:.1f}:1 ({member.file_size} uncompressed vs {member.compress_size} compressed). "
                                "This pattern is characteristic of decompression bomb payloads."
                            ),
                            severity="high",
                            weight=0.85,
                            evidence={
                                "entry": filename,
                                "uncompressed_bytes": member.file_size,
                                "compressed_bytes": member.compress_size,
                                "compression_ratio": round(entry_ratio, 2),
                            },
                        )
                    )

            # 4. Dangerous / Executable Content Check
            member_suffix = Path(filename).suffix.lower()
            if member_suffix in DANGEROUS_ARCHIVE_EXTENSIONS:
                findings.append(
                    Finding(
                        title="Executable / Dangerous File Inside Archive",
                        detail=(
                            f"Archive contains executable or script payload '{filename}'. "
                            "PRAMAANX strictly prohibits executing or unpacking unauthorized executable files."
                        ),
                        severity="high",
                        weight=0.95,
                        evidence={"dangerous_entry": filename, "extension": member_suffix},
                    )
                )

            # Check if entry is a supported file format
            if member_suffix in ALLOWED_EXTENSIONS and not member.is_dir():
                safe_entry_names.append(filename)

        # 5. Total Uncompressed Size Check (Zip Bomb defense)
        if total_uncompressed_bytes > MAX_ZIP_UNCOMPRESSED_BYTES:
            findings.append(
                Finding(
                    title="Decompression Bomb Detected (Total Uncompressed Size Exceeded)",
                    detail=(
                        f"Total uncompressed size of archive is {total_uncompressed_bytes / (1024*1024):.2f} MB, "
                        f"which exceeds the safety limit of {MAX_ZIP_UNCOMPRESSED_BYTES / (1024*1024):.0f} MB."
                    ),
                    severity="high",
                    weight=1.0,
                    evidence={
                        "total_uncompressed_bytes": total_uncompressed_bytes,
                        "max_allowed_bytes": MAX_ZIP_UNCOMPRESSED_BYTES,
                    },
                )
            )
            return (False, findings, [])

    # If any critical finding was registered with weight >= 0.90, mark safe = False
    is_safe = not any(f.weight >= 0.90 for f in findings)
    return (is_safe, findings, safe_entry_names)


def safe_extract_zip(
    zip_source: Union[str, Path],
    destination_dir: Path,
) -> List[Path]:
    """
    Safely extracts validated archive entries into a target directory.

    Security Guarantees:
    --------------------
    1. Validates entire archive safety before writing a single byte to disk.
    2. Resolves destination paths strictly within `destination_dir`.
    3. Never executes or runs any extracted file.

    Args:
        zip_source: Path to ZIP archive on disk.
        destination_dir: Directory where safe files will be stored.

    Returns:
        List of absolute Paths to safely extracted files.
    """
    is_safe, findings, safe_entries = validate_zip_safety(zip_source)
    if not is_safe:
        critical_titles = [f.title for f in findings if f.weight >= 0.90]
        raise ValueError(f"ZIP archive failed safety validation: {', '.join(critical_titles)}")

    destination_dir = destination_dir.resolve()
    destination_dir.mkdir(parents=True, exist_ok=True)
    extracted_paths: List[Path] = []

    with zipfile.ZipFile(zip_source) as zf:
        for entry_name in safe_entries:
            # Re-verify path safety under resolved destination
            target_path = (destination_dir / entry_name).resolve()
            if not target_path.is_relative_to(destination_dir):
                raise ValueError(f"Path traversal detected during extraction: {entry_name}")

            target_path.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(entry_name) as source, open(target_path, "wb") as target:
                while chunk := source.read(65536):
                    target.write(chunk)

            extracted_paths.append(target_path)

    return extracted_paths
