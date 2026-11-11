"""
PRAMAANX - JPEG Structure & Compression History Analyzer
========================================================
Extracts low-level structural, quantization, and marker telemetry from JPEG images:
1. IJG quantization table quality factor estimation
2. SHA-256 fingerprinting of quantization matrices
3. Chroma subsampling factor identification (4:2:0, 4:2:2, 4:4:4)
4. Compression encoding mode (Baseline DCT vs. Progressive DCT)
5. Physical JPEG marker sequence tracking (SOI, APPn, DQT, SOFn, DHT, SOS, EOI)
6. Byte density and pixel geometry
7. Recompression and messaging-app sharing heuristics
"""

import hashlib
import io
import math
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from PIL import Image

# Standard Independent JPEG Group (IJG) Luminance Quantization Table
STD_LUMINANCE_QUANT_TABLE = [
    16, 11, 10, 16, 24, 40, 51, 61,
    12, 12, 14, 19, 26, 58, 60, 55,
    14, 13, 16, 24, 40, 57, 69, 56,
    14, 17, 22, 29, 51, 87, 80, 62,
    18, 22, 37, 56, 68, 109, 103, 77,
    24, 35, 55, 64, 81, 104, 113, 92,
    49, 64, 78, 87, 103, 121, 120, 101,
    72, 92, 95, 98, 112, 100, 103, 99,
]

# Standard IJG Chrominance Quantization Table
STD_CHROMINANCE_QUANT_TABLE = [
    17, 18, 24, 47, 99, 99, 99, 99,
    18, 21, 26, 66, 99, 99, 99, 99,
    24, 26, 56, 99, 99, 99, 99, 99,
    47, 66, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99,
]

MARKER_NAMES: Dict[int, str] = {
    0xD8: "SOI (Start of Image)",
    0xE0: "APP0 (JFIF)",
    0xE1: "APP1 (Exif / XMP)",
    0xE2: "APP2 (ICC Profile)",
    0xED: "APP13 (Photoshop / IPTC)",
    0xEE: "APP14 (Adobe)",
    0xDB: "DQT (Quantization Table)",
    0xC0: "SOF0 (Baseline DCT)",
    0xC1: "SOF1 (Extended Sequential)",
    0xC2: "SOF2 (Progressive DCT)",
    0xC4: "DHT (Huffman Table)",
    0xDA: "SOS (Start of Scan)",
    0xD9: "EOI (End of Image)",
    0xFE: "COM (Comment)",
}


def estimate_jpeg_quality(quant_tables: Dict[int, List[int]]) -> Optional[int]:
    """
    Estimates the original JPEG quality factor (0-100) by comparing the extracted
    luminance quantization table (table 0) against the standard IJG quantization matrix.
    """
    if not quant_tables or 0 not in quant_tables:
        return None

    actual_table = quant_tables[0]
    if len(actual_table) < 64:
        return None

    # Calculate scaling factor ratios for standard positions
    ratios = []
    for actual, std in zip(actual_table[:64], STD_LUMINANCE_QUANT_TABLE):
        if std > 0:
            ratios.append((actual / std) * 100.0)

    if not ratios:
        return None

    avg_scale = sum(ratios) / len(ratios)

    if avg_scale <= 0:
        return 100
    elif avg_scale > 100.0:
        # Scale factor S = 5000 / Q => Q = 5000 / S
        quality = 5000.0 / avg_scale
    else:
        # Scale factor S = 200 - 2*Q => Q = (200 - S) / 2
        quality = (200.0 - avg_scale) / 2.0

    return max(1, min(100, int(round(quality))))


def compute_quantization_hash(quant_tables: Dict[int, List[int]]) -> Optional[str]:
    """Generates a short SHA-256 fingerprint from the quantization tables."""
    if not quant_tables:
        return None
    hasher = hashlib.sha256()
    for tbl_id in sorted(quant_tables.keys()):
        tbl = quant_tables[tbl_id]
        hasher.update(bytes([tbl_id]))
        hasher.update(bytes(min(255, max(0, int(val))) for val in tbl))
    return hasher.hexdigest()[:12]


def parse_jpeg_markers(raw_bytes: bytes) -> Tuple[List[str], str, Optional[str], Optional[int]]:
    """
    Parses JPEG binary stream to extract:
    - ordered marker sequence
    - encoding mode (baseline / progressive)
    - chroma subsampling (4:2:0, 4:2:2, 4:4:4)
    - number of components
    """
    markers: List[str] = []
    encoding = "baseline"
    chroma_subsampling: Optional[str] = None
    num_components: Optional[int] = None

    idx = 0
    n = len(raw_bytes)

    if n < 2 or raw_bytes[0] != 0xFF or raw_bytes[1] != 0xD8:
        return markers, encoding, chroma_subsampling, num_components

    markers.append(MARKER_NAMES.get(0xD8, "SOI"))
    idx = 2

    while idx < n - 1:
        # Find next 0xFF byte
        if raw_bytes[idx] != 0xFF:
            idx += 1
            continue

        # Skip fill bytes 0xFF
        while idx < n and raw_bytes[idx] == 0xFF:
            idx += 1

        if idx >= n:
            break

        marker_code = raw_bytes[idx]
        idx += 1

        # Ignore 0x00 (escaped byte inside entropy-coded scan data)
        if marker_code == 0x00:
            continue

        marker_name = MARKER_NAMES.get(marker_code, f"Marker 0xFF{marker_code:02X}")
        markers.append(marker_name)

        # Standalone markers without payload length
        if marker_code in (0xD8, 0xD9, 0x01) or (0xD0 <= marker_code <= 0xD7):
            if marker_code == 0xD9:  # EOI
                break
            continue

        # Read payload length
        if idx + 2 > n:
            break
        length = (raw_bytes[idx] << 8) | raw_bytes[idx + 1]
        payload_start = idx + 2
        payload_end = idx + length

        # Inspect SOF (Start of Frame) markers for encoding and chroma subsampling
        if marker_code in (0xC0, 0xC1, 0xC2, 0xC3):
            if marker_code == 0xC2:
                encoding = "progressive"
            else:
                encoding = "baseline"

            # Parse SOF payload if sufficient bytes
            # Structure: precision (1B), height (2B), width (2B), num_components (1B)
            # followed by components: ID (1B), sampling factors (1B), quant table ID (1B)
            if payload_start + 6 <= n:
                num_components = raw_bytes[payload_start + 5]
                comp_offset = payload_start + 6
                components = []
                for _ in range(num_components):
                    if comp_offset + 3 <= n:
                        c_id = raw_bytes[comp_offset]
                        sampling = raw_bytes[comp_offset + 1]
                        h_samp = (sampling >> 4) & 0x0F
                        v_samp = sampling & 0x0F
                        components.append({"id": c_id, "h": h_samp, "v": v_samp})
                        comp_offset += 3

                if len(components) >= 3:
                    y_h, y_v = components[0]["h"], components[0]["v"]
                    cb_h, cb_v = components[1]["h"], components[1]["v"]
                    cr_h, cr_v = components[2]["h"], components[2]["v"]

                    if y_h == 2 and y_v == 2 and cb_h == 1 and cb_v == 1 and cr_h == 1 and cr_v == 1:
                        chroma_subsampling = "4:2:0"
                    elif y_h == 2 and y_v == 1 and cb_h == 1 and cb_v == 1 and cr_h == 1 and cr_v == 1:
                        chroma_subsampling = "4:2:2"
                    elif y_h == 1 and y_v == 1 and cb_h == 1 and cb_v == 1 and cr_h == 1 and cr_v == 1:
                        chroma_subsampling = "4:4:4"
                    elif y_h == 4 and y_v == 1:
                        chroma_subsampling = "4:1:1"
                    else:
                        chroma_subsampling = f"{y_h}:{cb_h}:{cr_h}"
                elif num_components == 1:
                    chroma_subsampling = "grayscale"

        # Advance to end of segment
        if marker_code == 0xDA:  # SOS (Start of Scan) - rest is compressed scan data
            # Scan till next marker (typically EOI)
            eoi_idx = raw_bytes.rfind(b"\xFF\xD9")
            if eoi_idx != -1:
                markers.append("EOI (End of Image)")
            break
        else:
            idx = payload_end

    return markers, encoding, chroma_subsampling, num_components


def analyze_jpeg_structure(
    file_path: Union[str, Path],
    img: Optional[Image.Image] = None,
    exif_present: bool = False,
    absent_meta_count: int = 0,
) -> Dict[str, Any]:
    """
    Executes forensic JPEG structure and compression history analysis.
    """
    path = Path(file_path).resolve()
    file_bytes = path.read_bytes()
    file_size = len(file_bytes)

    # 1. Geometry & Pillow quantization tables
    width, height = 0, 0
    quant_tables: Dict[int, List[int]] = {}

    if img is not None:
        width, height = img.size
        if hasattr(img, "quantization") and isinstance(img.quantization, dict):
            quant_tables = {k: list(v) for k, v in img.quantization.items()}
    else:
        try:
            with Image.open(path) as pil_img:
                width, height = pil_img.size
                if hasattr(pil_img, "quantization") and isinstance(pil_img.quantization, dict):
                    quant_tables = {k: list(v) for k, v in pil_img.quantization.items()}
        except Exception:
            pass

    # 2. Quality and Quantization hash
    estimated_quality = estimate_jpeg_quality(quant_tables)
    quant_hash = compute_quantization_hash(quant_tables)

    # 3. Low-level markers and subsampling
    markers, encoding, chroma_subsampling, _ = parse_jpeg_markers(file_bytes)

    # 4. Geometry and byte density
    long_side_px = max(width, height)
    aspect_ratio = round(width / max(1, height), 2) if height > 0 else 1.0
    bytes_per_pixel = round(file_size / max(1, (width * height)), 4) if (width * height) > 0 else 0.0

    # 5. Recompression & Messaging App Detection (Task 2 & 4 Rules)
    # Rules:
    # - Long image side <= 1600px AND EXIF is absent (classic WhatsApp/Signal/Telegram resize)
    # - OR Estimated quality is below 80
    # - OR 5 or more of the 9 metadata fields are absent
    is_messaging_res = (long_side_px <= 1600 and not exif_present)
    is_low_quality = (estimated_quality is not None and estimated_quality < 80)
    is_metadata_stripped = (absent_meta_count >= 5)

    likely_messaging = bool(is_messaging_res or is_low_quality or is_metadata_stripped)

    # 6. Double compression detection
    # In accordance with prompt mandate: "if you cannot implement it reliably, return null and do not guess"
    # We return None (null in JSON) unless demonstrable evidence is present.
    double_compression_suspected: Optional[bool] = None

    return {
        "estimated_quality": estimated_quality,
        "quantization_tables_hash": quant_hash,
        "chroma_subsampling": chroma_subsampling or "4:2:0",
        "encoding": encoding,
        "markers": markers,
        "bytes_per_pixel": bytes_per_pixel,
        "long_side_px": long_side_px,
        "aspect_ratio": aspect_ratio,
        "double_compression_suspected": double_compression_suspected,
        "likely_messaging_app_recompression": likely_messaging,
        "recompression_indicators": {
            "messaging_resolution_limit": is_messaging_res,
            "low_quality_quantization": is_low_quality,
            "stripped_camera_metadata": is_metadata_stripped,
        },
    }

