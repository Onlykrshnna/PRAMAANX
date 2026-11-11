"""
PRAMAANX - Image Forensic & ML Tampering Analyzer (Phase 4)
===========================================================
Comprehensive static & machine-learning forensic inspection of images:
1. Deep Learning Tampering Inference:
   - Architecture: EfficientNet-B0 (Transfer learning fine-tuned on CASIA 2.0)
   - Pretrained ImageNet weights fine-tuned for authentic vs. spliced/copy-move detection
   - 224x224 input resolution, standardized ImageNet normalization
   - Softmax probabilities, predicted class ('Authentic' or 'Tampered'), and confidence
   - Singleton model loader (loaded once in memory, shared across analyses)
2. Explainable AI Visualization (Grad-CAM):
   - Computes gradient-weighted class activation mapping on final convolutional layer (model.features[-1])
   - Visualizes attention regions influencing the tampering decision
   - Blends heatmap overlay without modifying the original image
   - Explicitly framed as an explanation of model attention, not a definitive pixel-level manipulation mask
3. Static Image Forensics Heuristics:
   - Error Level Analysis (ELA) with quantitative error statistics
   - EXIF metadata extraction and editing software detection (Photoshop, GIMP, Canva, Lightroom)
   - Appended data / overlay steganography detection (bytes trailing after JPEG EOI or PNG IEND)
   - JPEG quantization table inspection where available
   - Image geometry, bit depth, aspect ratio, and color mode verification
4. Defensive Safeguards:
   - Resource-controlled processing with Pillow DecompressionBomb protection
   - Never presents statistical ML predictions as definitive forensic proof
   - Clear distinction between heuristic signals and neural network outputs
"""

from dataclasses import dataclass, field
from datetime import datetime
import io
import json
import math
import os
from pathlib import Path
import re
import shutil
import threading
from typing import Any, Dict, List, Optional, Tuple, Union

import cv2
import numpy as np
from PIL import Image, ImageChops, ImageEnhance, ExifTags
import torch
import torch.nn as nn
import torchvision.models as models
import torchvision.transforms as transforms

from backend.config import MAX_UPLOAD_SIZE_BYTES, UPLOAD_TEMP_DIR
from backend.analyzers.common import Finding, compute_sha256
from backend.analyzers.jpeg_structure import analyze_jpeg_structure


# ==============================================================================
# Model Configuration, Calibration & Singleton Management
# ==============================================================================

MODEL_PATH: Path = Path(__file__).resolve().parent.parent / "models" / "image_tampering" / "pramaanx_efficientnet_best.pth"
CALIBRATION_PATH: Path = Path(__file__).resolve().parent.parent / "models" / "image_tampering" / "calibration.json"

_MODEL_LOCK = threading.Lock()
_IMAGE_MODEL: Optional[nn.Module] = None
_MODEL_METADATA: Dict[str, Any] = {}


def get_calibration_params() -> Dict[str, Any]:
    """
    Loads temperature scaling and ROC thresholds from calibration.json.
    Strictly enforces status: if status != 'calibrated', returns uncalibrated parameters
    (T=1.0, is_calibrated=False) to prevent claiming false calibration confidence.
    """
    default_params = {
        "status": "uncalibrated",
        "is_calibrated": False,
        "temperature": 1.0,
        "threshold_low": 0.35,
        "threshold_high": 0.65,
    }
    if CALIBRATION_PATH.is_file():
        try:
            data = json.loads(CALIBRATION_PATH.read_text(encoding="utf-8"))
            status = data.get("status", "uncalibrated")
            is_calibrated = (status == "calibrated")
            return {
                "status": status,
                "is_calibrated": is_calibrated,
                "temperature": float(data.get("temperature", 1.0)) if is_calibrated else 1.0,
                "threshold_low": float(data.get("threshold_low", 0.35)),
                "threshold_high": float(data.get("threshold_high", 0.65)),
            }
        except Exception:
            pass
    return default_params


def get_tamper_model() -> Tuple[nn.Module, Dict[str, Any]]:
    """
    Thread-safe singleton loader for the trained EfficientNet-B0 tampering model.
    Loads the model into memory exactly once.
    """
    global _IMAGE_MODEL, _MODEL_METADATA

    if _IMAGE_MODEL is not None:
        return _IMAGE_MODEL, _MODEL_METADATA

    with _MODEL_LOCK:
        if _IMAGE_MODEL is not None:
            return _IMAGE_MODEL, _MODEL_METADATA

        if not MODEL_PATH.is_file():
            raise FileNotFoundError(
                f"Trained model checkpoint not found at '{MODEL_PATH}'. "
                "Per PRAMAANX zero-cost/self-owned policy, fake weights are prohibited. "
                "Please place the authentic CASIA 2.0 trained checkpoint at this path."
            )

        # Load checkpoint onto CPU (device-agnostic)
        checkpoint = torch.load(MODEL_PATH, map_location="cpu")

        # Instantiate EfficientNet-B0 architecture
        model = models.efficientnet_b0(weights=None)
        # Adapt classifier head to 2 classes (0: Authentic, 1: Tampered)
        model.classifier[1] = nn.Linear(1280, 2)

        # Load trained state dictionary
        state_dict = checkpoint.get("model_state_dict", checkpoint)
        model.load_state_dict(state_dict)
        model.eval()

        _IMAGE_MODEL = model
        _MODEL_METADATA = {
            "architecture": checkpoint.get("architecture", "efficientnet_b0"),
            "class_names": checkpoint.get("class_names", ["Authentic", "Tampered"]),
            "input_size": checkpoint.get("input_size", 224),
            "normalization_mean": checkpoint.get("normalization_mean", [0.485, 0.456, 0.406]),
            "normalization_std": checkpoint.get("normalization_std", [0.229, 0.224, 0.225]),
            "test_accuracy": checkpoint.get("test_accuracy", 0.7137),
            "best_validation_loss": checkpoint.get("best_validation_loss", None),
        }

        return _IMAGE_MODEL, _MODEL_METADATA


# Preprocessing pipeline matching CASIA 2.0 training
IMAGE_TRANSFORM = transforms.Compose([
    transforms.Resize((224, 224)),
    transforms.ToTensor(),
    transforms.Normalize(
        mean=[0.485, 0.456, 0.406],
        std=[0.229, 0.224, 0.225],
    ),
])


# ==============================================================================
# Data Structures
# ==============================================================================

@dataclass
class ImageForensicReport:
    """Standardized output of the image forensic analyzer."""
    findings: List[Finding] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    visual_evidence: Dict[str, str] = field(default_factory=dict)
    ml_prediction: Optional[Dict[str, Any]] = None
    ela_stats: Optional[Dict[str, Any]] = None
    exif_data: Dict[str, Any] = field(default_factory=dict)
    image_geometry: Dict[str, Any] = field(default_factory=dict)
    ai_status: str = "active"
    ai_status_reason: Optional[str] = None
    jpeg_structure: Optional[Dict[str, Any]] = None


# ==============================================================================
# Grad-CAM Implementation for EfficientNet-B0
# ==============================================================================

class GradCAM:
    """
    Gradient-weighted Class Activation Mapping (Grad-CAM) for EfficientNet-B0.
    Targets the final convolutional block (model.features[-1]).
    """

    def __init__(self, model: nn.Module):
        self.model = model
        self.target_layer = model.features[-1]
        self.activations: Optional[torch.Tensor] = None
        self.gradients: Optional[torch.Tensor] = None
        self.handles: List[Any] = []
        self._register_hooks()

    def _register_hooks(self) -> None:
        def forward_hook(module, input_t, output_t):
            self.activations = output_t.detach()

        def backward_hook(module, grad_in, grad_out):
            self.gradients = grad_out[0].detach()

        self.handles.append(self.target_layer.register_forward_hook(forward_hook))
        self.handles.append(self.target_layer.register_full_backward_hook(backward_hook))

    def generate_heatmap(
        self,
        input_tensor: torch.Tensor,
        target_class: int = 1,  # Target class 1: Tampered
    ) -> np.ndarray:
        """
        Computes the normalized Grad-CAM activation heatmap for target class.
        Returns 2D float numpy array in [0.0, 1.0].
        """
        self.model.zero_grad()
        output = self.model(input_tensor)
        score = output[0, target_class]
        score.backward(retain_graph=True)

        if self.gradients is None or self.activations is None:
            raise RuntimeError("Grad-CAM hooks failed to capture activations or gradients.")

        # Global average pooling of gradients: (1, 1280, 1, 1)
        weights = torch.mean(self.gradients, dim=[2, 3], keepdim=True)
        # Linear combination of forward activations: (1, 1, 7, 7)
        cam = torch.sum(weights * self.activations, dim=1, keepdim=True)
        # Apply ReLU to retain only features with positive influence on class
        cam = torch.relu(cam)

        # Normalize CAM
        cam_min, cam_max = torch.min(cam), torch.max(cam)
        if cam_max > cam_min:
            cam = (cam - cam_min) / (cam_max - cam_min)
        else:
            cam = torch.zeros_like(cam)

        # Upsample to 224x224
        cam_upsampled = nn.functional.interpolate(
            cam, size=(input_tensor.shape[2], input_tensor.shape[3]), mode="bilinear", align_corners=False
        )

        heatmap = cam_upsampled.squeeze().cpu().numpy()
        return heatmap

    def release(self) -> None:
        """Remove hooks to prevent memory leaks."""
        for h in self.handles:
            h.remove()
        self.handles.clear()


def generate_gradcam_overlay(
    image: Image.Image,
    model: nn.Module,
    input_tensor: torch.Tensor,
    output_path: Path,
    target_class: int = 1,
) -> Path:
    """
    Renders Grad-CAM heatmap blended onto the input image and saves as PNG.
    Heatmap is upscaled to exact original image dimensions (width, height)
    so both layers have identical pixel aspect ratio and coordinates.
    """
    grad_cam = GradCAM(model)
    try:
        heatmap_2d = grad_cam.generate_heatmap(input_tensor, target_class=target_class)

        # Original image dimensions and RGB array
        orig_img = image.convert("RGB")
        orig_w, orig_h = orig_img.size
        orig_np = np.array(orig_img)

        # Apply JET colormap via OpenCV
        heatmap_uint8 = np.uint8(255 * heatmap_2d)
        heatmap_colored_bgr = cv2.applyColorMap(heatmap_uint8, cv2.COLORMAP_JET)
        heatmap_colored_rgb = cv2.cvtColor(heatmap_colored_bgr, cv2.COLOR_BGR2RGB)

        # Resize heatmap to match exact original image dimensions (width, height)
        heatmap_resized = cv2.resize(
            heatmap_colored_rgb, (orig_w, orig_h), interpolation=cv2.INTER_CUBIC
        )

        # Blend: 60% original image + 40% attention heatmap
        blended = cv2.addWeighted(orig_np, 0.60, heatmap_resized, 0.40, 0)

        overlay_img = Image.fromarray(blended)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        overlay_img.save(output_path, format="PNG")
        return output_path
    finally:
        grad_cam.release()


# ==============================================================================
# Error Level Analysis (ELA)
# ==============================================================================

def compute_ela(
    image: Image.Image,
    output_path: Path,
    quality: int = 95,
) -> Tuple[Dict[str, Any], Path]:
    """
    Performs Error Level Analysis (ELA) by resaving the image as a JPEG
    at fixed quality and analyzing pixel compression artifacts.

    Normalization & Colormap (Task 6):
    ----------------------------------
    Scales the error map by the 99th percentile of the absolute error to prevent
    near-black underexposure, then renders using the OpenCV Inferno colormap.
    """
    im_rgb = image.convert("RGB")

    # Resave in memory at fixed JPEG quality
    buffer = io.BytesIO()
    im_rgb.save(buffer, format="JPEG", quality=quality)
    buffer.seek(0)
    resaved = Image.open(buffer)

    # Compute pixel-wise absolute difference
    diff = ImageChops.difference(im_rgb, resaved)
    diff_np = np.array(diff, dtype=np.float32)

    # Calculate quantitative ELA statistics
    mean_error = float(np.mean(diff_np))
    max_error = float(np.max(diff_np))
    std_error = float(np.std(diff_np))

    # Error magnitude per pixel (average across color channels)
    error_mag = np.mean(diff_np, axis=2) if diff_np.ndim == 3 else diff_np

    # 99th percentile normalization (Task 6)
    p99 = float(np.percentile(error_mag, 99))
    scale_factor = float(255.0 / p99) if p99 > 0.0 else 1.0

    # Scale and clip to uint8
    scaled_error = np.clip(error_mag * scale_factor, 0, 255).astype(np.uint8)

    # Apply Inferno colormap
    colormap_bgr = cv2.applyColorMap(scaled_error, cv2.COLORMAP_INFERNO)
    colormap_rgb = cv2.cvtColor(colormap_bgr, cv2.COLOR_BGR2RGB)

    ela_image = Image.fromarray(colormap_rgb)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    ela_image.save(output_path, format="PNG")

    stats = {
        "mean_error": round(mean_error, 4),
        "max_error": round(max_error, 4),
        "std_error": round(std_error, 4),
        "p99_error": round(p99, 4),
        "scale_factor": round(scale_factor, 2),
        "colormap": "inferno",
        "quality_level": quality,
    }
    return stats, output_path


# ==============================================================================
# EXIF Metadata & Steganography Heuristics
# ==============================================================================

EDITING_SOFTWARE_KEYWORDS: List[str] = [
    "photoshop", "gimp", "canva", "lightroom", "snapseed", "paint.net",
    "vsco", "procreate", "pixlr", "fotor", "coreldraw", "illustrator",
]


def _format_gps_coords(gps_info: Dict[str, Any]) -> Optional[str]:
    """Safely formats EXIF GPS coordinates into a human-readable string if present."""
    try:
        lat = gps_info.get("GPSLatitude")
        lat_ref = gps_info.get("GPSLatitudeRef", "N")
        lon = gps_info.get("GPSLongitude")
        lon_ref = gps_info.get("GPSLongitudeRef", "E")

        if lat and lon:
            def _convert_dms(dms):
                if isinstance(dms, (list, tuple)) and len(dms) >= 3:
                    d = float(dms[0])
                    m = float(dms[1])
                    s = float(dms[2])
                    return f"{d:.0f}°{m:.0f}'{s:.2f}\""
                return str(dms)

            return f"{_convert_dms(lat)} {lat_ref}, {_convert_dms(lon)} {lon_ref}"
    except Exception:
        pass
    return None


def _extract_exif_data(image: Image.Image) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[Finding]]:
    """Extracts and evaluates EXIF tags, sub-IFDs, software signatures, and timestamps."""
    exif_data: Dict[str, Any] = {}
    timeline: List[Dict[str, Any]] = []
    findings: List[Finding] = []

    try:
        raw_exif = image.getexif()
        if not raw_exif:
            return exif_data, timeline, findings

        # 1. Main 0th IFD
        for tag_id, value in raw_exif.items():
            tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
            if isinstance(value, bytes):
                try:
                    value = value.decode("utf-8", errors="ignore").strip("\x00")
                except Exception:
                    value = str(value)
            exif_data[tag_name] = str(value)

        # 2. Exif Sub-IFD (contains DateTimeOriginal, DateTimeDigitized)
        try:
            exif_sub_id = getattr(getattr(ExifTags, "IFD", None), "Exif", 0x8769)
            exif_sub = raw_exif.get_ifd(exif_sub_id)
            if exif_sub:
                for tag_id, value in exif_sub.items():
                    tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                    if isinstance(value, bytes):
                        try:
                            value = value.decode("utf-8", errors="ignore").strip("\x00")
                        except Exception:
                            value = str(value)
                    exif_data[tag_name] = str(value)
        except Exception:
            pass

        # 3. GPS Sub-IFD (contains GPSLatitude, GPSLongitude, etc.)
        try:
            gps_sub_id = getattr(getattr(ExifTags, "IFD", None), "GPSInfo", 0x8825)
            gps_sub = raw_exif.get_ifd(gps_sub_id)
            if gps_sub:
                gps_dict = {}
                for tag_id, value in gps_sub.items():
                    tag_name = getattr(ExifTags, "GPSTAGS", {}).get(tag_id, str(tag_id))
                    if isinstance(value, bytes):
                        try:
                            value = value.decode("utf-8", errors="ignore").strip("\x00")
                        except Exception:
                            value = str(value)
                    gps_dict[tag_name] = str(value)
                if gps_dict:
                    exif_data["GPSInfo"] = gps_dict
                    formatted_gps = _format_gps_coords(gps_dict)
                    if formatted_gps:
                        exif_data["GPSCoordinates"] = formatted_gps
        except Exception:
            pass

        # Check for editing software signatures
        software = exif_data.get("Software", "").lower()
        matched_software = [kw for kw in EDITING_SOFTWARE_KEYWORDS if kw in software]
        if matched_software:
            findings.append(
                Finding(
                    title="Image Editing Software Signature in EXIF",
                    detail=(
                        f"EXIF metadata indicates the image was created or modified using graphic editing "
                        f"software: '{exif_data.get('Software')}'. In document authenticity verification, "
                        "editing software signatures are strong indicators of potential digital alteration."
                    ),
                    severity="medium",
                    weight=0.55,
                    evidence={"software": exif_data.get("Software"), "identified_keywords": matched_software},
                    category="heuristic",
                )
            )

        # Extract timestamps
        dt_original = exif_data.get("DateTimeOriginal") or exif_data.get("DateTime")
        if dt_original:
            timeline.append({
                "event": "Image Captured / Digitized",
                "timestamp": str(dt_original),
                "camera_make": exif_data.get("Make", "Unknown"),
                "camera_model": exif_data.get("Model", "Unknown"),
            })

    except Exception:
        pass

    return exif_data, timeline, findings


def _check_trailing_data(file_path: Path, format_name: str) -> Optional[Finding]:
    """
    Checks for trailing data appended beyond standard end-of-file markers.
    (Common steganography / polyglot archive injection technique).
    """
    try:
        raw_bytes = file_path.read_bytes()
        file_len = len(raw_bytes)

        # 1. JPEG Check: End of Image marker is FF D9
        if format_name.upper() in ("JPEG", "JPG"):
            eoi_pos = raw_bytes.rfind(b"\xFF\xD9")
            if eoi_pos != -1 and (file_len - (eoi_pos + 2)) > 128:
                trailing_bytes = file_len - (eoi_pos + 2)
                return Finding(
                    title="Appended Data Beyond JPEG EOI Marker (Steganography / Hidden Payload)",
                    detail=(
                        f"Identified {trailing_bytes} trailing bytes after the standard JPEG End-of-Image "
                        "(FF D9) marker. Appending binary archives, encrypted payloads, or scripts beyond "
                        "the visual EOF is a well-documented evasion technique that keeps images visually intact."
                    ),
                    severity="high",
                    weight=0.80,
                    evidence={"trailing_bytes": trailing_bytes, "eoi_offset": eoi_pos, "byte_offset": eoi_pos + 2},
                    category="structural",
                )

        # 2. PNG Check: Ends with IEND chunk
        elif format_name.upper() == "PNG":
            iend_marker = b"IEND\xaeB`\x82"
            iend_pos = raw_bytes.rfind(iend_marker)
            if iend_pos != -1 and (file_len - (iend_pos + len(iend_marker))) > 128:
                trailing_bytes = file_len - (iend_pos + len(iend_marker))
                return Finding(
                    title="Appended Data Beyond PNG IEND Chunk (Steganography / Hidden Payload)",
                    detail=(
                        f"Identified {trailing_bytes} trailing bytes after the PNG IEND termination chunk. "
                        "Data past IEND is ignored by standard decoders but can harbor hidden executable content."
                    ),
                    severity="high",
                    weight=0.80,
                    evidence={"trailing_bytes": trailing_bytes, "iend_offset": iend_pos, "byte_offset": iend_pos + len(iend_marker)},
                    category="structural",
                )
    except Exception:
        pass

    return None


# ==============================================================================
# Main Public Interface
# ==============================================================================

def analyze_image(
    file_path: Union[str, Path],
    generate_gradcam: bool = True,
    generate_ela: bool = True,
) -> ImageForensicReport:
    """
    Executes full static and machine-learning forensic inspection of an image file.

    Args:
        file_path: Path to target image.
        generate_gradcam: Whether to generate Grad-CAM explanation overlay.
        generate_ela: Whether to generate Error Level Analysis visualization.

    Returns:
        ImageForensicReport containing ML inference results, findings, visual evidence,
        EXIF data, and ELA metrics.
    """
    path = Path(file_path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Image file not found: {path}")

    # Resource safety check: Enforce maximum file size
    file_size = path.stat().st_size
    if file_size > MAX_UPLOAD_SIZE_BYTES:
        report = ImageForensicReport()
        report.findings.append(
            Finding(
                title="Image Size Exceeds Maximum Limit",
                detail=f"Image size ({file_size / (1024*1024):.2f} MB) exceeds maximum 20 MB ceiling.",
                severity="high",
                weight=0.90,
                evidence={"file_size": file_size},
            )
        )
        return report

    report = ImageForensicReport()
    findings: List[Finding] = []
    timeline: List[Dict[str, Any]] = []
    visual_evidence: Dict[str, str] = {}

    file_hash = compute_sha256(path)[:16]

    # Preserve original evidence specimen for frontend inspection and layer comparison
    orig_ext = path.suffix.lower()
    if not orig_ext or orig_ext not in (".jpg", ".jpeg", ".png", ".bmp", ".webp", ".tiff", ".tif"):
        orig_ext = ".png"
    orig_specimen_path = UPLOAD_TEMP_DIR / f"{file_hash}_original{orig_ext}"
    try:
        if not orig_specimen_path.exists():
            shutil.copyfile(path, orig_specimen_path)
        visual_evidence["original"] = str(orig_specimen_path)
    except Exception:
        pass

    # Open and validate image with Pillow
    try:
        # Enforce safe image pixel limit to prevent decompression bombs
        Image.MAX_IMAGE_PIXELS = 89478485
        with Image.open(path) as img:
            format_name = img.format or "UNKNOWN"
            width, height = img.size
            mode = img.mode

            report.image_geometry = {
                "format": format_name,
                "width": width,
                "height": height,
                "mode": mode,
                "aspect_ratio": round(width / max(1, height), 2),
                "file_size_bytes": file_size,
            }

            # 1. EXIF Metadata Extraction
            exif_data, exif_timeline, exif_findings = _extract_exif_data(img)
            report.exif_data = exif_data
            timeline.extend(exif_timeline)
            findings.extend(exif_findings)

            # Evaluate 9 Standard Metadata Fields (Task 2 & 4)
            icc_profile = img.info.get("icc_profile")
            meta_fields = [
                bool(exif_data.get("Make") or exif_data.get("Model")),
                bool(exif_data.get("DateTimeOriginal")),
                bool(exif_data.get("DateTimeDigitized")),
                bool(exif_data.get("DateTime")),
                bool(exif_data.get("GPSCoordinates") or exif_data.get("GPSInfo")),
                bool(width and height),
                bool(exif_data.get("Orientation")),
                bool(exif_data.get("Software")),
                bool(icc_profile or (mode in ("RGB", "RGBA"))),
            ]
            absent_meta_count = sum(1 for present in meta_fields if not present)

            # Populate standardized metadata dictionary for frontend examination
            report.metadata = {
                "format": format_name,
                "width": width,
                "height": height,
                "dimensions": f"{width} x {height}",
                "color_mode": mode,
                "color_space": "sRGB" if mode == "RGB" else mode,
                "has_icc_profile": bool(icc_profile),
                "icc_profile_size": len(icc_profile) if icc_profile else None,
                "camera_make": exif_data.get("Make"),
                "camera_model": exif_data.get("Model"),
                "datetime_original": exif_data.get("DateTimeOriginal"),
                "datetime_digitized": exif_data.get("DateTimeDigitized"),
                "datetime": exif_data.get("DateTime"),
                "orientation": exif_data.get("Orientation"),
                "software": exif_data.get("Software"),
                "gps_coordinates": exif_data.get("GPSCoordinates"),
                "gps_info": exif_data.get("GPSInfo"),
                "exif_fields": exif_data,
                "absent_fields_count": absent_meta_count,
            }

            # 1b. JPEG Structural & Compression History Analysis (Task 4)
            if format_name.upper() in ("JPEG", "JPG"):
                try:
                    jpeg_struct = analyze_jpeg_structure(
                        path,
                        img=img,
                        exif_present=bool(exif_data),
                        absent_meta_count=absent_meta_count,
                    )
                    report.jpeg_structure = jpeg_struct
                    report.metadata["jpeg_structure"] = jpeg_struct
                except Exception:
                    pass

            # 2. Trailing Appended Data (Steganography Check)
            trailing_finding = _check_trailing_data(path, format_name)
            if trailing_finding:
                findings.append(trailing_finding)

            # 3. Error Level Analysis (ELA) - Technically appropriate for lossy JPEG formats
            if generate_ela and format_name in ("JPEG", "JPG"):
                try:
                    ela_path = UPLOAD_TEMP_DIR / f"{file_hash}_ela.png"
                    ela_stats, saved_ela_path = compute_ela(img, ela_path, quality=95)
                    report.ela_stats = ela_stats
                    visual_evidence["ela"] = str(saved_ela_path)

                    # ELA heuristic anomaly threshold
                    if ela_stats["mean_error"] > 16.0 or ela_stats["std_error"] > 14.0:
                        findings.append(
                            Finding(
                                title="High Error Level Variance (ELA Anomaly)",
                                detail=(
                                    f"Error Level Analysis measured an anomalous mean error of {ela_stats['mean_error']} "
                                    f"and standard deviation of {ela_stats['std_error']}. Pronounced error level disparities "
                                    "suggest disparate JPEG compression histories, characteristic of spliced image regions."
                                ),
                                severity="medium",
                                weight=0.45,
                                evidence=ela_stats,
                                category="statistical",
                            )
                        )
                except Exception:
                    # Non-fatal ELA failure
                    pass

            # 4. Deep Learning Tampering Inference (EfficientNet-B0)
            try:
                model, meta = get_tamper_model()
                calib = get_calibration_params()
                temp = calib["temperature"]
                th_low = calib["threshold_low"]
                th_high = calib["threshold_high"]

                img_rgb = img.convert("RGB")
                input_tensor = IMAGE_TRANSFORM(img_rgb).unsqueeze(0)

                with torch.no_grad():
                    logits = model(input_tensor)

                # Task 1 Validation: Check if logits is None, NaN, or Inf
                is_invalid_logits = (
                    logits is None
                    or not isinstance(logits, torch.Tensor)
                    or torch.isnan(logits).any().item()
                    or torch.isinf(logits).any().item()
                )

                if is_invalid_logits:
                    report.ai_status = "unavailable"
                    report.ai_status_reason = "Model generated non-finite or empty logits."
                    ml_info = {
                        "ai_status": "unavailable",
                        "ai_status_reason": report.ai_status_reason,
                        "architecture": meta.get("architecture", "efficientnet_b0"),
                        "dataset": "CASIA 2.0 (Fine-tuned from ImageNet)",
                        "predicted_class": None,
                        "confidence": None,
                        "authentic_probability": None,
                        "tampered_probability": None,
                    }
                    report.ml_prediction = ml_info
                    findings.append(
                        Finding(
                            title="AI Tamper Screening Unavailable",
                            detail=(
                                f"Neural network tamper screening could not produce a valid output: {report.ai_status_reason} "
                                "Edit-detection confidence is reduced."
                            ),
                            severity="low",
                            weight=0.0,
                            evidence=ml_info,
                            category="inconclusive",
                        )
                    )
                else:
                    # Calibrate logits with Temperature Scaling (Task 7)
                    scaled_logits = logits / temp
                    probabilities = torch.softmax(scaled_logits, dim=1)[0]
                    p_authentic = float(probabilities[0].item())
                    p_tampered = float(probabilities[1].item())

                    # Task 1 Validation: Check probabilities finite and in [0, 1]
                    is_invalid_prob = (
                        math.isnan(p_authentic)
                        or math.isinf(p_authentic)
                        or math.isnan(p_tampered)
                        or math.isinf(p_tampered)
                        or not (0.0 <= p_authentic <= 1.0)
                        or not (0.0 <= p_tampered <= 1.0)
                    )

                    if is_invalid_prob:
                        report.ai_status = "unavailable"
                        report.ai_status_reason = "Computed tamper probability is non-finite or outside range [0, 1]."
                        ml_info = {
                            "ai_status": "unavailable",
                            "ai_status_reason": report.ai_status_reason,
                            "architecture": meta.get("architecture", "efficientnet_b0"),
                            "dataset": "CASIA 2.0 (Fine-tuned from ImageNet)",
                            "predicted_class": None,
                            "confidence": None,
                            "authentic_probability": None,
                            "tampered_probability": None,
                        }
                        report.ml_prediction = ml_info
                        findings.append(
                            Finding(
                                title="AI Tamper Screening Unavailable",
                                detail=(
                                    f"Neural network tamper screening output was non-finite: {report.ai_status_reason} "
                                    "Edit-detection checks are less reliable."
                                ),
                                severity="low",
                                weight=0.0,
                                evidence=ml_info,
                                category="inconclusive",
                            )
                        )
                    else:
                        # Model inference succeeded cleanly
                        report.ai_status = "active"
                        report.ai_status_reason = None

                        if p_tampered > th_high:
                            predicted_class = "Tampered"
                            confidence = p_tampered
                        elif p_tampered < th_low:
                            predicted_class = "Authentic"
                            confidence = p_authentic
                        else:
                            predicted_class = "Inconclusive"
                            confidence = p_tampered

                        is_calibrated = calib.get("is_calibrated", False)
                        calib_status = calib.get("status", "uncalibrated")

                        ml_info = {
                            "ai_status": "active",
                            "ai_status_reason": None,
                            "architecture": meta["architecture"],
                            "dataset": "CASIA 2.0 (Checkpoint)" if not is_calibrated else "CASIA 2.0 (Calibrated)",
                            "test_accuracy": round(meta.get("test_accuracy", 0.7137), 4),
                            "predicted_class": predicted_class,
                            "confidence": round(confidence, 4),
                            "authentic_probability": round(p_authentic, 4),
                            "tampered_probability": round(p_tampered, 4),
                            "temperature": temp,
                            "threshold_low": th_low,
                            "threshold_high": th_high,
                            "is_calibrated": is_calibrated,
                            "calibration_status": calib_status,
                        }
                        report.ml_prediction = ml_info

                        # Task 3: Cap ML finding at 0.50 points max
                        if predicted_class == "Tampered":
                            excess = max(0.0, (confidence - th_high) / max(0.01, (1.0 - th_high)))
                            ml_weight = min(0.50, 0.35 + 0.15 * excess)
                            ml_severity = "medium"

                            title = (
                                "Machine Learning Image Manipulation Indicator (Calibrated EfficientNet-B0)"
                                if is_calibrated
                                else "Machine Learning Image Manipulation Indicator (Experimental - Uncalibrated)"
                            )
                            detail = (
                                f"Calibrated EfficientNet-B0 classifier predicted 'Tampered' with "
                                f"{p_tampered * 100:.1f}% calibrated probability (Threshold: >{th_high * 100:.0f}%). "
                                "Notice: Machine learning predictions evaluate statistical correlation with "
                                "splicing and copy-move artifacts and are capped at moderate confidence."
                                if is_calibrated
                                else f"Experimental EfficientNet-B0 classifier predicted 'Tampered' with "
                                f"{p_tampered * 100:.1f}% raw probability (Provisional threshold: >{th_high * 100:.0f}%). "
                                "Notice: Model is uncalibrated pending formal validation on an independent test benchmark. "
                                "Raw probability does not constitute conclusive evidence of tampering."
                            )

                            findings.append(
                                Finding(
                                    title=title,
                                    detail=detail,
                                    severity=ml_severity,
                                    weight=ml_weight,
                                    evidence=ml_info,
                                    category="machine_learning",
                                )
                            )
                        elif predicted_class == "Inconclusive":
                            title = (
                                "Inconclusive Neural Tamper Screening (Calibrated)"
                                if is_calibrated
                                else "Inconclusive Neural Tamper Screening (Experimental - Uncalibrated)"
                            )
                            detail = (
                                f"Model evaluated spatial pixel features as uncertain ({p_tampered * 100:.1f}% probability, "
                                f"falling within the [{th_low * 100:.0f}%, {th_high * 100:.0f}%] calibrated inconclusive zone). "
                                "This is common on recompressed, low-contrast, or natural images."
                                if is_calibrated
                                else f"Model evaluated spatial pixel features as inconclusive ({p_tampered * 100:.1f}% raw probability, "
                                f"falling within the provisional [{th_low * 100:.0f}%, {th_high * 100:.0f}%] uncertainty band). "
                                "Model is uncalibrated. This uncertainty does not indicate manipulation."
                            )
                            findings.append(
                                Finding(
                                    title=title,
                                    detail=detail,
                                    severity="low",
                                    weight=0.0,
                                    evidence=ml_info,
                                    category="inconclusive",
                                )
                            )
                        else:
                            detail = (
                                f"EfficientNet-B0 evaluated spatial image features as consistent with authentic training distributions "
                                f"({p_authentic * 100:.1f}% confidence). Notice: Does not guarantee absence of subtle global edits."
                                if is_calibrated
                                else f"EfficientNet-B0 recorded low tamper probability ({p_authentic * 100:.1f}% authentic raw score). "
                                "Notice: Experimental uncalibrated model. Does not guarantee authenticity or absence of editing."
                            )
                            findings.append(
                                Finding(
                                    title="Machine Learning Consistency Assessment (Authentic)",
                                    detail=detail,
                                    severity="low",
                                    weight=0.0,
                                    evidence=ml_info,
                                    category="machine_learning",
                                )
                            )

                        # 5. Grad-CAM Visualization
                        if generate_gradcam and predicted_class == "Tampered":
                            try:
                                gradcam_path = UPLOAD_TEMP_DIR / f"{file_hash}_gradcam.png"
                                saved_cam_path = generate_gradcam_overlay(
                                    img_rgb, model, input_tensor, gradcam_path, target_class=1
                                )
                                visual_evidence["gradcam"] = str(saved_cam_path)
                            except Exception:
                                pass

            except FileNotFoundError as e:
                report.ai_status = "unavailable"
                report.ai_status_reason = "Trained model checkpoint missing."
                findings.append(
                    Finding(
                        title="Trained Model Checkpoint Unavailable",
                        detail=str(e),
                        severity="low",
                        weight=0.0,
                        evidence={"error": "ModelCheckpointMissing", "ai_status": "unavailable"},
                        category="inconclusive",
                    )
                )
            except Exception as e:
                report.ai_status = "unavailable"
                report.ai_status_reason = f"Model execution error: {str(e)}"
                findings.append(
                    Finding(
                        title="AI Tamper Screening Unavailable",
                        detail=f"Neural network tamper screening failed to execute: {str(e)}",
                        severity="low",
                        weight=0.0,
                        evidence={"error": str(e), "ai_status": "unavailable"},
                        category="inconclusive",
                    )
                )

    except Image.DecompressionBombError as e:
        findings.append(
            Finding(
                title="Image Decompression Bomb Hazard Detected",
                detail=f"Image dimensions exceed safety thresholds, indicating a potential decompression attack: {str(e)}",
                severity="high",
                weight=0.95,
                evidence={"error": str(e)},
                category="structural",
            )
        )
    except Exception as e:
        findings.append(
            Finding(
                title="Image Decoding Failure / Corrupted Media",
                detail=f"Failed to decode image content: {str(e)}",
                severity="medium",
                weight=0.50,
                evidence={"error": str(e)},
                category="inconclusive",
            )
        )

    report.findings = findings
    report.timeline = timeline
    report.visual_evidence = visual_evidence
    return report
