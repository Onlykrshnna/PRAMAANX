"""
PRAMAANX - Static PDF Feature Extractor & ML Interface (Phase 4)
================================================================
Extracts standardized structural feature vectors from PDF files for ML-based
maliciousness classification (XGBoost).

Implementation & Policy Compliance Note:
-----------------------------------------
Per PRAMAANX zero-cost/self-owned AI policy and Section 6 instructions:
1. No synthetic training data or fabricated model predictions are permitted.
2. The 22-dimensional static structural feature extraction engine is fully implemented here.
3. If an authentic trained XGBoost model (`backend/models/malpdf_xgb.json`) is not present,
   the analyzer extracts and returns the reproducible feature vector without inventing fake scores,
   and explicitly notes that model training on legitimate corpora remains pending.
4. Static heuristic and rule-based PDF analysis in `backend/analyzers/pdf.py` remains the primary
   operational engine.
"""

from dataclasses import dataclass, field
import json
import math
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple, Union

import pymupdf

from backend.analyzers.common import Finding, compute_shannon_entropy


from backend.config import PDF_XGB_MODEL_PATH as MODEL_PATH


@dataclass
class MaliciousPdfReport:
    """Standardized output of the PDF feature extractor and ML classifier interface."""
    findings: List[Finding] = field(default_factory=list)
    features: Dict[str, float] = field(default_factory=dict)
    is_model_available: bool = False
    predicted_label: Optional[str] = None
    prediction_probability: Optional[float] = None


def extract_pdf_features(file_path: Union[str, Path]) -> Dict[str, float]:
    """
    Extracts a 22-dimensional static structural feature vector from a PDF document.

    Features:
    ---------
    1.  file_size_kb: File size in Kilobytes.
    2.  entropy: Global Shannon byte entropy (0.0 to 8.0).
    3.  page_count: Total pages reported by DOM parser.
    4.  obj_count: Raw count of 'obj' declarations.
    5.  endobj_count: Raw count of 'endobj' declarations.
    6.  stream_count: Raw count of 'stream' data blocks.
    7.  endstream_count: Raw count of 'endstream' terminators.
    8.  xref_count: Count of 'xref' tables.
    9.  startxref_count: Count of 'startxref' offset pointers.
    10. eof_count: Count of '%%EOF' markers (indicator of revisions).
    11. javascript_count: Count of '/JavaScript' tokens.
    12. js_count: Count of '/JS' tokens.
    13. launch_count: Count of '/Launch' directives.
    14. embedded_files_count: Count of '/EmbeddedFiles' or '/EF' tokens.
    15. openaction_count: Count of '/OpenAction' automatic execution triggers.
    16. aa_count: Count of '/AA' (Additional Actions) triggers.
    17. acroform_count: Count of '/AcroForm' interactive form elements.
    18. xfa_count: Count of '/XFA' dynamic forms tokens.
    19. uri_count: Count of '/URI' hyperlinks.
    20. encrypt_count: Count of '/Encrypt' dictionary markers.
    21. obj_mismatch_ratio: Absolute difference between 'obj' and 'endobj'.
    22. stream_mismatch_ratio: Absolute difference between 'stream' and 'endstream'.
    """
    path = Path(file_path).resolve()
    raw_bytes = path.read_bytes()
    file_size_kb = len(raw_bytes) / 1024.0

    # 1. Entropy
    entropy = compute_shannon_entropy(raw_bytes)

    # 2. Token Counts via regex
    def count_pattern(pattern: bytes) -> int:
        return len(re.findall(pattern, raw_bytes))

    obj_count = count_pattern(rb"\bobj\b")
    endobj_count = count_pattern(rb"\bendobj\b")
    stream_count = count_pattern(rb"\bstream\b")
    endstream_count = count_pattern(rb"\bendstream\b")
    xref_count = count_pattern(rb"\bxref\b")
    startxref_count = count_pattern(rb"\bstartxref\b")
    eof_count = count_pattern(b"%%EOF")

    js_full_count = count_pattern(rb"/JavaScript\b")
    js_short_count = count_pattern(rb"/JS\b")
    launch_count = count_pattern(rb"/Launch\b")
    ef_count = count_pattern(rb"/(?:EmbeddedFiles|EF)\b")
    openaction_count = count_pattern(rb"/OpenAction\b")
    aa_count = count_pattern(rb"/AA\b")
    acroform_count = count_pattern(rb"/AcroForm\b")
    xfa_count = count_pattern(rb"/XFA\b")
    uri_count = count_pattern(rb"/URI\b")
    encrypt_count = count_pattern(rb"/Encrypt\b")

    # 3. DOM-level page count
    page_count = 0
    try:
        doc = pymupdf.open(path)
        page_count = doc.page_count
        doc.close()
    except Exception:
        page_count = 0

    features = {
        "file_size_kb": round(file_size_kb, 3),
        "entropy": round(entropy, 4),
        "page_count": float(page_count),
        "obj_count": float(obj_count),
        "endobj_count": float(endobj_count),
        "stream_count": float(stream_count),
        "endstream_count": float(endstream_count),
        "xref_count": float(xref_count),
        "startxref_count": float(startxref_count),
        "eof_count": float(eof_count),
        "javascript_count": float(js_full_count),
        "js_count": float(js_short_count),
        "launch_count": float(launch_count),
        "embedded_files_count": float(ef_count),
        "openaction_count": float(openaction_count),
        "aa_count": float(aa_count),
        "acroform_count": float(acroform_count),
        "xfa_count": float(xfa_count),
        "uri_count": float(uri_count),
        "encrypt_count": float(encrypt_count),
        "obj_mismatch_ratio": float(abs(obj_count - endobj_count)),
        "stream_mismatch_ratio": float(abs(stream_count - endstream_count)),
    }
    return features


def analyze_malicious_pdf(file_path: Union[str, Path]) -> MaliciousPdfReport:
    """
    Performs static feature extraction and checks for trained ML classifier.
    """
    path = Path(file_path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"PDF file not found: {path}")

    features = extract_pdf_features(path)
    report = MaliciousPdfReport(features=features)

    # Check if legitimate trained model weights exist
    if MODEL_PATH.is_file():
        try:
            import xgboost as xgb
            bst = xgb.Booster()
            bst.load_model(str(MODEL_PATH))
            report.is_model_available = True

            # Prepare feature DMatrix
            feature_order = list(features.keys())
            feature_values = [[features[k] for k in feature_order]]
            dmat = xgb.DMatrix(feature_values, feature_names=feature_order)
            preds = bst.predict(dmat)
            prob_malicious = float(preds[0])
            report.prediction_probability = prob_malicious
            report.predicted_label = "Malicious" if prob_malicious >= 0.5 else "Benign"

            if report.predicted_label == "Malicious":
                report.findings.append(
                    Finding(
                        title="Machine Learning PDF Anomaly Indicator (XGBoost)",
                        detail=(
                            f"Static XGBoost model predicted malicious structural anomaly with "
                            f"{prob_malicious * 100:.1f}% probability based on structural vector."
                        ),
                        severity="high" if prob_malicious >= 0.8 else "medium",
                        weight=0.75 if prob_malicious >= 0.8 else 0.50,
                        evidence={"probability": prob_malicious, "features": features},
                        category="machine_learning",
                    )
                )
        except Exception as e:
            report.findings.append(
                Finding(
                    title="XGBoost Inference Failure",
                    detail=f"Failed to execute XGBoost inference: {str(e)}",
                    severity="low",
                    weight=0.10,
                    evidence={"error": str(e)},
                    category="inconclusive",
                )
            )
    else:
        # Per project rule: Do not invent fake predictions. State that model training is pending.
        report.is_model_available = False
        report.findings.append(
            Finding(
                title="PDF ML Model Training Pending (Feature Vector Extracted)",
                detail=(
                    "Static PDF structural feature vector was successfully extracted (22 features). "
                    "In accordance with project integrity rules, no synthetic or fabricated model predictions "
                    "are generated. Supervised XGBoost classifier weights (`malpdf_xgb.json`) remain pending "
                    "training on authentic malware corpora."
                ),
                severity="low",
                weight=0.0,
                evidence={"extracted_features": features},
                category="inconclusive",
            )
        )

    return report
