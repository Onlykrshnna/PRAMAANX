# PRAMAANX — AI Digital Document & Image Forensics Platform

[![Tests](https://img.shields.io/badge/pytest-91%20passed-brightgreen.svg)]()
[![Python](https://img.shields.io/badge/python-3.11-blue.svg)]()
[![FastAPI](https://img.shields.io/badge/FastAPI-0.135+-009688.svg)]()
[![PyTorch](https://img.shields.io/badge/PyTorch-2.6.0-EE4C2C.svg)]()
[![License](https://img.shields.io/badge/license-MIT-lightgrey.svg)]()

**PRAMAANX** (derived from the Sanskrit word *Pramāna*, meaning "proof" or "means of valid knowledge") is a portfolio-grade, zero-cost, self-owned AI and heuristic digital forensics platform. It inspects documents and images to identify image forgery, tampering, PDF structural exploits, Office document remote injection, metadata inconsistencies, and malicious payloads.

> **Strict Zero-Cost & Privacy Policy**: PRAMAANX does not depend on any paid or third-party APIs (no OpenAI, Anthropic Claude, Google Gemini, external OCR, or cloud scanners). All ML models, computer vision heuristics, and parsing engines execute entirely locally and on-premise.

---

## Table of Contents
1. [Supported File Formats](#supported-file-formats)
2. [Forensic Architecture & Phases](#forensic-architecture--phases)
3. [Security Boundaries & Limits](#security-boundaries--limits)
4. [API Endpoints Reference](#api-endpoints-reference)
5. [CURL Examples](#curl-examples)
6. [Local Installation & Setup](#local-installation--setup)
7. [Running Tests](#running-tests)
8. [Docker Deployment](#docker-deployment)

---

## Supported File Formats

| Category | Extensions | MIME Types |
| :--- | :--- | :--- |
| **Documents** | `.pdf` | `application/pdf` |
| **Images** | `.jpg`, `.jpeg`, `.png`, `.bmp`, `.tiff`, `.tif` | `image/jpeg`, `image/png`, `image/bmp`, `image/tiff` |
| **Office (OpenXML)** | `.docx`, `.xlsx`, `.pptx` | `application/vnd.openxmlformats-officedocument.*` |
| **Office (Legacy OLE)** | `.doc`, `.xls`, `.ppt` | `application/msword`, `application/vnd.ms-excel`, `application/vnd.ms-powerpoint`, `application/x-ole-storage` |
| **Archives** | `.zip` | `application/zip` |

---

## Forensic Architecture & Phases

```
PRAMAANX/
├── backend/
│   ├── analyzers/
│   │   ├── common.py     # Core forensic primitives (SHA-256, Entropy, Magic Bytes, Noisy-OR, ZIP screener)
│   │   ├── image.py      # Image tampering detection (EfficientNet-B0, Grad-CAM, ELA, EXIF, Trailing Data)
│   │   ├── pdf.py        # PDF structural inspection (Incremental updates, JS, Launch, Streams, Font anomaly)
│   │   ├── office.py     # Office OpenXML & OLE CFBF forensics (Remote templates, Macros, OLE, Hidden sheets)
│   │   └── malpdf.py     # 22-dimensional static PDF feature extraction engine (XGBoost ready)
│   ├── config.py         # Centralized security thresholds, limits, and MIME specifications
│   ├── main.py           # Production FastAPI REST application & safe streaming
│   ├── pipeline.py       # Orchestration pipeline with recursive embedded image inspection
│   ├── models/           # Local trained ML weights (CASIA 2.0 EfficientNet-B0: 16.3 MB)
│   │   └── image_tampering/pramaanx_efficientnet_best.pth
│   ├── Dockerfile        # Hardened non-root container configuration
│   └── tests/            # Automated test suite (91 comprehensive unit & integration tests)
├── training/             # Kaggle training notebooks (CASIA 2.0 transfer learning)
├── docs/                 # Architectural specifications
├── docker-compose.yml    # Multi-container orchestration definition
└── pytest.ini            # Pytest configuration
```

### Forensic Engines
- **Phase 1 — Core Primitives**:
  - Chunked SHA-256 cryptographic hashing.
  - Header magic-byte inspection (disarming extension-spoofing attacks).
  - Shannon byte entropy $H(X) = -\sum p(i) \log_2 p(i)$ to spot packed/encrypted steganography.
  - Hardened pre-extraction ZIP screening (preventing Zip Slip and Zip Bombs).
  - Multi-finding compounding risk scoring using calibrated **Noisy-OR**:
    $$P(\text{Tampered}) = 1 - \prod_{i=1}^{n} (1 - w_i)$$
- **Phase 2 — Document Forensics**:
  - **PDF Analyzer**: PyMuPDF AST parsing + raw binary token scan (`/JavaScript`, `/Launch`, `/EmbeddedFiles`, `/URI`, `/OpenAction`, `/AA`, `/XFA`, microscopic text fonts $\le 2.0\text{pt}$, revision counting via `%%EOF`).
  - **Office Analyzer**: OpenXML relationships, Remote Template Injection (`CVE-2017-0199`), external OLE packages, cloaked VBA macros, Excel `veryHidden` sheets, PowerPoint hidden slides, and white-on-white vanishing text.
- **Phase 4 — Computer Vision & Deep Learning**:
  - **EfficientNet-B0 Tamper Detection**: Fine-tuned on the CASIA 2.0 image tampering dataset (~71.37% test accuracy).
  - **Grad-CAM Saliency Maps**: Computes gradient-weighted class activation heatmaps off the final convolutional feature layer to highlight manipulated regions.
  - **Error Level Analysis (ELA)**: Computes compression artifact differentials at 95% JPEG quality to reveal multi-source splicing.
  - **Steganography & Trailing Data Detection**: Flags appended data beyond JPEG `FF D9` (EOI) and PNG `IEND` chunks.
  - **Static PDF Structural Feature Extraction**: 22-dimensional static feature vector extracted for supervised classification (XGBoost weights pending authentic malware corpora).
- **Phase 5 — FastAPI REST API & Batch Ingestion**:
  - High-throughput asynchronous endpoints with chunked stream validation.
  - Batch ingestion (up to 10 files) with individual failure isolation.
  - Hardened ZIP archive unpacking and automated multi-document analysis.
  - Secure visual evidence retrieval protecting against path traversal.

---

## Security Boundaries & Limits

| Parameter | Limit | Enforcement Layer |
| :--- | :--- | :--- |
| **Max Single Upload Size** | 20 MB (`20,971,520` bytes) | Streaming byte counter in `_save_upload_stream_safely()` |
| **Max Batch File Count** | 10 files | List length check in `analyze_batch()` |
| **Max Batch Aggregate Size** | 100 MB (`104,857,600` bytes) | Aggregate streaming accumulator |
| **Max ZIP Archive Entries** | 200 items | Pre-extraction check in `validate_zip_safety()` |
| **Max ZIP Uncompressed Size**| 100 MB | Pre-extraction sum in `validate_zip_safety()` |
| **Max ZIP Compression Ratio**| 10.0 : 1 | Pre-extraction ratio screening (Zip Bomb defense) |
| **Execution Security** | Read-only static analysis | Zero execution of macros, scripts, shell commands, or payloads |
| **Evidence Retrieval** | Strict regex `^[a-f0-9]{16}_(gradcam\|ela)\.png$` | Path traversal defense & directory sandboxing |

---

## API Endpoints Reference

| Method | Endpoint | Description | Status Codes |
| :--- | :--- | :--- | :--- |
| `GET` | `/` | API banner and documentation links | `200 OK` |
| `GET` | `/health` | Legacy health check | `200 OK` |
| `GET` | `/api/v1/health` | Comprehensive system health, model inventory, and analyzer capabilities | `200 OK` |
| `POST`| `/api/v1/analyze` | Single document/image forensic analysis | `200 OK`, `400 Bad Request`, `413 Content Too Large`, `415 Unsupported Media Type` |
| `POST`| `/api/v1/analyze/batch` | Batch inspection of up to 10 documents or images | `200 OK`, `400 Bad Request`, `413 Content Too Large` |
| `POST`| `/api/v1/analyze/archive` | Hardened batch analysis of a ZIP evidence archive | `200 OK`, `400 Bad Request`, `413 Content Too Large` |
| `GET` | `/api/v1/evidence/{evidence_type}/{filename}` | Stream Grad-CAM (`gradcam`) or ELA (`ela`) PNG visual evidence | `200 OK`, `400 Bad Request`, `404 Not Found` |

---

## CURL Examples

### 1. Health & Capability Inventory
```bash
curl -X GET "http://127.0.0.1:8000/api/v1/health"
```
**Example Response:**
```json
{
  "status": "operational",
  "version": "1.0.0",
  "timestamp": "2026-11-05T01:50:00Z",
  "models": {
    "image_tampering_efficientnet": {
      "loaded": true,
      "device": "cpu",
      "architecture": "EfficientNet-B0",
      "dataset": "CASIA 2.0",
      "test_accuracy": 0.7137
    },
    "malicious_pdf_xgboost": {
      "loaded": false,
      "status": "training_pending_authentic_corpora",
      "feature_dimensions": 22
    }
  },
  "capabilities": {
    "supported_extensions": [".bmp", ".doc", ".docx", ".jpeg", ".jpg", ".pdf", ".png", ".ppt", ".pptx", ".tif", ".tiff", ".xls", ".xlsx", ".zip"],
    "max_single_upload_mb": 20,
    "max_batch_files": 10,
    "max_batch_total_mb": 100,
    "max_zip_entries": 200,
    "max_zip_uncompressed_mb": 100,
    "visual_evidence_available": ["gradcam", "ela"]
  }
}
```

### 2. Single File Analysis (PDF / Office / Image)
```bash
curl -X POST "http://127.0.0.1:8000/api/v1/analyze" \
  -H "accept: application/json" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@sample_contract.pdf;type=application/pdf"
```

### 3. Batch Analysis (Multiple Files)
```bash
curl -X POST "http://127.0.0.1:8000/api/v1/analyze/batch" \
  -H "accept: application/json" \
  -H "Content-Type: multipart/form-data" \
  -F "files=@invoice.pdf" \
  -F "files=@id_badge.jpg" \
  -F "files=@quarterly_report.docx"
```

### 4. Hardened ZIP Archive Ingestion
```bash
curl -X POST "http://127.0.0.1:8000/api/v1/analyze/archive" \
  -H "accept: application/json" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@case_evidence_bundle.zip;type=application/zip"
```

### 5. Visual Evidence Retrieval (Grad-CAM / ELA PNGs)
```bash
curl -X GET "http://127.0.0.1:8000/api/v1/evidence/gradcam/0123456789abcdef_gradcam.png" \
  --output gradcam_overlay.png
```

---

## Local Installation & Setup

### Prerequisites
- Python 3.11+
- Virtual environment (`venv` or `uv`)

### 1. Clone & Set Up Virtual Environment
```bash
git clone https://github.com/Onlykrshnna/PRAMAANX.git
cd PRAMAANX

# Create and activate virtual environment
python -m venv .venv

# Windows PowerShell:
.\.venv\Scripts\Activate.ps1

# Linux / macOS:
source .venv/bin/activate
```

### 2. Install Dependencies
```bash
pip install -r backend/requirements.txt
```

### 3. Verify ML Checkpoint
Ensure the trained CASIA 2.0 checkpoint is present:
```
backend/models/image_tampering/pramaanx_efficientnet_best.pth
```

### 4. Run the REST API Server
```bash
uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```
Interactive Swagger API documentation will be available at:
`http://127.0.0.1:8000/docs`

---

## Running Tests

Run the full automated test suite covering all forensic analyzers, ML inference, guardrails, and API endpoints:

```bash
pytest backend/tests/ -v
```

All 91 unit and integration tests should pass cleanly without warnings or network dependencies.

---

## Docker Deployment

Build and run the production backend inside a hardened, non-root container:

```bash
# Build the Docker image
docker compose build

# Start the container detached
docker compose up -d

# Check operational logs
docker compose logs -f

# Verify service health
curl http://localhost:8000/api/v1/health
```

---

## License & Attribution
PRAMAANX is built for academic research and digital forensics education. MIT License.
