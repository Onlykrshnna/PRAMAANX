# PRAMAANX — AI Digital Document & Image Forensics Platform

PRAMAANX is a portfolio-grade, zero-cost, self-owned AI & heuristic digital document and image forensics platform. It analyzes uploaded files to identify image manipulation, structural modifications, metadata inconsistencies, and malicious elements.

---

## Supported Formats
- Images: `JPG`, `JPEG`, `PNG`
- Documents: `PDF`
- Microsoft Office (OpenXML): `DOCX`, `XLSX`, `PPTX`
- Archives: `ZIP` (with strict security checks)

---

## Core Forensic Capabilities (Phase 1)
- **SHA-256 Hashing**: Cryptographic integrity and chain of custody tracking.
- **Magic-Byte Signature Detection**: Identifies true file format regardless of file extension.
- **Extension Mismatch Detection**: Flags extension spoofing attacks (e.g., executables disguised as PDFs).
- **Shannon Entropy Calculation**: Identifies encrypted payloads, high-density steganography, and packed data ($H(X) \in [0.0, 8.0]$).
- **ZIP Safety Screener**: Prevents Zip Slip (directory traversal attacks) and Zip Bombs (decompression denial-of-service).
- **Probabilistic Risk Scoring**: Noisy-OR formula combining independent forensic indicators into a calibrated 0–100 score.

---

## Architecture

```
PRAMAANX/
├── backend/
│   ├── analyzers/
│   │   ├── common.py     # Core forensic primitives & data models
│   │   ├── image.py      # Image forensic analyzer (Phase 4)
│   │   ├── pdf.py        # PDF forensics (Phase 2)
│   │   ├── office.py     # Office OpenXML forensics (Phase 2)
│   │   └── malpdf.py     # Malicious PDF detection (Phase 2 & 4)
│   ├── config.py         # Security limits & settings
│   ├── main.py           # FastAPI application
│   ├── pipeline.py       # Analysis pipeline orchestrator
│   ├── models/           # Local trained ML weights (Phase 3 & 4)
│   ├── report.py         # PDF forensic report generation (Phase 6)
│   ├── requirements.txt  # Python dependencies
│   ├── Dockerfile        # Hardened non-root container definition
│   └── tests/            # Test suite
├── training/             # Kaggle training notebooks & pipelines (Phase 3)
├── frontend/             # Frontend application (to be developed later)
├── docs/                 # Documentation & architectural diagrams
├── docker-compose.yml    # Container orchestration
└── README.md
```

---

## Docker Deployment

To build and run the backend using Docker:

```bash
# Build the image
docker compose build

# Start the service
docker compose up -d

# Verify health status
curl http://localhost:8000/health
```

---

## Running Unit Tests Locally

```bash
pytest backend/tests/ -v
```

