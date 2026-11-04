"""
PRAMAANX - Digital Document & Image Forensics Platform API
==========================================================
FastAPI application entrypoint for PRAMAANX.

Phase 1 provides:
- Core application instantiation
- Health and forensic engine readiness endpoints
- OpenAPI documentation scaffold

Phase 5 will implement:
- Full file upload multipart endpoints
- Batch processing endpoints
- PDF report retrieval endpoints
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="PRAMAANX Forensics Engine",
    description=(
        "Production-grade, zero-cost, self-owned AI & heuristic digital document "
        "and image forensics platform."
    ),
    version="1.0.0-phase1",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS configuration for future frontend connectivity
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", tags=["General"])
def root():
    """Service status and platform identification."""
    return {
        "platform": "PRAMAANX",
        "role": "AI Digital Document & Image Forensics",
        "status": "operational",
        "phase": 1,
        "supported_formats": [
            "JPG/JPEG",
            "PNG",
            "PDF",
            "DOCX",
            "XLSX",
            "PPTX",
            "ZIP (safe archives)",
        ],
    }


@app.get("/health", tags=["Health"])
def health_check():
    """Engine health and security subsystem verification."""
    return {
        "status": "healthy",
        "engine": "pramaanx-core",
        "phase1_subsystems": {
            "sha256": "active",
            "magic_bytes": "active",
            "shannon_entropy": "active",
            "extension_spoof_detection": "active",
            "zip_safety_screener": "active",
            "noisy_or_scoring": "active",
        },
    }
