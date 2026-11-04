"""
PRAMAANX - API Entrypoint & Health Unit Tests
==============================================
Tests the FastAPI endpoint handlers directly to verify platform
metadata, operational status, and Phase 1 subsystem readiness.
"""

from backend.main import root, health_check


def test_api_root_status():
    """Verify root endpoint returns platform metadata and active operational status."""
    data = root()
    assert data["platform"] == "PRAMAANX"
    assert data["status"] == "operational"
    assert data["phase"] == 1
    assert "PDF" in data["supported_formats"]


def test_api_health_check():
    """Verify healthcheck endpoint reports healthy status for Phase 1 subsystems."""
    data = health_check()
    assert data["status"] == "healthy"
    assert data["engine"] == "pramaanx-core"
    assert data["phase1_subsystems"]["sha256"] == "active"
    assert data["phase1_subsystems"]["magic_bytes"] == "active"
    assert data["phase1_subsystems"]["shannon_entropy"] == "active"
    assert data["phase1_subsystems"]["zip_safety_screener"] == "active"
    assert data["phase1_subsystems"]["noisy_or_scoring"] == "active"
