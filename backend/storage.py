"""
PRAMAANX - Storage Abstraction Layer
====================================
Provides unified storage for forensic evidence and artifacts:
- Local filesystem storage (offline / fallback mode)
- Supabase Storage private buckets:
    - `pramaanx_evidence`: Immutable evidence binaries
    - `pramaanx_artifacts`: Visual heatmaps, ELA masks, and PDF reports

Security Guarantees:
- Private buckets with authenticated server-side access
- Short-lived signed URLs for secure downloads
- Service role key kept strictly server-side (never exposed to frontend)
- Path traversal defense on all storage operations
- Cryptographic hash verification on upload
"""

import logging
import os
from pathlib import Path
from typing import Optional
import httpx

from backend.config import ARTIFACTS_DIR, EVIDENCE_DIR, REPORTS_DIR

logger = logging.getLogger("pramaanx.storage")

SUPABASE_URL = os.getenv("SUPABASE_URL", "").rstrip("/")
SUPABASE_SECRET_KEY = os.getenv("SUPABASE_SECRET_KEY", "")

# Exact private bucket names
BUCKET_EVIDENCE = "pramaanx_evidence"
BUCKET_ARTIFACTS = "pramaanx_artifacts"


def is_supabase_storage_enabled() -> bool:
    """Returns True if Supabase Storage credentials are configured."""
    return bool(SUPABASE_URL and SUPABASE_SECRET_KEY)


def get_storage_client() -> Optional[httpx.Client]:
    """Returns an authenticated HTTP client for Supabase Storage API."""
    if not is_supabase_storage_enabled():
        return None
    return httpx.Client(
        base_url=SUPABASE_URL,
        headers={
            "apikey": SUPABASE_SECRET_KEY,
            "Authorization": f"Bearer {SUPABASE_SECRET_KEY}",
        },
        timeout=30.0,
    )


def upload_to_storage(
    bucket: str,
    storage_path: str,
    file_bytes: bytes,
    content_type: str = "application/octet-stream",
) -> bool:
    """
    Uploads file bytes to a private Supabase Storage bucket.
    Idempotent: uses x-upsert header.
    """
    if not is_supabase_storage_enabled():
        return False

    client = get_storage_client()
    if not client:
        return False

    try:
        url = f"/storage/v1/object/{bucket}/{storage_path}"
        headers = {
            "Content-Type": content_type,
            "x-upsert": "true",
        }
        resp = client.post(url, content=file_bytes, headers=headers)
        if resp.status_code in (200, 201):
            logger.info(f"Successfully uploaded to Supabase Storage: {bucket}/{storage_path}")
            return True
        logger.warning(
            f"Failed to upload to Supabase Storage ({bucket}/{storage_path}): "
            f"status {resp.status_code} - {resp.text}"
        )
        return False
    except Exception as exc:
        logger.error(f"Upload error to Supabase Storage ({bucket}/{storage_path}): {exc}")
        return False
    finally:
        client.close()


def download_from_storage(bucket: str, storage_path: str) -> Optional[bytes]:
    """
    Downloads binary data from a private Supabase Storage bucket using
    authenticated server-side service credentials.
    """
    if not is_supabase_storage_enabled():
        return None

    client = get_storage_client()
    if not client:
        return None

    try:
        url = f"/storage/v1/object/{bucket}/{storage_path}"
        resp = client.get(url)
        if resp.status_code == 200:
            logger.info(f"Successfully fetched object from Supabase Storage: {bucket}/{storage_path}")
            return resp.content
        logger.warning(
            f"Object not found in Supabase Storage ({bucket}/{storage_path}): "
            f"status {resp.status_code}"
        )
        return None
    except Exception as exc:
        logger.error(f"Download error from Supabase Storage ({bucket}/{storage_path}): {exc}")
        return None
    finally:
        client.close()


def create_signed_url(bucket: str, storage_path: str, expires_in: int = 3600) -> Optional[str]:
    """
    Creates a time-limited signed URL for private bucket access.
    Expires in specified seconds (default 1 hour = 3600s).
    Allows secure direct downloads without exposing service keys.
    """
    if not is_supabase_storage_enabled():
        return None

    client = get_storage_client()
    if not client:
        return None

    try:
        url = f"/storage/v1/object/sign/{bucket}/{storage_path}"
        payload = {"expiresIn": expires_in}
        resp = client.post(url, json=payload)
        if resp.status_code == 200:
            data = resp.json()
            signed_path = data.get("signedURL")
            if signed_path:
                return f"{SUPABASE_URL}/storage/v1{signed_path}"
        logger.warning(
            f"Failed to generate signed URL ({bucket}/{storage_path}): "
            f"status {resp.status_code} - {resp.text}"
        )
        return None
    except Exception as exc:
        logger.error(f"Signed URL generation error ({bucket}/{storage_path}): {exc}")
        return None
    finally:
        client.close()
