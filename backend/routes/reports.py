"""
PRAMAANX - Forensic Reports API Routes (Milestone E)
====================================================
Exposes endpoints for generating, listing, previewing, and downloading
immutable PDF forensic examination reports.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from backend.database import (
    get_investigation,
    get_report_by_id,
    get_report_file_path,
    list_reports,
)
from backend.reporting.generator import generate_case_report

reports_router = APIRouter(prefix="/api/v1", tags=["reports"])


class GenerateReportRequest(BaseModel):
    report_type: str = Field(
        default="detailed",
        description="Type of forensic report: 'executive' or 'detailed'.",
    )
    title: Optional[str] = Field(
        default=None,
        description="Optional custom title for the report.",
    )
    examiner: Optional[str] = Field(
        default="Forensic Analyst",
        description="Name or callsign of the examiner compiling the report.",
    )


@reports_router.post(
    "/investigations/{case_id}/reports",
    status_code=status.HTTP_201_CREATED,
    summary="Generate Forensic PDF Report",
    description="Compiles an immutable Executive Summary or Detailed Forensic Report for a given case.",
)
def create_investigation_report(
    case_id: str,
    payload: GenerateReportRequest,
) -> Dict[str, Any]:
    case = get_investigation(case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{case_id}' not found.",
        )

    clean_type = payload.report_type.strip().lower()
    if clean_type not in ("executive", "detailed"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid report_type. Must be 'executive' or 'detailed'.",
        )

    try:
        report_record = generate_case_report(
            case_id=case_id,
            report_type=clean_type,
            title=payload.title,
            generated_by=payload.examiner or "Forensic Analyst",
        )
        return {
            "status": "success",
            "report": report_record,
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Report generation failed: {str(e)}",
        )


@reports_router.get(
    "/reports",
    summary="List Generated Reports",
    description="Retrieves a paginated registry of all generated PDF forensic reports.",
)
def get_reports_catalog(
    case_id: Optional[str] = Query(None, description="Filter reports by investigation case ID."),
    report_type: Optional[str] = Query(None, description="Filter by 'executive' or 'detailed'."),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> Dict[str, Any]:
    res = list_reports(
        investigation_id=case_id,
        report_type=report_type,
        limit=limit,
        offset=offset,
    )
    return {
        "status": "success",
        "reports": res["reports"],
        "total": res["total"],
        "limit": limit,
        "offset": offset,
    }


@reports_router.get(
    "/reports/{report_id}",
    summary="Get Report Metadata",
    description="Retrieves metadata, SHA-256 fingerprint, and included examination records for a report.",
)
def get_report_metadata(report_id: str) -> Dict[str, Any]:
    report = get_report_by_id(report_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report '{report_id}' not found.",
        )
    return {
        "status": "success",
        "report": report,
    }


@reports_router.get(
    "/reports/{report_id}/download",
    summary="Download Report PDF",
    description="Downloads the finalized immutable PDF report with Content-Disposition attachment.",
)
def download_report_pdf(report_id: str):
    try:
        file_path = get_report_file_path(report_id)
        rec = get_report_by_id(report_id)
        filename = rec["stored_filename"] if rec else f"{report_id}.pdf"
        return FileResponse(
            path=str(file_path),
            filename=filename,
            media_type="application/pdf",
        )
    except FileNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@reports_router.get(
    "/reports/{report_id}/preview",
    summary="Preview Report PDF in Browser",
    description="Streams the immutable PDF report with inline disposition for in-browser rendering.",
)
def preview_report_pdf(report_id: str):
    try:
        file_path = get_report_file_path(report_id)
        rec = get_report_by_id(report_id)
        filename = rec["stored_filename"] if rec else f"{report_id}.pdf"
        return FileResponse(
            path=str(file_path),
            media_type="application/pdf",
            headers={"Content-Disposition": f"inline; filename={filename}"},
        )
    except FileNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

