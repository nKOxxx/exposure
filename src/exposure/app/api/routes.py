"""HTTP API (spec section 26). Thin adapter over the service layer.

There is deliberately no arbitrary ``/fetch?url=`` endpoint: retrieval only runs
against URLs associated with a scan or an explicit manual import.
"""

from __future__ import annotations

from typing import Any, cast

from fastapi import APIRouter, Request

from exposure.app.schemas import (
    CaseCreate,
    CaseEvent,
    FindingDecision,
    ProviderUpdate,
    ScanCreate,
    SubjectCreate,
)
from exposure.app.service import Service

router = APIRouter(prefix="/api/v1")


def _service(request: Request) -> Service:
    return cast(Service, request.app.state.service)


@router.get("/health")
def health() -> dict[str, Any]:
    return {"status": "ok"}


# -- subjects --------------------------------------------------------------- #


@router.post("/subjects")
def create_subject(payload: SubjectCreate, request: Request) -> dict[str, Any]:
    subject = _service(request).create_subject(payload)
    return _service(request)._subject_public(subject)


@router.get("/subjects")
def list_subjects(request: Request) -> list[dict[str, Any]]:
    return _service(request).list_subjects()


@router.get("/subjects/{subject_id}")
def get_subject(subject_id: str, request: Request) -> dict[str, Any]:
    return _service(request).subject_public(subject_id)


@router.delete("/subjects/{subject_id}")
def delete_subject(subject_id: str, request: Request) -> dict[str, Any]:
    _service(request).delete_subject(subject_id)
    return {"deleted": subject_id}


@router.get("/subjects/{subject_id}/dashboard")
def dashboard(subject_id: str, request: Request) -> dict[str, Any]:
    return _service(request).dashboard(subject_id)


# -- scans ------------------------------------------------------------------ #


@router.get("/subjects/{subject_id}/scan-plan")
def scan_plan(subject_id: str, request: Request) -> list[dict[str, Any]]:
    return _service(request).scan_plan(subject_id)


@router.post("/subjects/{subject_id}/scans")
def start_scan(subject_id: str, payload: ScanCreate, request: Request) -> dict[str, Any]:
    scan_id = _service(request).start_scan_background(subject_id, payload)
    return {"scan_id": scan_id, "status": "started"}


@router.get("/scans/{scan_id}")
def get_scan(scan_id: str, request: Request) -> dict[str, Any]:
    return _service(request).get_scan(scan_id)


# -- findings --------------------------------------------------------------- #


@router.get("/findings")
def list_findings(request: Request, subject_id: str | None = None) -> list[dict[str, Any]]:
    return _service(request).list_findings(subject_id)


@router.get("/subjects/{subject_id}/findings-by-page")
def findings_by_page(subject_id: str, request: Request) -> list[dict[str, Any]]:
    return _service(request).grouped_findings(subject_id)


@router.get("/findings/{finding_id}")
def get_finding(finding_id: str, request: Request) -> dict[str, Any]:
    return _service(request).finding_detail(finding_id)


@router.post("/findings/{finding_id}/decision")
def decide_finding(finding_id: str, payload: FindingDecision, request: Request) -> dict[str, Any]:
    return _service(request).decide_finding(finding_id, payload)


@router.get("/findings/{finding_id}/remediation-routes")
def routes_for(finding_id: str, request: Request) -> list[dict[str, Any]]:
    return _service(request).routes_for(finding_id)


# -- cases ------------------------------------------------------------------ #


@router.post("/cases")
def create_case(payload: CaseCreate, request: Request) -> dict[str, Any]:
    return _service(request).create_case(payload)


@router.get("/cases")
def list_cases(request: Request) -> list[dict[str, Any]]:
    return _service(request).list_cases()


@router.get("/cleanup")
def cleanup_board(request: Request) -> dict[str, Any]:
    return _service(request).cleanup_board()


@router.post("/cleanup/recheck")
def recheck_all(request: Request) -> dict[str, Any]:
    return _service(request).recheck_all()


@router.get("/cases/{case_id}")
def get_case(case_id: str, request: Request) -> dict[str, Any]:
    return _service(request).get_case(case_id)


@router.post("/cases/{case_id}/events")
def case_event(case_id: str, payload: CaseEvent, request: Request) -> dict[str, Any]:
    return _service(request).add_case_event(case_id, payload)


@router.post("/cases/{case_id}/verify")
def verify_case(case_id: str, request: Request) -> dict[str, Any]:
    return _service(request).verify_case(case_id)


# -- settings / providers --------------------------------------------------- #


@router.get("/settings/providers")
def list_providers(request: Request) -> list[dict[str, Any]]:
    return _service(request).list_providers()


@router.put("/settings/providers/{provider_id}")
def set_provider(provider_id: str, payload: ProviderUpdate, request: Request) -> dict[str, Any]:
    return _service(request).set_provider(provider_id, payload)


# -- exports ---------------------------------------------------------------- #


@router.post("/exports")
def export_report(request: Request, subject_id: str) -> dict[str, Any]:
    return _service(request).export_report(subject_id)


@router.get("/exports/report")
def report_json(request: Request, subject_id: str) -> dict[str, Any]:
    return _service(request).report_json(subject_id)


# -- danger zone ------------------------------------------------------------ #


@router.post("/danger/delete-all")
def delete_all(request: Request) -> dict[str, Any]:
    _service(request).delete_all()
    return {"deleted": "all"}
