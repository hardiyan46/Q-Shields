"""Wazuh synchronization service supporting mock-first development and live API readiness."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import (
    Endpoint,
    EndpointStatus,
    Finding,
    FindingSource,
    FindingStatus,
    OSFamily,
    SeverityLevel,
)
from ..schemas import SyncResultOut
from .mock_wazuh import load_mock_wazuh_payload


class WazuhLiveSyncNotImplementedError(NotImplementedError):
    """Raised when WAZUH_USE_MOCK=false is requested before Sprint 4 live client wiring."""


def _is_mock_enabled() -> bool:
    """Read WAZUH_USE_MOCK from environment (defaults to true for mock-first vibe coding)."""
    return os.getenv("WAZUH_USE_MOCK", "true").strip().lower() in {"1", "true", "yes", "on"}


def _upsert_mock_data(db: Session, payload: dict[str, Any]) -> SyncResultOut:
    """Idempotently upsert endpoints and findings into PostgreSQL."""
    now = datetime.now(timezone.utc)
    endpoints_created = 0
    endpoints_updated = 0
    findings_created = 0
    findings_updated = 0

    for ep_data in payload.get("endpoints", []):
        agent_id = str(ep_data["wazuh_agent_id"])
        existing_ep = db.scalar(select(Endpoint).where(Endpoint.wazuh_agent_id == agent_id))

        os_family = OSFamily(ep_data["os_family"])
        ep_status = EndpointStatus(ep_data["status"])

        if existing_ep is None:
            endpoint = Endpoint(
                wazuh_agent_id=agent_id,
                hostname=ep_data["hostname"],
                ip_address=ep_data.get("ip_address"),
                os_family=os_family,
                os_name=ep_data["os_name"],
                os_version=ep_data["os_version"],
                architecture=ep_data.get("architecture"),
                agent_version=ep_data.get("agent_version"),
                status=ep_status,
                compliance_score=ep_data.get("compliance_score"),
                last_seen_at=now,
            )
            db.add(endpoint)
            db.flush()
            endpoints_created += 1
        else:
            existing_ep.hostname = ep_data["hostname"]
            existing_ep.ip_address = ep_data.get("ip_address")
            existing_ep.os_family = os_family
            existing_ep.os_name = ep_data["os_name"]
            existing_ep.os_version = ep_data["os_version"]
            existing_ep.architecture = ep_data.get("architecture")
            existing_ep.agent_version = ep_data.get("agent_version")
            existing_ep.status = ep_status
            existing_ep.compliance_score = ep_data.get("compliance_score")
            existing_ep.last_seen_at = now
            endpoint = existing_ep
            endpoints_updated += 1

        for f_data in ep_data.get("findings", []):
            source_type = FindingSource(f_data["source_type"])
            external_id = str(f_data["external_id"])
            severity = SeverityLevel(f_data["severity"])
            incoming_status = FindingStatus(f_data.get("status", FindingStatus.OPEN.value))

            existing_finding = db.scalar(
                select(Finding).where(
                    Finding.endpoint_id == endpoint.id,
                    Finding.source_type == source_type,
                    Finding.external_id == external_id,
                )
            )

            if existing_finding is None:
                finding = Finding(
                    endpoint_id=endpoint.id,
                    source_type=source_type,
                    external_id=external_id,
                    title=f_data["title"],
                    description=f_data["description"],
                    severity=severity,
                    status=incoming_status,
                    remediation_hint=f_data.get("remediation_hint"),
                    raw_payload=f_data.get("raw_payload"),
                    detected_at=now,
                )
                db.add(finding)
                findings_created += 1
            else:
                existing_finding.title = f_data["title"]
                existing_finding.description = f_data["description"]
                existing_finding.severity = severity
                existing_finding.remediation_hint = f_data.get("remediation_hint")
                existing_finding.raw_payload = f_data.get("raw_payload")
                # Preserve active workflow statuses (e.g. IN_PROGRESS / MANUAL_REQUIRED) across re-syncs
                if existing_finding.status == FindingStatus.OPEN:
                    existing_finding.status = incoming_status
                findings_updated += 1

    db.commit()

    return SyncResultOut(
        mode="mock",
        endpoints_synced=endpoints_created + endpoints_updated,
        endpoints_created=endpoints_created,
        endpoints_updated=endpoints_updated,
        findings_synced=findings_created + findings_updated,
        findings_created=findings_created,
        findings_updated=findings_updated,
        synced_at=now,
    )


def _sync_live_wazuh(_db: Session) -> SyncResultOut:
    """Placeholder for Sprint 4 live Wazuh Manager REST API integration."""
    api_url = os.getenv("WAZUH_API_URL", "https://wazuh-manager:55000")
    raise WazuhLiveSyncNotImplementedError(
        f"Live Wazuh sync to {api_url} is scheduled for Sprint 4. "
        "Set WAZUH_USE_MOCK=true in .env to use deterministic mock data."
    )


def sync_wazuh_data(db: Session) -> SyncResultOut:
    """Synchronize endpoints and CVE/SCA_CIS findings from mock fixtures or Wazuh Manager."""
    if _is_mock_enabled():
        payload = load_mock_wazuh_payload()
        return _upsert_mock_data(db, payload)
    return _sync_live_wazuh(db)
