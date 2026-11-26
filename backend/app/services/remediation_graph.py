"""LangGraph + local Ollama workflow for generating multi-OS remediation scripts with pre-change backup."""

from __future__ import annotations

import json
import os
import re
import uuid
from typing import Any, TypedDict

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_ollama import ChatOllama
from langgraph.graph import END, START, StateGraph
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from ..models import (
    Endpoint,
    Finding,
    FindingStatus,
    JobStatus,
    OSFamily,
    RemediationJob,
    ScriptLanguage,
    User,
)
from ..schemas import RemediationDraftSchema
from .audit import record_audit_log

MAX_GENERATION_RETRIES = 2


class OllamaServiceError(RuntimeError):
    """Base error raised when local Ollama inference cannot complete."""


class OllamaConnectionError(OllamaServiceError):
    """Raised when Ollama server is unreachable or times out."""


class OllamaModelNotFoundError(OllamaServiceError):
    """Raised when the configured OLLAMA_MODEL has not been pulled yet."""


class FindingNotFoundError(LookupError):
    """Raised when the requested finding does not exist."""


class RemediationGraphState(TypedDict, total=False):
    """Typed state passed across LangGraph nodes."""

    # Inputs (non-serializable DB session & user passed via state for node persistence)
    db: Session
    requested_by: User
    finding_id: uuid.UUID
    client_ip: str | None

    # Context built by Node 1
    job_id: uuid.UUID
    endpoint_id: uuid.UUID
    target_os: OSFamily
    script_language: ScriptLanguage
    backup_path: str
    finding_context: dict[str, Any]

    # Generation & validation loop (Nodes 2 & 3)
    draft: dict[str, Any] | None
    has_pre_backup: bool
    validation_errors: list[str]
    retry_count: int

    # Output persisted by Node 4
    saved_job: RemediationJob


def build_backup_path(os_family: OSFamily, job_id: uuid.UUID) -> str:
    """Return the mandatory unique per-job pre-change backup directory by OS family."""
    if os_family == OSFamily.LINUX:
        return f"/var/backups/q-shields/{job_id}/"
    if os_family == OSFamily.WINDOWS:
        return f"C:\\ProgramData\\Q-Shields\\backups\\{job_id}\\"
    return f"/Library/Application Support/Q-Shields/backups/{job_id}/"


def resolve_script_language(os_family: OSFamily) -> ScriptLanguage:
    """Map target OS family to the mandatory script dialect."""
    if os_family == OSFamily.LINUX:
        return ScriptLanguage.BASH
    if os_family == OSFamily.WINDOWS:
        return ScriptLanguage.POWERSHELL
    return ScriptLanguage.ZSH_BSD


def _build_os_system_prompt(os_family: OSFamily, backup_path: str) -> str:
    """Build strict OS-specific system instructions for ChatOllama."""
    common_rules = (
        "You are Q-Shields Security Remediation Architect. Generate safe, idempotent, production-grade "
        "remediation and rollback scripts strictly matching the target OS rules below.\n"
        f"Mandatory unique backup directory for this job: {backup_path}\n"
        "You MUST return structured JSON matching RemediationDraftSchema.\n"
        "CRITICAL RULES:\n"
        "1. NEVER assume interactive user input or GUI prompts.\n"
        "2. Perform pre-change backup into the exact backup directory BEFORE modifying any config, registry, plist, service, or package.\n"
        "3. Validate the change after applying it, and automatically revert from the backup directory if validation fails.\n"
        "4. Produce a separate standalone rollback_script referencing the exact backup directory above to restore the prior state.\n"
        "5. Populate backup_targets with every config file, registry key, plist, or package snapshot backed up.\n"
    )

    if os_family == OSFamily.LINUX:
        return (
            common_rules
            + "\nTARGET OS: linux (Bash .sh)\n"
            "- Start remediation_script and rollback_script with `#!/usr/bin/env bash` and `set -euo pipefail`.\n"
            "- Use absolute paths (e.g. `/etc/...`, `/usr/sbin/...`).\n"
            f"- Pre-backup MUST create `{backup_path}`, copy target config files with `cp -a`, compute `sha256sum`, "
            "and/or record installed packages (`dpkg -l` or `rpm -qa`) BEFORE making changes.\n"
            "- Include post-change validation and `trap` / explicit auto-revert from backup on failure.\n"
            "- Set requires_manual_mdm=false.\n"
        )

    if os_family == OSFamily.WINDOWS:
        return (
            common_rules
            + "\nTARGET OS: windows (PowerShell .ps1)\n"
            "- Start remediation_script and rollback_script with `$ErrorActionPreference = \"Stop\"`.\n"
            "- Assume execution under `NT AUTHORITY\\SYSTEM` (no interactive user session, no `HKCU:\\` user hive, no `$env:USERPROFILE`).\n"
            f"- Pre-backup MUST create `{backup_path}`, back up files via `Copy-Item`, export affected registry keys via `reg export` (or `reg.exe export`), "
            "record `Get-FileHash -Algorithm SHA256`, and/or snapshot installed packages/KBs (`Get-HotFix` / `Get-Package`) BEFORE making changes.\n"
            "- Use `try { ... } catch { ... }` to auto-revert from the backup directory if remediation or validation fails.\n"
            "- Set requires_manual_mdm=false.\n"
        )

    return (
        common_rules
        + "\nTARGET OS: macos (BSD-safe shell .sh / zsh / Bash 3.2)\n"
        "- Start remediation_script and rollback_script with `#!/bin/sh` (or `#!/bin/zsh`) and `set -eu`.\n"
        "- STRICTLY BSD-safe: NEVER use Linux-only commands (`systemctl`, `apt-get`, `yum`, `dnf`, GNU `sed -i` without `''`, `sha256sum`). Use macOS native utilities (`shasum -a 256`, `cp -p`, `defaults`, `plutil`, `launchctl`, `pkgutil`, `socketfilterfw`, `brew` for Homebrew).\n"
        "- Respect Apple System Integrity Protection (SIP), TCC, and corporate MDM policies.\n"
        "- If the finding is protected by SIP, TCC, or locked by MDM (e.g. Gatekeeper/SIP/MDM profile controls or `/System` binaries), "
        "DO NOT attempt unsafe local overrides: set `requires_manual_mdm=true`, explain the exact manual or MDM Configuration Profile (`.mobileconfig`) steps in `ai_explanation`, "
        "and keep `remediation_script` / `rollback_script` as safe non-destructive informational stubs referencing the backup path.\n"
        f"- If safe via CLI, pre-backup MUST create `{backup_path}`, copy allowed files/plists with `cp -p` or export `defaults` / `tar`, "
        "record `shasum -a 256`, validate after change, and auto-revert on failure.\n"
    )


def validate_script_backup_contract(
    *,
    os_family: OSFamily,
    backup_path: str,
    draft: RemediationDraftSchema,
) -> list[str]:
    """Programmatically verify pre-change backup, OS safety rules, and rollback contract."""
    errors: list[str] = []
    rem = draft.remediation_script or ""
    rb = draft.rollback_script or ""
    rem_lower = rem.lower()
    rb_lower = rb.lower()

    # Special safe handling for macOS findings blocked by SIP/TCC/MDM
    if os_family == OSFamily.MACOS and draft.requires_manual_mdm:
        if not draft.ai_explanation.strip():
            errors.append("ai_explanation must explain required manual/MDM steps when requires_manual_mdm=True.")
        return errors

    # Check backup_path reference (allow optional trailing slash variance)
    normalized_path = backup_path.rstrip("\\/").lower()
    if normalized_path not in rem_lower:
        errors.append(f"remediation_script does not reference mandatory backup_path '{backup_path}'.")
    if normalized_path not in rb_lower:
        errors.append(f"rollback_script does not reference mandatory backup_path '{backup_path}'.")

    if not draft.backup_targets:
        errors.append("backup_targets must list at least one file, registry key, plist, or package snapshot.")

    if os_family == OSFamily.LINUX:
        if "set -euo pipefail" not in rem_lower:
            errors.append("Linux bash script must include 'set -euo pipefail'.")
        if not re.search(r"\b(cp|tar|dpkg|rpm|sha256sum)\b", rem_lower):
            errors.append("Linux remediation_script must contain pre-change backup command (cp/tar/dpkg/rpm).")
        if not re.search(r"\b(trap|revert|restore|cp\s+-a)\b", rem_lower):
            errors.append("Linux remediation_script must include auto-revert logic on validation failure.")

    elif os_family == OSFamily.WINDOWS:
        if "$erroractionpreference" not in rem_lower or "stop" not in rem_lower:
            errors.append("Windows PowerShell script must set '$ErrorActionPreference = \"Stop\"'.")
        if not re.search(r"(copy-item|reg(\.exe)?\s+export|get-filehash|get-hotfix|get-package)", rem_lower):
            errors.append("Windows remediation_script must contain pre-change backup command (Copy-Item/reg export/Get-FileHash).")
        if not re.search(r"\b(catch|revert|restore|reg(\.exe)?\s+import)\b", rem_lower):
            errors.append("Windows remediation_script must include try/catch auto-revert logic.")

    elif os_family == OSFamily.MACOS:
        if not re.search(r"set\s+-[a-z]*e[a-z]*u|set\s+-eu", rem_lower):
            errors.append("macOS shell script must include 'set -eu'.")
        if re.search(r"\b(systemctl|apt-get|yum|dnf)\b", rem_lower):
            errors.append("macOS script must not contain Linux-only commands (systemctl, apt-get, yum, dnf).")
        if not re.search(r"\b(cp|defaults|tar|shasum|plutil|pkgutil)\b", rem_lower):
            errors.append("macOS remediation_script must contain BSD-safe backup command (cp/defaults/tar/shasum).")
        if not re.search(r"\b(revert|restore|trap|if\s+!)\b", rem_lower):
            errors.append("macOS remediation_script must include auto-revert logic on validation failure.")

    return errors


def _build_ollama_client() -> ChatOllama:
    base_url = os.getenv("OLLAMA_BASE_URL", "http://ollama:11434").strip()
    model = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:7b").strip()
    return ChatOllama(
        model=model,
        base_url=base_url,
        temperature=0.1,
    )


def _classify_ollama_exception(exc: Exception) -> OllamaServiceError:
    """Translate Ollama client/HTTP errors into friendly actionable exceptions."""
    model = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:7b").strip()
    base_url = os.getenv("OLLAMA_BASE_URL", "http://ollama:11434").strip()
    msg = str(exc).lower()

    if "not found" in msg and ("model" in msg or "pull" in msg or "404" in msg):
        return OllamaModelNotFoundError(
            f"Model Ollama '{model}' belum tersedia di {base_url}. "
            f"Jalankan: docker compose -f docker-compose.app.yml exec ollama ollama pull {model}"
        )

    return OllamaConnectionError(
        f"Gagal terhubung ke Ollama di {base_url} (model '{model}'): {exc}. "
        f"Pastikan service ollama berjalan dan model sudah di-pull dengan: "
        f"docker compose -f docker-compose.app.yml exec ollama ollama pull {model}"
    )


# ==============================================================================
# LANGGRAPH NODES
# ==============================================================================


def node_build_context(state: RemediationGraphState) -> dict[str, Any]:
    """Node 1: Load Finding + Endpoint context and assign deterministic job_id & backup_path."""
    db = state["db"]
    finding_id = state["finding_id"]

    finding = db.scalar(
        select(Finding)
        .options(selectinload(Finding.endpoint))
        .where(Finding.id == finding_id)
    )
    if finding is None:
        raise FindingNotFoundError(f"Finding {finding_id} not found")

    endpoint: Endpoint = finding.endpoint
    job_id = uuid.uuid4()
    backup_path = build_backup_path(endpoint.os_family, job_id)
    script_language = resolve_script_language(endpoint.os_family)

    finding_context: dict[str, Any] = {
        "job_id": str(job_id),
        "endpoint": {
            "hostname": endpoint.hostname,
            "os_family": endpoint.os_family.value,
            "os_name": endpoint.os_name,
            "os_version": endpoint.os_version,
            "architecture": endpoint.architecture,
        },
        "finding": {
            "source_type": finding.source_type.value,
            "external_id": finding.external_id,
            "severity": finding.severity.value,
            "title": finding.title,
            "description": finding.description,
            "remediation_hint": finding.remediation_hint,
            "raw_payload": finding.raw_payload,
        },
        "backup_path": backup_path,
        "script_language": script_language.value,
    }

    return {
        "job_id": job_id,
        "endpoint_id": endpoint.id,
        "target_os": endpoint.os_family,
        "script_language": script_language,
        "backup_path": backup_path,
        "finding_context": finding_context,
        "retry_count": 0,
        "validation_errors": [],
        "has_pre_backup": False,
    }


def node_generate_scripts(state: RemediationGraphState) -> dict[str, Any]:
    """Node 2: Invoke local ChatOllama with structured output to draft remediation & rollback."""
    os_family = state["target_os"]
    backup_path = state["backup_path"]
    context_json = json.dumps(state["finding_context"], indent=2)
    prior_errors = state.get("validation_errors") or []

    system_prompt = _build_os_system_prompt(os_family, backup_path)
    user_prompt = (
        "Generate a remediation draft for the following Wazuh finding and endpoint context:\n\n"
        f"{context_json}\n"
    )
    if prior_errors:
        joined = "\n- ".join(prior_errors)
        user_prompt += (
            "\nPREVIOUS DRAFT FAILED SAFETY VALIDATION. Fix ALL issues below:\n"
            f"- {joined}\n"
        )

    llm = _build_ollama_client().with_structured_output(RemediationDraftSchema)

    try:
        result = llm.invoke(
            [
                SystemMessage(content=system_prompt),
                HumanMessage(content=user_prompt),
            ]
        )
        draft = (
            result
            if isinstance(result, RemediationDraftSchema)
            else RemediationDraftSchema.model_validate(result)
        )
    except (ValidationError, json.JSONDecodeError) as exc:
        return {
            "draft": None,
            "validation_errors": [f"Structured output validation error: {exc}"],
            "retry_count": state.get("retry_count", 0) + 1,
        }
    except Exception as exc:
        raise _classify_ollama_exception(exc) from exc

    return {
        "draft": draft.model_dump(),
    }


def node_validate_backup_guard(state: RemediationGraphState) -> dict[str, Any]:
    """Node 3: Programmatically verify pre-change backup & OS constraints."""
    raw_draft = state.get("draft")
    if raw_draft is None:
        return {
            "has_pre_backup": False,
        }

    draft = RemediationDraftSchema.model_validate(raw_draft)
    os_family = state["target_os"]
    backup_path = state["backup_path"]

    errors = validate_script_backup_contract(
        os_family=os_family,
        backup_path=backup_path,
        draft=draft,
    )

    if errors:
        return {
            "has_pre_backup": False,
            "validation_errors": errors,
            "retry_count": state.get("retry_count", 0) + 1,
        }

    # For macOS SIP/TCC/MDM blocked items, keep has_pre_backup=False so automated Approve remains locked
    if os_family == OSFamily.MACOS and draft.requires_manual_mdm:
        return {
            "has_pre_backup": False,
            "validation_errors": [],
        }

    return {
        "has_pre_backup": True,
        "validation_errors": [],
    }


def _route_after_validation(state: RemediationGraphState) -> str:
    """Retry script generation up to MAX_GENERATION_RETRIES if backup validation failed."""
    if state.get("validation_errors") and state.get("retry_count", 0) < MAX_GENERATION_RETRIES:
        return "retry_generate"
    return "save_job"


def node_save_pending_approval(state: RemediationGraphState) -> dict[str, Any]:
    """Node 4: Persist PENDING_APPROVAL job to PostgreSQL and stop for Human-in-the-Loop."""
    db = state["db"]
    requested_by = state["requested_by"]
    os_family = state["target_os"]
    backup_path = state["backup_path"]

    raw_draft = state.get("draft")
    if raw_draft is not None:
        draft = RemediationDraftSchema.model_validate(raw_draft)
    else:
        # Fallback record if structured output repeatedly failed; locked with has_pre_backup=False
        draft = RemediationDraftSchema(
            remediation_script="# Generation failed structured validation; regenerate draft.",
            rollback_script="# No rollback script available.",
            ai_explanation="; ".join(state.get("validation_errors") or ["LLM output invalid"]),
            risk_level="HIGH",
            requires_reboot=False,
            requires_manual_mdm=(os_family == OSFamily.MACOS),
            backup_targets=[],
        )

    job = RemediationJob(
        id=state["job_id"],
        endpoint_id=state["endpoint_id"],
        finding_id=state["finding_id"],
        target_os=os_family,
        script_language=state["script_language"],
        remediation_script=draft.remediation_script,
        rollback_script=draft.rollback_script,
        ai_explanation=draft.ai_explanation,
        risk_level=draft.risk_level,
        requires_reboot=draft.requires_reboot,
        requires_manual_mdm=draft.requires_manual_mdm,
        backup_path=backup_path,
        backup_targets=draft.backup_targets,
        has_pre_backup=bool(state.get("has_pre_backup", False)),
        status=JobStatus.PENDING_APPROVAL,
        requested_by_id=requested_by.id,
    )
    db.add(job)

    finding = db.scalar(select(Finding).where(Finding.id == state["finding_id"]))
    if finding is not None:
        finding.status = FindingStatus.IN_PROGRESS

    record_audit_log(
        db,
        action="GENERATE_REMEDIATION_JOB",
        resource_type="remediation_job",
        resource_id=str(job.id),
        actor_user=requested_by,
        ip_address=state.get("client_ip"),
        details={
            "finding_id": str(state["finding_id"]),
            "target_os": os_family.value,
            "has_pre_backup": job.has_pre_backup,
            "requires_manual_mdm": job.requires_manual_mdm,
            "status": JobStatus.PENDING_APPROVAL.value,
        },
    )
    db.commit()
    db.refresh(job)
    return {"saved_job": job}


def _compile_remediation_graph():
    """Compile the LangGraph workflow ending at Human-in-the-Loop PENDING_APPROVAL."""
    graph = StateGraph(RemediationGraphState)
    graph.add_node("build_context", node_build_context)
    graph.add_node("generate_scripts", node_generate_scripts)
    graph.add_node("validate_backup_guard", node_validate_backup_guard)
    graph.add_node("save_pending_approval", node_save_pending_approval)

    graph.add_edge(START, "build_context")
    graph.add_edge("build_context", "generate_scripts")
    graph.add_edge("generate_scripts", "validate_backup_guard")
    graph.add_conditional_edges(
        "validate_backup_guard",
        _route_after_validation,
        {
            "retry_generate": "generate_scripts",
            "save_job": "save_pending_approval",
        },
    )
    graph.add_edge("save_pending_approval", END)
    return graph.compile()


remediation_workflow = _compile_remediation_graph()


def run_remediation_generation(
    db: Session,
    *,
    finding_id: uuid.UUID,
    requested_by: User,
    client_ip: str | None = None,
) -> RemediationJob:
    """Execute the LangGraph remediation workflow and return the PENDING_APPROVAL job."""
    final_state = remediation_workflow.invoke(
        {
            "db": db,
            "finding_id": finding_id,
            "requested_by": requested_by,
            "client_ip": client_ip,
        }
    )
    return final_state["saved_job"]
