"""Loader for deterministic multi-OS Wazuh mock fixtures (linux, windows, macos)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

MOCK_DATA_FILE = Path(__file__).resolve().parent.parent / "mock_data" / "wazuh_mock.json"


def load_mock_wazuh_payload() -> dict[str, Any]:
    """Load and parse mock Wazuh endpoints and CVE/SCA_CIS findings from JSON fixture."""
    with MOCK_DATA_FILE.open("r", encoding="utf-8") as fh:
        data: dict[str, Any] = json.load(fh)
    return data
