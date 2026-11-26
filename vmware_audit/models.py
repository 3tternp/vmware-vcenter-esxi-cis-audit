"""Shared data structures."""
from __future__ import annotations

from dataclasses import dataclass, asdict, field
from typing import Any

PASS, FAIL, WARN, MANUAL, ERROR, INFO = "PASS", "FAIL", "WARN", "MANUAL", "ERROR", "INFO"
STATUSES = (FAIL, WARN, ERROR, MANUAL, INFO, PASS)


@dataclass
class Result:
    check_id: str          # e.g. ESXI-ADV-001
    category: str          # CIS / EOL / PATCH
    area: str              # ESXi Host, VM, vCenter, vDS, Appliance, Lifecycle ...
    title: str
    target: str            # host / vm / vcenter name
    status: str
    actual: Any = ""
    expected: Any = ""
    remediation: str = ""
    level: str = ""        # CIS profile level (L1/L2) when applicable
    reference: str = ""

    def to_dict(self):
        d = asdict(self)
        d["actual"] = str(d["actual"])
        d["expected"] = str(d["expected"])
        return d


@dataclass
class ScanOptions:
    scan_hosts: bool = True
    scan_vms: bool = True
    scan_vcenter: bool = True
    scan_appliance: bool = True
    scan_network: bool = True
    snapshot_max_days: int = 3
    verify_tls: bool = False
    max_vms: int = 0       # 0 = unlimited


def make(check_id, area, title, target, status, actual="", expected="",
         remediation="", level="", category="CIS", reference=""):
    return Result(check_id, category, area, title, target, status, actual,
                  expected, remediation, level, reference)
