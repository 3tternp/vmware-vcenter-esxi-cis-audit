"""End-of-life and missing-patch assessment."""
from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path

from .models import PASS, FAIL, WARN, INFO, make
from .connector import prop

DATA_DIR = Path(__file__).parent / "data"
USER_DIR = Path(os.path.expanduser("~")) / ".vmware_audit"
WARN_DAYS = 180

ONLINE_SLUGS = {"esxi": ["vmware-esxi", "esxi"], "vcenter": ["vmware-vcenter", "vcenter", "vmware-vsphere"]}


def _load(name):
    """User copy (~/.vmware_audit) overrides the bundled copy."""
    for p in (USER_DIR / name, DATA_DIR / name):
        if p.exists():
            with open(p, encoding="utf-8") as f:
                return json.load(f)
    return {}


def load_eol():
    return _load("eol.json")


def load_builds():
    return _load("builds.json")


def save_user_json(name, data):
    USER_DIR.mkdir(exist_ok=True)
    with open(USER_DIR / name, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def import_json_file(path, log=lambda m: None):
    """Install a user supplied eol.json or builds.json (detected by content)."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    isbuild = isinstance(data.get("esxi"), dict)
    name = "builds.json" if isbuild else "eol.json"
    save_user_json(name, data)
    log(f"Imported {path} as {name}")
    return name


def fetch_eol_online(log=lambda m: None, timeout=15):
    """Refresh EOL dates from endoflife.date; falls back silently to bundled data."""
    import requests
    data = load_eol()
    changed = 0
    for product, slugs in ONLINE_SLUGS.items():
        for slug in slugs:
            try:
                r = requests.get(f"https://endoflife.date/api/{slug}.json", timeout=timeout,
                                 headers={"User-Agent": "vmware-audit-tool"})
                if r.status_code != 200:
                    continue
                rows = {str(x.get("cycle")): x for x in data.get(product, [])}
                for item in r.json():
                    cyc = str(item.get("cycle"))
                    eol = item.get("eol")
                    if not isinstance(eol, str):
                        continue
                    row = rows.setdefault(cyc, {"cycle": cyc, "tech_guidance": ""})
                    if row.get("eogs") != eol:
                        row["eogs"] = eol
                        changed += 1
                data[product] = sorted(rows.values(), key=lambda x: [int(p) if p.isdigit() else 0 for p in x["cycle"].split(".")])
                log(f"EOL data for {product} refreshed from endoflife.date/{slug}")
                break
            except Exception as e:
                log(f"endoflife.date/{slug}: {e}")
    save_user_json("eol.json", data)
    return changed


def train(version: str) -> str:
    parts = str(version).split(".")
    return ".".join(parts[:2])


def _d(s):
    try:
        return dt.date.fromisoformat(s)
    except (TypeError, ValueError):
        return None


def eol_result(product, label, version, target, today=None):
    """product: 'esxi' | 'vcenter'."""
    today = today or dt.date.today()
    tr = train(version)
    row = next((r for r in load_eol().get(product, []) if r["cycle"] == tr), None)
    title = f"{label} {tr} support lifecycle"
    if not row or not _d(row.get("eogs")):
        return make(f"EOL-{product.upper()}", "Lifecycle", title, target, WARN, f"version {version}: no EOL data",
                    "known EOL date", "Update EOL data (Data > Fetch EOL online) or add the release to eol.json.",
                    category="EOL")
    eogs, tg = _d(row["eogs"]), _d(row.get("tech_guidance"))
    days = (eogs - today).days
    if days < 0:
        tgtxt = f"; technical guidance until {tg}" if tg and tg >= today else ""
        status, txt = FAIL, f"END OF GENERAL SUPPORT {eogs} ({-days} days ago){tgtxt}"
        fix = f"Upgrade {label} to a supported release; no new security patches after end of general support."
    elif days <= WARN_DAYS:
        status, txt, fix = WARN, f"EOGS {eogs} (in {days} days)", f"Plan an upgrade of {label} before {eogs}."
    else:
        status, txt, fix = PASS, f"EOGS {eogs} ({days} days remaining)", ""
    return make(f"EOL-{product.upper()}", "Lifecycle", title, target, status, txt, "supported release", fix, category="EOL")


def patch_result(product, label, version, build, target):
    builds = load_builds().get(product, {}).get(train(version), [])
    title = f"{label} patch level (build {build})"
    try:
        b = int(build)
    except (TypeError, ValueError):
        return make(f"PATCH-{product.upper()}", "Lifecycle", title, target, WARN, f"unparseable build {build}", "", category="PATCH")
    if not builds:
        return make(f"PATCH-{product.upper()}", "Lifecycle", title, target, WARN,
                    f"{version} build {b}: no build table for train {train(version)}", "latest patch",
                    "Update builds.json; compare against Broadcom release notes.", category="PATCH")
    builds = sorted(builds, key=lambda x: x["build"])
    latest = builds[-1]
    match = next((x for x in builds if x["build"] == b), None)
    if b > latest["build"]:
        return make(f"PATCH-{product.upper()}", "Lifecycle", title, target, INFO,
                    f"build {b} is newer than newest table entry ({latest['name']}, {latest['build']})",
                    "latest patch", "Refresh builds.json to confirm this is the latest release.", category="PATCH")
    behind = len([x for x in builds if x["build"] > b])
    cur = match["name"] if match else "unlisted build"
    if behind == 0:
        return make(f"PATCH-{product.upper()}", "Lifecycle", title, target, PASS,
                    f"{cur} (latest known)", latest["name"], category="PATCH")
    missing = [x["name"] for x in builds if x["build"] > b]
    shown = ", ".join(missing[-6:]) + (" ..." if len(missing) > 6 else "")
    return make(f"PATCH-{product.upper()}", "Lifecycle", title, target, FAIL,
                f"{cur}; {behind} release(s) behind. Missing: {shown}",
                f"{latest['name']} (build {latest['build']}, {latest['date']})",
                f"Patch {label} to at least {latest['name']} via vSphere Lifecycle Manager / "
                f"esxcli software profile update / VAMI. Review VMSA advisories fixed in the skipped releases.",
                category="PATCH")


def host_lifecycle(host, log=lambda m: None):
    name = getattr(host, "name", "host")
    prod = prop(host, "config.product")
    out = []
    if prod is None:
        return out
    out.append(eol_result("esxi", "ESXi", prod.version, name))
    out.append(patch_result("esxi", "ESXi", prod.version, prod.build, name))
    reboot = prop(host, "summary.rebootRequired", False)
    out.append(make("PATCH-REBOOT", "Lifecycle", "No pending reboot after patching", name,
                    WARN if reboot else PASS, "reboot required" if reboot else "none", "none",
                    "Reboot the host (maintenance mode) to finish applying installed patches." if reboot else "",
                    category="PATCH"))
    try:
        pk = host.configManager.imageConfigManager.fetchSoftwarePackages()
        out.append(make("PATCH-VIBS", "Lifecycle", "Installed VIB inventory", name, INFO,
                        f"{len(pk)} VIBs; newest install/creation date "
                        f"{max((str(p.creationDate)[:10] for p in pk if p.creationDate), default='n/a')}",
                        "", "Compare vendor/driver VIBs against the vendor HCL / vLCM baseline.", category="PATCH"))
    except Exception:
        pass
    return out


def vcenter_lifecycle(sess, target):
    a = sess.about
    return [eol_result("vcenter", "vCenter Server", a.version, target),
            patch_result("vcenter", "vCenter Server", a.version, a.build, target)]
