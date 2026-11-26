"""vCenter Server, virtual machine, distributed switch and VCSA appliance checks."""
from __future__ import annotations

import datetime as dt

from .models import PASS, FAIL, WARN, MANUAL, ERROR, make
from .connector import prop, vim

# ------------------------------------------------------------------ vCenter
VC_OPTIONS = [
    # id, option, title, predicate(callable), expected text, fix
    ("VC-ADV-001", "VirtualCenter.VimPasswordExpirationInDays", "ESXi host password rotation <= 30 days",
     lambda v: v.isdigit() and 0 < int(v) <= 30, "1..30", "Set VirtualCenter.VimPasswordExpirationInDays=30 (vCenter > Configure > Advanced Settings)."),
    ("VC-ADV-002", "config.log.level", "vCenter log level is 'info'",
     lambda v: v.lower() == "info", "info", "Set config.log.level=info."),
    ("VC-ADV-003", "config.vpxd.hostPasswordLength", "Managed host password length >= 32",
     lambda v: v.isdigit() and int(v) >= 32, ">= 32", "Set config.vpxd.hostPasswordLength=32."),
    ("VC-ADV-004", "mail.smtp.server", "SMTP server configured for alarm e-mail",
     lambda v: bool(v.strip()), "not empty", "Configure SMTP under vCenter > Configure > Settings > General > Mail."),
]


def check_vcenter_settings(sess, t):
    out = []
    om = sess.content.setting
    for cid, opt, title, pred, exp, fix in VC_OPTIONS:
        try:
            vals = om.QueryOptions(opt)
            v = str(vals[0].value) if vals else ""
            ok = pred(v)
            out.append(make(cid, "vCenter", title, t, PASS if ok else FAIL, v, exp, "" if ok else fix, "L1", reference=opt))
        except Exception:
            out.append(make(cid, "vCenter", title, t, WARN, "option not present", exp,
                            "Option absent on this vCenter version; confirm in the matching benchmark.", "L1", reference=opt))
    msg = ""
    try:
        msg = sess.content.sessionManager.message or ""
    except Exception:
        pass
    out.append(make("VC-BNR-001", "vCenter", "Login banner / message of the day configured", t,
                    PASS if msg.strip() else FAIL, msg[:80] or "not set", "Banner set",
                    "" if msg.strip() else "Configure a login message (vSphere Client > Administration > Single Sign On > Configuration > Login Message).", "L1"))
    return out


def check_permissions(sess, t):
    out = []
    am = sess.content.authorizationManager
    perms = am.RetrieveAllPermissions()
    roles = {r.roleId: r.name for r in am.roleList}
    admins = sorted({p.principal for p in perms if roles.get(p.roleId) == "Admin" or p.roleId == -1})
    broad = [p for p in admins if any(k in p.lower() for k in ("everyone", "domain users", "authenticated", "users@"))]
    out.append(make("VC-IAM-001", "vCenter", "Administrator role assignments reviewed (least privilege)", t,
                    FAIL if broad else (WARN if len(admins) > 3 else PASS),
                    ", ".join(admins) or "none", "Few, named admin principals; no broad groups",
                    "" if not broad and len(admins) <= 3 else "Reduce Administrator-role assignments; avoid 'Domain Users'-type groups.", "L1"))
    out.append(make("VC-IAM-002", "vCenter", "SSO identity source, MFA/AD integration, password & lockout policy", t, MANUAL,
                    "not exposed via the vSphere API", "Reviewed",
                    "Review vSphere Client > Administration > Single Sign On > Configuration.", "L1"))
    return out


# -------------------------------------------------------------------- VMs
VM_FLAGS = [
    # id, key, expected, title, level
    ("VM-001", "isolation.tools.copy.disable", "true", "Disable VM console copy operations", "L1"),
    ("VM-002", "isolation.tools.dnd.disable", "true", "Disable VM console drag and drop", "L1"),
    ("VM-003", "isolation.tools.paste.disable", "true", "Disable VM console paste operations", "L1"),
    ("VM-004", "isolation.tools.setGUIOptions.enable", "false", "Disable GUI options from guest", "L1"),
    ("VM-005", "isolation.tools.diskShrink.disable", "true", "Disable virtual disk shrink", "L1"),
    ("VM-006", "isolation.tools.diskWiper.disable", "true", "Disable virtual disk wiper", "L1"),
    ("VM-007", "isolation.device.connectable.disable", "true", "Prevent device connect/disconnect from guest", "L1"),
    ("VM-008", "isolation.device.edit.disable", "true", "Prevent device modification from guest", "L1"),
    ("VM-009", "RemoteDisplay.maxConnections", "1", "Limit console connections to 1", "L2"),
    ("VM-010", "tools.setinfo.sizeLimit", "1048576", "Limit guest info (setinfo) size", "L1"),
    ("VM-011", "mks.enable3d", "false", "Disable 3D acceleration on non-graphics VMs", "L2"),
    ("VM-012", "tools.guestlib.enableHostInfo", "false", "Do not send host info to guests", "L1"),
    ("VM-013", "log.keepOld", "10", "Limit VM log file count to 10", "L1"),
]
UNNEEDED_DEVICES = {
    "VirtualFloppy": "floppy", "VirtualSerialPort": "serial port",
    "VirtualParallelPort": "parallel port", "VirtualUSBController": "USB controller",
}


def _hw_version(vm):
    v = prop(vm, "config.version", "") or ""
    try:
        return int(v.replace("vmx-", ""))
    except ValueError:
        return 0


def check_vms(sess, opts, log=lambda m: None):
    vms = [v for v in sess.objects(vim.VirtualMachine)
           if not prop(v, "config.template", False)]
    if opts.max_vms:
        vms = vms[: opts.max_vms]
    log(f"Auditing {len(vms)} virtual machines")
    findings = {k[0]: [] for k in VM_FLAGS}
    for extra in ("VM-DEV", "VM-HW", "VM-TOOLS", "VM-SNAP", "VM-RDM"):
        findings[extra] = []
    now = dt.datetime.now(dt.timezone.utc)
    for vm in vms:
        try:
            name = vm.name
            cfg = vm.config
            if cfg is None:
                continue
            extra = {o.key: str(o.value) for o in (cfg.extraConfig or [])}
            for cid, key, expected, _, _ in VM_FLAGS:
                actual = extra.get(key)
                # CIS expects these to be set explicitly, so "not set" is a finding.
                if actual is None or actual.lower() != expected.lower():
                    findings[cid].append(f"{name} ({'not set' if actual is None else actual})")
            devs = [UNNEEDED_DEVICES[type(d).__name__.split(".")[-1]] for d in (cfg.hardware.device or [])
                    if type(d).__name__.split(".")[-1] in UNNEEDED_DEVICES]
            if devs:
                findings["VM-DEV"].append(f"{name} ({', '.join(sorted(set(devs)))})")
            if 0 < _hw_version(vm) <= 14:
                findings["VM-HW"].append(f"{name} ({cfg.version})")
            ts = prop(vm, "guest.toolsStatus")
            if ts in ("toolsNotInstalled", "toolsOld"):
                findings["VM-TOOLS"].append(f"{name} ({ts})")
            for snap in _walk_snaps(prop(vm, "snapshot.rootSnapshotList", []) or []):
                age = (now - snap.createTime.astimezone(dt.timezone.utc)).days
                if age > opts.snapshot_max_days:
                    findings["VM-SNAP"].append(f"{name}/{snap.name} ({age}d)")
            for d in cfg.hardware.device or []:
                b = getattr(d, "backing", None)
                if b is not None and type(b).__name__.endswith("RawDiskMappingVer1BackingInfo"):
                    findings["VM-RDM"].append(name)
                    break
        except Exception as e:
            log(f"VM audit error: {e}")
    out = []
    tgt = f"{len(vms)} VMs"
    for cid, key, expected, title, level in VM_FLAGS:
        bad = findings[cid]
        out.append(make("CIS-" + cid, "VM", title, tgt, FAIL if bad else PASS,
                        _short(bad) or "all compliant", f"{key}={expected}",
                        "" if not bad else f"Add advanced VM option {key} = {expected} (VM must be powered off / reconfigured).",
                        level, reference=key))
    out.extend([
        make("CIS-VM-DEV", "VM", "Unnecessary devices removed (floppy/serial/parallel/USB controller)", tgt,
             WARN if findings["VM-DEV"] else PASS, _short(findings["VM-DEV"]) or "none", "none",
             "Remove unneeded virtual hardware.", "L1"),
        make("CIS-VM-HW", "VM", "Virtual hardware version not legacy (> vmx-14)", tgt,
             WARN if findings["VM-HW"] else PASS, _short(findings["VM-HW"]) or "none", "vmx-15+ (tied to supported ESXi)",
             "Schedule 'Upgrade VM Compatibility' after tools upgrade.", "L1", category="EOL"),
        make("CIS-VM-TOOLS", "VM", "VMware Tools installed and current", tgt,
             WARN if findings["VM-TOOLS"] else PASS, _short(findings["VM-TOOLS"]) or "none", "toolsOk",
             "Install / upgrade VMware Tools (open-vm-tools on Linux).", "L1", category="PATCH"),
        make("CIS-VM-SNAP", "VM", f"No snapshots older than {opts.snapshot_max_days} days", tgt,
             FAIL if findings["VM-SNAP"] else PASS, _short(findings["VM-SNAP"]) or "none", f"<= {opts.snapshot_max_days} days",
             "Consolidate/delete stale snapshots.", "L2"),
        make("CIS-VM-RDM", "VM", "Raw device mappings reviewed", tgt,
             WARN if findings["VM-RDM"] else PASS, _short(findings["VM-RDM"]) or "none", "none unless justified",
             "Use VMDKs unless an RDM is required.", "L2"),
    ])
    return out


def _walk_snaps(lst):
    for s in lst:
        yield s
        yield from _walk_snaps(s.childSnapshotList or [])


def _short(items, limit=12):
    if len(items) <= limit:
        return "; ".join(items)
    return "; ".join(items[:limit]) + f" ... (+{len(items) - limit} more, total {len(items)})"


# ------------------------------------------------------------- distributed
def check_vds(sess, t_unused=None):
    out = []
    try:
        pgs = [p for p in sess.objects(vim.dvs.DistributedVirtualPortgroup)
               if not getattr(p.config, "uplink", False)]
    except Exception:
        return out
    bad = {"promisc": [], "forged": [], "mac": []}
    for pg in pgs:
        pol = prop(pg, "config.defaultPortConfig.securityPolicy")
        if pol is None:
            continue
        for key, attr in (("promisc", "allowPromiscuous"), ("forged", "forgedTransmits"), ("mac", "macChanges")):
            v = getattr(pol, attr, None)
            if v is not None and getattr(v, "value", False):
                bad[key].append(pg.name)
    for cid, key, title in (("VDS-001", "promisc", "Promiscuous mode rejected"),
                            ("VDS-002", "forged", "Forged transmits rejected"),
                            ("VDS-003", "mac", "MAC address changes rejected")):
        out.append(make(cid, "vDS", f"Distributed portgroups: {title}", f"{len(pgs)} portgroups",
                        FAIL if bad[key] else PASS, _short(bad[key]) or "none accept", "Reject",
                        "" if not bad[key] else "Edit portgroup > Security and set to Reject.", "L1"))
    return out


# ---------------------------------------------------------------- appliance
def check_appliance(host, user, password, port, verify_tls, log=lambda m: None):
    """VCSA settings through the vSphere Automation REST API (best effort)."""
    try:
        import requests
    except ImportError:
        return [make("APP-000", "Appliance", "VCSA checks need 'requests'", host, ERROR, "requests not installed", "")]
    base = f"https://{host}:{port}"
    if not verify_tls:
        try:
            import urllib3
            urllib3.disable_warnings()
        except Exception:
            pass
    out = []
    try:
        r = requests.post(f"{base}/api/session", auth=(user, password), verify=verify_tls, timeout=20)
        if r.status_code not in (200, 201):
            return [make("APP-000", "Appliance", "VCSA REST session", host, WARN, f"HTTP {r.status_code}",
                         "authenticated", "Appliance checks skipped (needs an SSO account with appliance access).")]
        hdr = {"vmware-api-session-id": r.json()}
    except Exception as e:
        return [make("APP-000", "Appliance", "VCSA REST session", host, WARN, str(e)[:120], "reachable",
                     "Appliance checks skipped; is this a vCenter Server Appliance?")]

    def get(path):
        resp = requests.get(base + path, headers=hdr, verify=verify_tls, timeout=20)
        resp.raise_for_status()
        return resp.json()

    def safe(cid, title, path, fn, expected, fix, level="L1"):
        try:
            data = get(path)
            status, actual = fn(data)
            out.append(make(cid, "Appliance", title, host, status, actual, expected, "" if status == PASS else fix, level))
        except Exception as e:
            out.append(make(cid, "Appliance", title, host, WARN, f"could not query: {str(e)[:90]}", expected,
                            "Verify manually in the VAMI (https://<vcsa>:5480)."))

    safe("APP-001", "Appliance SSH disabled", "/api/appliance/access/ssh",
         lambda d: (PASS if d is False else FAIL, d), "False", "Disable SSH in VAMI > Access (re-enable only for maintenance).")
    safe("APP-002", "Appliance bash shell disabled", "/api/appliance/access/shell",
         lambda d: (PASS if not d.get("enabled") else FAIL, d), "enabled=False", "Disable the bash shell in VAMI > Access.")
    safe("APP-003", "Appliance NTP/time sync configured", "/api/appliance/timesync",
         lambda d: (PASS if d.get("mode") in ("NTP", "HOST") else FAIL, d), "mode NTP (or HOST)", "Configure NTP in VAMI > Time.")
    safe("APP-004", "Remote syslog forwarding configured", "/api/appliance/logging/forwarding",
         lambda d: (PASS if d else FAIL, f"{len(d)} target(s)"), ">= 1 target", "Configure syslog forwarding in VAMI > Syslog.")
    safe("APP-005", "Local account password max age <= 90 days", "/api/appliance/local-accounts/global-policy",
         lambda d: (PASS if 0 < (d.get("max_days") or 0) <= 90 else FAIL, d), "max_days 1..90",
         "Set appliance local account policy in VAMI > Administration.")
    return out
