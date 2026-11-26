"""ESXi host hardening checks (aligned with the CIS VMware ESXi Benchmark themes).

Numbering: CIS renumbers recommendations between benchmark releases, so each
check carries its own stable ID (ESXI-xxx) and a short title that maps to the
CIS recommendation name. Always cross-reference with the PDF of the exact
benchmark version your organisation audits against.
"""
from __future__ import annotations

import re

from .models import PASS, FAIL, WARN, MANUAL, ERROR, make
from .connector import prop

AREA = "ESXi Host"


# ---------------------------------------------------------------- predicates
def eq(expected):
    def f(v):
        if isinstance(expected, bool):
            return str(v).lower() == str(expected).lower()
        return str(v).strip().lower() == str(expected).strip().lower()
    f.desc = f"= {expected}"
    return f


def int_range(lo, hi):
    def f(v):
        try:
            return lo <= int(v) <= hi
        except (TypeError, ValueError):
            return False
    f.desc = f"{lo}..{hi}"
    return f


def nonempty(v):
    return bool(str(v).strip())
nonempty.desc = "not empty"


def empty(v):
    return not str(v).strip()
empty.desc = "empty"


def contains_all(*tokens):
    def f(v):
        s = str(v).lower()
        return all(t in s for t in tokens)
    f.desc = "contains " + ",".join(tokens)
    return f


def pwd_quality(v):
    """Security.PasswordQualityControl: require >=14 char minimum length."""
    m = re.search(r"min=([^\s]+)", str(v))
    if not m:
        return False
    parts = m.group(1).split(",")
    nums = [int(p) for p in parts if p.isdigit()]
    return bool(nums) and nums[-1] >= 14
pwd_quality.desc = "min=... with minimum length >= 14"


# (id, option, title, predicate, level, kind)
ADV_OPTIONS = [
    ("ESXI-ADV-001", "Config.HostAgent.plugins.solo.enableMob", "Managed Object Browser (MOB) disabled", eq("false"), "L1", "bool"),
    ("ESXI-ADV-002", "Security.AccountLockFailures", "Account lockout after failed logins (<=5)", int_range(1, 5), "L1", "int"),
    ("ESXI-ADV-003", "Security.AccountUnlockTime", "Account unlock time (>=900s)", int_range(900, 10**9), "L1", "int"),
    ("ESXI-ADV-004", "Security.PasswordQualityControl", "Password complexity / minimum length 14", pwd_quality, "L1", "str"),
    ("ESXI-ADV-005", "Security.PasswordHistory", "Password history (>=5)", int_range(5, 10**6), "L1", "int"),
    ("ESXI-ADV-006", "Security.PasswordMaxDays", "Password maximum age (<=90 days)", int_range(1, 90), "L1", "int"),
    ("ESXI-ADV-007", "UserVars.ESXiShellInteractiveTimeOut", "Shell interactive idle timeout (1-900s)", int_range(1, 900), "L1", "int"),
    ("ESXI-ADV-008", "UserVars.ESXiShellTimeOut", "Shell availability timeout (1-600s)", int_range(1, 600), "L1", "int"),
    ("ESXI-ADV-009", "UserVars.DcuiTimeOut", "DCUI idle timeout (1-600s)", int_range(1, 600), "L1", "int"),
    ("ESXI-ADV-010", "UserVars.SuppressShellWarning", "Shell warning not suppressed", eq("0"), "L1", "int"),
    ("ESXI-ADV-011", "UserVars.HostClientSessionTimeout", "Host Client session timeout (1-900s)", int_range(1, 900), "L1", "int"),
    ("ESXI-ADV-012", "Syslog.global.logHost", "Remote syslog host configured", nonempty, "L1", "str"),
    ("ESXI-ADV-013", "Syslog.global.logDir", "Persistent log directory configured", nonempty, "L1", "str"),
    ("ESXI-ADV-014", "Syslog.global.auditRecord.storageEnable", "Local audit record storage enabled", eq("true"), "L2", "bool"),
    ("ESXI-ADV-015", "Net.BlockGuestBPDU", "BPDU guest filter enabled", eq("1"), "L1", "int"),
    ("ESXI-ADV-016", "Net.DVFilterBindIpAddress", "DVFilter bind IP empty (no unused vSafe)", empty, "L1", "str"),
    ("ESXI-ADV-017", "Mem.ShareForceSalting", "Transparent page sharing salting enforced (=2)", eq("2"), "L2", "int"),
    ("ESXI-ADV-018", "Config.HostAgent.log.level", "Host agent log level = info", eq("info"), "L1", "str"),
    ("ESXI-ADV-019", "VMkernel.Boot.execInstalledOnly", "execInstalledOnly enabled", eq("true"), "L2", "bool"),
    ("ESXI-ADV-020", "UserVars.ESXiVPsDisabledProtocols", "Legacy TLS/SSL protocols disabled", contains_all("sslv3", "tlsv1", "tlsv1.1"), "L1", "str"),
]

# (id, service key, title, should_run, policy)
SERVICES = [
    ("ESXI-SVC-001", "TSM-SSH", "SSH service stopped, startup policy off", False, "off"),
    ("ESXI-SVC-002", "TSM", "ESXi Shell stopped, startup policy off", False, "off"),
    ("ESXI-SVC-003", "slpd", "SLP service stopped, startup policy off", False, "off"),
    ("ESXI-SVC-004", "snmpd", "SNMP stopped unless required (v3 only)", False, "off"),
    ("ESXI-SVC-005", "ntpd", "NTP daemon running, startup policy on", True, "on"),
]


def _adv_cmd(option, value, kind):
    path = "/" + option.replace(".", "/")
    flag = "-s" if kind == "str" else "-i"
    return f"esxcli system settings advanced set -o {path} {flag} {value}"


_ADV_FIX = {
    "Config.HostAgent.plugins.solo.enableMob": "esxcli system settings advanced set -o /Config/HostAgent/plugins/solo/enableMob -i 0",
    "Syslog.global.logHost": "esxcli system syslog config set --loghost='udp://loghost.example.com:514' && esxcli system syslog reload",
    "Security.PasswordQualityControl": "esxcli system settings advanced set -o /Security/PasswordQualityControl -s 'similar=deny retry=3 min=disabled,disabled,disabled,disabled,14'",
    "UserVars.ESXiVPsDisabledProtocols": "esxcli system settings advanced set -o /UserVars/ESXiVPsDisabledProtocols -s 'sslv3,tlsv1,tlsv1.1'",
    "VMkernel.Boot.execInstalledOnly": "esxcli system settings kernel set -s execInstalledOnly -v TRUE  (reboot required; test first)",
    "Syslog.global.auditRecord.storageEnable": "esxcli system auditrecords local enable (needs storage capacity set)",
}
_ADV_TARGET = {
    "ESXI-ADV-001": "false", "ESXI-ADV-002": 5, "ESXI-ADV-003": 900, "ESXI-ADV-005": 5, "ESXI-ADV-006": 90,
    "ESXI-ADV-007": 900, "ESXI-ADV-008": 600, "ESXI-ADV-009": 600, "ESXI-ADV-010": 0, "ESXI-ADV-011": 900,
    "ESXI-ADV-015": 1, "ESXI-ADV-016": "''", "ESXI-ADV-017": 2, "ESXI-ADV-018": "info", "ESXI-ADV-013": "/scratch/log",
}


def _query(host, name):
    adv = host.configManager.advancedOption
    vals = adv.QueryOptions(name)
    return vals[0].value if vals else None


def check_advanced(host, t):
    out = []
    for cid, opt, title, pred, level, kind in ADV_OPTIONS:
        try:
            val = _query(host, opt)
        except Exception as e:  # InvalidName on versions lacking the option
            out.append(make(cid, AREA, title, t, WARN, "option not present / not readable",
                            pred.desc, f"Verify applicability for this ESXi version ({opt}). {type(e).__name__}", level))
            continue
        ok = pred(val)
        fix = _ADV_FIX.get(opt) or _adv_cmd(opt, _ADV_TARGET.get(cid, "<value>"), kind)
        out.append(make(cid, AREA, title, t, PASS if ok else FAIL, val, pred.desc,
                        "" if ok else fix, level, reference=opt))
    return out


def check_services(host, t):
    out = []
    svcs = {s.key: s for s in (prop(host, "configManager.serviceSystem.serviceInfo.service", []) or [])}
    for cid, key, title, should_run, policy in SERVICES:
        s = svcs.get(key)
        if s is None:
            out.append(make(cid, AREA, title, t, WARN, "service not found", f"running={should_run}, policy={policy}", level="L1"))
            continue
        ok = (bool(s.running) == should_run) and (s.policy == policy)
        # SNMP legitimately runs when monitoring requires it -> WARN not FAIL
        status = PASS if ok else (WARN if key == "snmpd" else FAIL)
        out.append(make(cid, AREA, title, t, status,
                        f"running={s.running}, policy={s.policy}", f"running={should_run}, policy={policy}",
                        "" if ok else f"Set service '{key}' to running={should_run}, policy={policy} "
                                      f"(vSphere Client > Host > Configure > Services, or vim-cmd/PowerCLI Set-VMHostService).",
                        "L1"))
    return out


def check_lockdown(host, t):
    mode = None
    ham = prop(host, "configManager.hostAccessManager")
    if ham is not None:
        mode = getattr(ham, "lockdownMode", None)
    if mode is None:
        mode = prop(host, "config.lockdownMode")
    ok = str(mode) in ("lockdownNormal", "lockdownStrict", "normal", "strict")
    res = [make("ESXI-ACC-001", AREA, "Lockdown mode enabled (normal or strict)", t,
                PASS if ok else FAIL, mode, "lockdownNormal / lockdownStrict",
                "" if ok else "Enable lockdown mode: Host > Configure > System > Security Profile > Lockdown Mode "
                              "(or Get-VMHost | Get-View ... EnterLockdownMode()).", "L1")]
    try:
        exc = ham.QueryLockdownExceptions() if ham else []
        res.append(make("ESXI-ACC-002", AREA, "Lockdown exception users reviewed", t,
                        PASS if not exc else WARN, ", ".join(exc) or "none", "no / reviewed exceptions",
                        "" if not exc else "Review every exception user; keep to the minimum required.", "L1"))
    except Exception:
        pass
    return res


def check_ntp(host, t):
    servers = list(prop(host, "config.dateTimeInfo.ntpConfig.server", []) or [])
    return [make("ESXI-NTP-001", AREA, "NTP servers configured", t,
                 PASS if len(servers) >= 2 else (WARN if servers else FAIL), ", ".join(servers) or "none",
                 ">= 2 trusted NTP servers",
                 "" if len(servers) >= 2 else "Configure two or more NTP sources: Host > Configure > System > Time Configuration.", "L1")]


def check_firewall(host, t):
    out = []
    fw = prop(host, "configManager.firewallSystem.firewallInfo")
    if fw is None:
        return [make("ESXI-FW-001", AREA, "Host firewall information", t, ERROR, "unavailable", "")]
    dp = fw.defaultPolicy
    ok = bool(dp.incomingBlocked) and bool(dp.outgoingBlocked)
    out.append(make("ESXI-FW-001", AREA, "Default firewall policy blocks incoming and outgoing", t,
                    PASS if ok else FAIL, f"incomingBlocked={dp.incomingBlocked}, outgoingBlocked={dp.outgoingBlocked}",
                    "both True",
                    "" if ok else "Set default firewall policy to deny (esxcli network firewall set --default-action false).", "L1"))
    open_rules = []
    for rs in fw.ruleset:
        if rs.enabled and rs.allowedHosts is not None and rs.allowedHosts.allIp:
            open_rules.append(rs.key)
    # Only flag well-known management rulesets; others listed as warnings
    mgmt = [r for r in open_rules if r in ("sshServer", "vSphereClient", "webAccess", "snmp", "ntpClient", "vpxHeartbeats")]
    out.append(make("ESXI-FW-002", AREA, "Enabled rulesets restrict allowed IP addresses", t,
                    PASS if not open_rules else (FAIL if mgmt else WARN),
                    ", ".join(open_rules) or "all enabled rulesets restricted",
                    "allowedHosts limited to management networks",
                    "" if not open_rules else "esxcli network firewall ruleset set -r <ruleset> --allowed-all false; "
                                              "esxcli network firewall ruleset allowedip add -r <ruleset> -i <cidr>", "L1"))
    return out


def check_acceptance(host, t):
    mgr = prop(host, "configManager.imageConfigManager")
    out = []
    if mgr is None:
        return out
    try:
        lvl = mgr.HostImageConfigGetAcceptance()
        ok = lvl in ("vmware_certified", "vmware_accepted", "partner")
        out.append(make("ESXI-VIB-001", AREA, "Host image acceptance level (not community)", t,
                        PASS if ok else FAIL, lvl, "VMwareCertified / VMwareAccepted / PartnerSupported",
                        "" if ok else "esxcli software acceptance set --level=PartnerSupported", "L1"))
    except Exception as e:
        out.append(make("ESXI-VIB-001", AREA, "Host image acceptance level", t, ERROR, str(e), ""))
    try:
        pk = mgr.fetchSoftwarePackages()
        community = [p.name for p in pk if str(p.acceptanceLevel).lower() == "community"]
        out.append(make("ESXI-VIB-002", AREA, "No CommunitySupported VIBs installed", t,
                        PASS if not community else FAIL, ", ".join(community) or "none", "none",
                        "" if not community else "Remove community VIBs: esxcli software vib remove -n <name>", "L1"))
    except Exception:
        pass
    return out


def _sec(pol):
    """Return (promisc, forged, macchg) booleans/None from a security policy."""
    if pol is None:
        return None, None, None
    return (getattr(pol, "allowPromiscuous", None), getattr(pol, "forgedTransmits", None), getattr(pol, "macChanges", None))


def check_vswitches(host, t):
    out = []
    net = prop(host, "config.network")
    if net is None:
        return out
    bad = {"promisc": [], "forged": [], "mac": []}
    for vs in (net.vswitch or []):
        p, f, m = _sec(prop(vs, "spec.policy.security"))
        if p: bad["promisc"].append(f"vSwitch:{vs.name}")
        if f: bad["forged"].append(f"vSwitch:{vs.name}")
        if m: bad["mac"].append(f"vSwitch:{vs.name}")
    for pg in (net.portgroup or []):
        p, f, m = _sec(prop(pg, "spec.policy.security"))
        name = f"PG:{pg.spec.name}"
        if p: bad["promisc"].append(name)
        if f: bad["forged"].append(name)
        if m: bad["mac"].append(name)
    for cid, key, title, fixopt in (
        ("ESXI-NET-001", "promisc", "Promiscuous mode rejected", "--allow-promiscuous=false"),
        ("ESXI-NET-002", "forged", "Forged transmits rejected", "--allow-forged-transmits=false"),
        ("ESXI-NET-003", "mac", "MAC address changes rejected", "--allow-mac-change=false"),
    ):
        offenders = bad[key]
        out.append(make(cid, AREA, f"Standard vSwitch/portgroup: {title}", t,
                        PASS if not offenders else FAIL, ", ".join(offenders) or "none accept", "Reject",
                        "" if not offenders else f"esxcli network vswitch standard policy security set -v <vSwitch> {fixopt}", "L1"))
    return out


def check_runtime(host, t):
    out = []
    # Hardware-assisted security posture (informational)
    try:
        tpm = prop(host, "capability.tpmSupported")
        if tpm is not None:
            out.append(make("ESXI-HW-001", AREA, "TPM 2.0 available for host attestation / secure boot", t,
                            PASS if tpm else WARN, tpm, "True",
                            "" if tpm else "Consider TPM 2.0 + Secure Boot capable hardware.", "L2"))
    except Exception:
        pass
    out.append(make("ESXI-MAN-001", AREA, "Local account review (root only used for break-glass, AD integration)", t, MANUAL,
                    "not automatable via API", "Reviewed", "Review host local users and AD join / Host Profiles.", "L1"))
    return out


CHECKS = (check_advanced, check_services, check_lockdown, check_ntp, check_firewall,
          check_acceptance, check_vswitches, check_runtime)


def run_host_checks(host, log=lambda m: None):
    name = getattr(host, "name", "host")
    out = []
    for fn in CHECKS:
        try:
            out.extend(fn(host, name))
        except Exception as e:
            log(f"[{name}] {fn.__name__} failed: {e}")
            out.append(make(f"ESXI-ERR-{fn.__name__}", AREA, f"{fn.__name__} could not run", name, ERROR, str(e), ""))
    return out
