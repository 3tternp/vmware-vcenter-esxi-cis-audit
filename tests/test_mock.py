"""Offline smoke test using fake vSphere objects (no real server needed).

Run:  python tests/test_mock.py
"""
import os
import sys
import tempfile
from types import SimpleNamespace as NS

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from vmware_audit import esxi_checks, lifecycle, report  # noqa: E402


class FakeAdv:
    def __init__(self, vals): self.vals = vals
    def QueryOptions(self, name):
        if name not in self.vals:
            raise KeyError(name)
        return [NS(value=self.vals[name])]


def fake_host():
    adv = {"Config.HostAgent.plugins.solo.enableMob": "false", "Security.AccountLockFailures": 10,
           "Security.PasswordQualityControl": "similar=deny retry=3 min=disabled,disabled,disabled,disabled,14",
           "UserVars.DcuiTimeOut": 600, "Syslog.global.logHost": ""}
    svc = [NS(key="TSM-SSH", running=True, policy="on"), NS(key="ntpd", running=True, policy="on")]
    cm = NS(advancedOption=FakeAdv(adv), serviceSystem=NS(serviceInfo=NS(service=svc)),
            hostAccessManager=NS(lockdownMode="lockdownDisabled", QueryLockdownExceptions=lambda: []),
            firewallSystem=NS(firewallInfo=NS(defaultPolicy=NS(incomingBlocked=True, outgoingBlocked=False),
                                              ruleset=[NS(key="sshServer", enabled=True, allowedHosts=NS(allIp=True))])),
            imageConfigManager=NS(HostImageConfigGetAcceptance=lambda: "community",
                                  fetchSoftwarePackages=lambda: [NS(name="x", acceptanceLevel="community", creationDate=None)]))
    return NS(name="esx01.lab", configManager=cm,
              config=NS(dateTimeInfo=NS(ntpConfig=NS(server=["pool.ntp.org"])),
                        network=NS(vswitch=[NS(name="vSwitch0", spec=NS(policy=NS(security=NS(allowPromiscuous=True, forgedTransmits=False, macChanges=False))))],
                                   portgroup=[]),
                        product=NS(version="7.0.3", build="18644231")),
              summary=NS(rebootRequired=True), capability=NS(tpmSupported=False))


def main():
    h = fake_host()
    res = lifecycle.host_lifecycle(h) + esxi_checks.run_host_checks(h)
    by = {r.check_id: r for r in res}
    assert by["ESXI-ADV-001"].status == "PASS"
    assert by["ESXI-ADV-002"].status == "FAIL"
    assert by["ESXI-ADV-004"].status == "PASS"
    assert by["ESXI-ADV-012"].status == "FAIL"
    assert by["ESXI-ADV-099" if False else "ESXI-ADV-005"].status == "WARN"   # option missing -> WARN
    assert by["ESXI-SVC-001"].status == "FAIL" and by["ESXI-SVC-005"].status == "PASS"
    assert by["ESXI-ACC-001"].status == "FAIL"
    assert by["ESXI-FW-001"].status == "FAIL" and by["ESXI-FW-002"].status == "FAIL"
    assert by["ESXI-VIB-001"].status == "FAIL"
    assert by["ESXI-NET-001"].status == "FAIL" and by["ESXI-NET-002"].status == "PASS"
    assert by["EOL-ESXI"].status == "FAIL" or by["EOL-ESXI"].status == "WARN"   # 7.0 is at/after end of support
    assert by["PATCH-ESXI"].status == "FAIL"        # 7.0 U3 GA is behind
    assert by["PATCH-REBOOT"].status == "WARN"
    assert lifecycle.patch_result("esxi", "ESXi", "8.0.3", 99999999, "t").status == "INFO"
    assert lifecycle.patch_result("esxi", "ESXi", "8.0.3", 24674346, "t").status == "PASS"
    from datetime import date
    assert lifecycle.eol_result("esxi", "ESXi", "6.7.0", "t").status == "FAIL"
    assert lifecycle.eol_result("esxi", "ESXi", "8.0.3", "t", today=date(2026, 1, 1)).status == "PASS"
    d = tempfile.mkdtemp()
    report.to_html(res, {"target": "x"}, os.path.join(d, "r.html"))
    report.to_csv(res, os.path.join(d, "r.csv"))
    report.to_json(res, {"target": "x"}, os.path.join(d, "r.json"))
    print(f"OK - {len(res)} results, reports written")


if __name__ == "__main__":
    main()
