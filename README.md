# VMware vCenter / ESXi CIS, EOL & Patch Auditor

Python (Tkinter) GUI that connects read-only to vCenter or a standalone ESXi host and reports:

1. **CIS hardening** – ESXi host (advanced settings, services, lockdown, NTP, firewall, VIB acceptance, vSwitch security), vCenter (advanced settings, banner, admin permissions), VMs (isolation/`extraConfig`, devices, snapshots, tools, RDM), distributed portgroups, and VCSA appliance (SSH/shell/NTP/syslog/password policy via REST).
2. **EOL** – each ESXi host and vCenter release vs. end of general support (bundled table, refreshable from endoflife.date), plus legacy VM hardware versions.
3. **Missing patches** – build number vs. known release builds, pending reboot, VIB inventory, VMware Tools status.

## Run
```powershell
pip install -r requirements.txt
python vmware_audit_gui.py            # GUI
python vmware_audit_gui.py --cli --host vcenter.example.com --user administrator@vsphere.local
python tests/test_mock.py             # offline self-test with fake objects
```
Exports: HTML / CSV / JSON (Export menu). Credentials are held in memory for the scan only. A read-only account is sufficient (appliance checks need an SSO admin).

## Important limits
- **Verify data tables.** `vmware_audit/data/builds.json` and `eol.json` are best-effort snapshots. Check them against Broadcom's release notes and Product Lifecycle Matrix, then keep current (Data menu imports your own JSON into `~/.vmware_audit/`). Builds newer than the table are reported INFO, not failures. Patch detection is build-based; it does not replace vSphere Lifecycle Manager compliance or VMSA review.
- **CIS numbering.** Checks use their own IDs (e.g. `ESXI-ADV-006`) mapped by topic; CIS renumbers per release. Expected values follow common CIS guidance but confirm against the benchmark version you audit to. Settings not reachable through the API are listed as MANUAL.
- Not yet validated against a live vCenter/ESXi: logic is covered by the mock test only.
