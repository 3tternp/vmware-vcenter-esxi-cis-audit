"""Scan orchestration shared by the GUI and CLI."""
from __future__ import annotations

from .models import ScanOptions, make, ERROR
from . import connector, esxi_checks, vcenter_checks, lifecycle
from .connector import vim


def run_scan(host, user, password, port=443, opts: ScanOptions | None = None,
             log=lambda m: None, progress=lambda done, total: None, cancelled=lambda: False):
    opts = opts or ScanOptions()
    log(f"Connecting to {host}:{port} ...")
    sess = connector.connect(host, user, password, port, opts.verify_tls)
    results = []
    meta = {"target": host, "type": "vCenter Server" if sess.is_vcenter else "ESXi host",
            "product": sess.about.fullName, "version": sess.about.version, "build": sess.about.build}
    try:
        log(f"Connected: {sess.about.fullName} (build {sess.about.build})")
        if sess.is_vcenter:
            if opts.scan_vcenter:
                results += lifecycle.vcenter_lifecycle(sess, host)
                for fn in (vcenter_checks.check_vcenter_settings, vcenter_checks.check_permissions):
                    try:
                        results += fn(sess, host)
                    except Exception as e:
                        log(f"{fn.__name__}: {e}")
                        results.append(make(f"ERR-{fn.__name__}", "vCenter", fn.__name__, host, ERROR, str(e), ""))
                if opts.scan_network:
                    try:
                        results += vcenter_checks.check_vds(sess)
                    except Exception as e:
                        log(f"vDS checks: {e}")
            if opts.scan_appliance:
                log("Querying VCSA appliance settings (REST) ...")
                results += vcenter_checks.check_appliance(host, user, password, port, opts.verify_tls, log)
        hosts = sess.objects(vim.HostSystem) if opts.scan_hosts else []
        total = len(hosts) + (1 if opts.scan_vms else 0)
        done = 0
        for h in hosts:
            if cancelled():
                log("Cancelled.")
                return results, meta
            log(f"Auditing ESXi host {h.name} ...")
            try:
                if h.runtime.connectionState != "connected":
                    log(f"  skipped (state {h.runtime.connectionState})")
                else:
                    results += lifecycle.host_lifecycle(h, log)
                    results += esxi_checks.run_host_checks(h, log)
            except Exception as e:
                log(f"  host error: {e}")
            done += 1
            progress(done, total)
        if opts.scan_vms and not cancelled():
            results += vcenter_checks.check_vms(sess, opts, log)
            progress(total, total)
    finally:
        sess.close()
    log(f"Scan complete: {len(results)} checks")
    return results, meta
