"""Launcher: python vmware_audit_gui.py   (add --cli for headless mode)."""
import argparse
import getpass
import sys


def cli():
    from vmware_audit.scanner import run_scan
    from vmware_audit.models import ScanOptions
    from vmware_audit import report
    ap = argparse.ArgumentParser()
    ap.add_argument("--cli", action="store_true")
    ap.add_argument("--host", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--verify-tls", action="store_true")
    ap.add_argument("--out", default="vmware_audit")
    a = ap.parse_args()
    pw = getpass.getpass("Password: ")
    res, meta = run_scan(a.host, a.user, pw, a.port, ScanOptions(verify_tls=a.verify_tls), log=print)
    report.to_html(res, meta, a.out + ".html")
    report.to_csv(res, a.out + ".csv")
    report.to_json(res, meta, a.out + ".json")
    c, score = report.summarize(res)
    print(dict(c), f"score={score}%", "-> reports written to", a.out + ".*")


if __name__ == "__main__":
    if "--cli" in sys.argv:
        cli()
    else:
        from vmware_audit.gui import main
        main()
