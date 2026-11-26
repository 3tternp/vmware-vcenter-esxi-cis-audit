"""Report export: CSV, JSON and a self-contained HTML file."""
from __future__ import annotations

import csv
import datetime as dt
import html
import json
from collections import Counter

from .models import STATUSES, PASS, FAIL

COLORS = {"PASS": "#1a7f37", "FAIL": "#cf222e", "WARN": "#bf8700", "MANUAL": "#6e7781",
          "ERROR": "#8250df", "INFO": "#0969da"}
FIELDS = ["status", "category", "area", "check_id", "title", "target", "actual", "expected", "remediation", "level", "reference"]


def summarize(results):
    c = Counter(r.status for r in results)
    scored = c[PASS] + c[FAIL] + c["WARN"]
    score = round(100 * c[PASS] / scored, 1) if scored else 0.0
    return c, score


def to_csv(results, path):
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for r in results:
            d = r.to_dict()
            w.writerow({k: d.get(k, "") for k in FIELDS})


def to_json(results, meta, path):
    c, score = summarize(results)
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"generated": dt.datetime.now().isoformat(timespec="seconds"), "meta": meta,
                   "summary": dict(c), "score": score, "results": [r.to_dict() for r in results]}, f, indent=2)


def to_html(results, meta, path):
    c, score = summarize(results)
    order = {s: i for i, s in enumerate(STATUSES)}
    rows = []
    for r in sorted(results, key=lambda x: (order.get(x.status, 9), x.category, x.check_id)):
        e = lambda s: html.escape(str(s))
        rows.append(
            f"<tr><td><b style='color:{COLORS.get(r.status, '#000')}'>{e(r.status)}</b></td><td>{e(r.category)}</td>"
            f"<td>{e(r.area)}</td><td>{e(r.check_id)}</td><td>{e(r.title)}</td><td>{e(r.target)}</td>"
            f"<td>{e(r.actual)}</td><td>{e(r.expected)}</td><td>{e(r.remediation)}</td></tr>")
    chips = "".join(f"<span style='background:{COLORS[s]};color:#fff;padding:3px 10px;border-radius:12px;margin-right:6px'>{s}: {c.get(s, 0)}</span>"
                    for s in STATUSES)
    doc = f"""<!doctype html><meta charset="utf-8"><title>VMware CIS audit</title>
<style>body{{font:14px Segoe UI,Arial,sans-serif;margin:24px}}table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #d0d7de;padding:5px 8px;vertical-align:top;font-size:13px}}th{{background:#f6f8fa;text-align:left}}</style>
<h1>VMware vCenter / ESXi CIS, EOL &amp; patch audit</h1>
<p>Target: <b>{html.escape(str(meta.get('target', '')))}</b> &mdash; {html.escape(str(meta.get('product', '')))} (build {html.escape(str(meta.get('build', '')))})<br>
Generated {dt.datetime.now():%Y-%m-%d %H:%M} &mdash; compliance score <b>{score}%</b> (PASS / PASS+FAIL+WARN)</p>
<p>{chips}</p>
<table><tr><th>Status</th><th>Type</th><th>Area</th><th>ID</th><th>Check</th><th>Target</th><th>Actual</th><th>Expected</th><th>Remediation</th></tr>
{''.join(rows)}</table>
<p style="color:#57606a">Results reflect API-visible settings only. MANUAL items need human review. Data tables for EOL/patch builds must be kept current.</p>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)
