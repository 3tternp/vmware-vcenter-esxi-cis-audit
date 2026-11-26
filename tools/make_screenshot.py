"""Render the GUI with DEMO data (fake lab objects, not a real environment) and save docs/screenshot.png."""
import ctypes
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

try:
    ctypes.windll.shcore.SetProcessDpiAwareness(2)
except Exception:
    pass

from PIL import ImageGrab  # noqa: E402
from vmware_audit import lifecycle, esxi_checks  # noqa: E402
from vmware_audit.gui import App  # noqa: E402
from test_mock import fake_host  # noqa: E402

h = fake_host()
results = lifecycle.host_lifecycle(h) + esxi_checks.run_host_checks(h)
meta = {"target": "esx01.lab (demo data)", "type": "ESXi host", "product": "VMware ESXi 7.0.3 (demo)", "build": "18644231"}

app = App()
app.geometry("1280x780+40+40")
app.v_host.set("esx01.lab")
app.results, app.meta = results, meta
for t in (app.tree_all, app.tree_cis, app.tree_eol, app.tree_patch):
    app._fill(t)
app._summary()
app.nb.select(1)  # "All findings"
first = app.tree_all.get_children()[0]
app.tree_all.selection_set(first)
app.update()
app.after(600, app.quit)
app.mainloop()
app.update()
x, y, w, h_ = app.winfo_rootx(), app.winfo_rooty(), app.winfo_width(), app.winfo_height()
out = ROOT / "docs"
out.mkdir(exist_ok=True)
ImageGrab.grab(bbox=(x, y, x + w, y + h_)).save(out / "screenshot.png")
app.nb.select(0)
app.update()
ImageGrab.grab(bbox=(x, y, x + w, y + h_)).save(out / "screenshot_summary.png")
print("saved", [p.name for p in out.iterdir()])
