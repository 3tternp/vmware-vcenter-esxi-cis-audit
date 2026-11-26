"""Connection helpers built on pyvmomi."""
from __future__ import annotations

import ssl
from dataclasses import dataclass

try:
    from pyVim.connect import SmartConnect, Disconnect
    from pyVmomi import vim
    HAVE_PYVMOMI = True
except ImportError:  # pragma: no cover
    HAVE_PYVMOMI = False
    vim = None


@dataclass
class Session:
    si: object
    host: str
    user: str
    port: int
    verify_tls: bool
    is_vcenter: bool
    about: object

    @property
    def content(self):
        return self.si.RetrieveContent()

    def objects(self, vimtype):
        """Return all managed objects of a type via a container view."""
        content = self.content
        view = content.viewManager.CreateContainerView(content.rootFolder, [vimtype], True)
        try:
            return list(view.view)
        finally:
            view.Destroy()

    def close(self):
        try:
            Disconnect(self.si)
        except Exception:
            pass


def connect(host: str, user: str, password: str, port: int = 443,
            verify_tls: bool = False) -> Session:
    if not HAVE_PYVMOMI:
        raise RuntimeError("pyvmomi is not installed. Run: pip install pyvmomi")
    ctx = ssl.create_default_context()
    if not verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    si = SmartConnect(host=host, user=user, pwd=password, port=port, sslContext=ctx)
    about = si.RetrieveContent().about
    return Session(si, host, user, port, verify_tls,
                   about.apiType == "VirtualCenter", about)


def prop(obj, path, default=None):
    """Safe nested attribute getter: prop(host, 'config.network.vswitch')."""
    cur = obj
    for part in path.split("."):
        if cur is None:
            return default
        try:
            cur = getattr(cur, part)
        except Exception:
            return default
    return default if cur is None else cur
