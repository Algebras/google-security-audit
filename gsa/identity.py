"""Who ran the scan (device user) and which repo was scanned."""
from __future__ import annotations

import getpass
import platform
import subprocess
from pathlib import Path


def _run(cmd, cwd=None) -> str:
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=10)
        return r.stdout.strip() if r.returncode == 0 else ""
    except Exception:
        return ""


def device_user() -> dict:
    user = getpass.getuser()
    full = ""
    system = platform.system()
    if system == "Darwin":
        full = _run(["id", "-F"]) or _run(["dscl", ".", "-read", f"/Users/{user}", "RealName"]).replace("RealName:", "").strip()
    elif system == "Linux":
        try:
            import pwd
            full = pwd.getpwnam(user).pw_gecos.split(",")[0]
        except Exception:
            pass
    elif system == "Windows":
        full = _run(["powershell", "-NoProfile", "-Command", "([adsi]\"WinNT://$env:USERDOMAIN/$env:USERNAME,user\").FullName"])
    return {
        "username": user,
        "full_name": full or user,
        "hostname": platform.node(),
        "os": f"{system} {platform.release()}",
        "git_name": _run(["git", "config", "--global", "user.name"]),
    }


def repo_info(root: Path) -> dict:
    remote = _run(["git", "-C", str(root), "config", "--get", "remote.origin.url"])
    # strip credentials from remote URLs
    if "@" in remote and remote.startswith("http"):
        remote = "https://" + remote.split("@", 1)[1]
    return {
        "name": (remote.rstrip("/").split("/")[-1].removesuffix(".git") if remote else root.resolve().name),
        "remote": remote or None,
        "branch": _run(["git", "-C", str(root), "rev-parse", "--abbrev-ref", "HEAD"]) or None,
        "commit": _run(["git", "-C", str(root), "rev-parse", "--short", "HEAD"]) or None,
    }
