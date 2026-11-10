#!/usr/bin/env python3

import subprocess, zipfile, time, os, argparse, sys

try:
    from .command_log import log_process
except ImportError:
    from command_log import log_process
from datetime import datetime
import tempfile

#subprocess helper
def run(cmd, **kwargs):
    log_process(cmd, **kwargs)
    if sys.platform == "win32":
        kwargs.setdefault("creationflags", subprocess.CREATE_NO_WINDOW)

    return subprocess.run(cmd, **kwargs)

def Popen(cmd, **kwargs):
    log_process(cmd, **kwargs)
    if sys.platform == "win32":
        kwargs.setdefault("creationflags", subprocess.CREATE_NO_WINDOW)

    return subprocess.Popen(cmd, **kwargs)

DEFAULT_EXCLUDES = [
    "/proc", "/apex", "/dev", "/tmp", "/cache", "/run", "/acct",
    "/mnt", "/config", "/data/dalvik-cache", "/data/local/tmp",
    "/bootstrap-apex", "/lost+found", "/linkerconfig", "/data/apex",
    "/system/apex", "/sys", "*.apex",
]


def device_has_su(serial=None):
    cmd = ["adb"] + (["-s", serial] if serial else [])
    result = run(cmd + ["shell", "command -v su"], capture_output=True,
                 timeout=15)
    return result.returncode == 0 and bool(result.stdout.strip())


def su_root_ffs(outzip="FFS.zip", filetext=None, prog_text=None, log=print,
                change=None, mtk_su=False, c_su=False, has_exec_out=True,
                serial=None, root="/", progress=None, zip_backend="auto"):
    try:
        from .ffs import DeviceStream, acquire
    except ImportError:
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from alex.ffs import DeviceStream, acquire
    try:
        result = acquire(outzip, stream=DeviceStream(
            serial=serial, c_su=c_su, mtk_su=mtk_su,
            has_su=device_has_su(serial), has_exec_out=has_exec_out),
            root=root, excludes=DEFAULT_EXCLUDES, output_format="zip",
            progress=progress, log=log or print, zip_backend=zip_backend)
    except Exception:
        if change is not None:
            change.set(-1)
        raise
    if change is not None:
        change.set(1)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="FFS.zip")
    parser.add_argument("--serial")
    parser.add_argument("--root", default="/")
    parser.add_argument("--backend", choices=("auto", "script"), default="auto")
    args = parser.parse_args()
    su_root_ffs(args.output, serial=args.serial, root=args.root, c_su=True, zip_backend=args.backend)
