#!/usr/bin/env python3

import subprocess, zipfile, time, os, argparse
from datetime import datetime
import tempfile

MARKER_PREFIX = "<<<FILE PATH="

DEFAULT_EXCLUDES = [
    "/proc", "/apex", "/dev", "/tmp", "/cache", "/run", "/acct",
    "/mnt", "/mnt/runtime", "/mnt/asec", "/mnt/obb", "/config",
    "/data/dalvik-cache", "/data/local/tmp", "/bootstrap-apex",
    "/lost+found", "/linkerconfig", "/data/apex", "/system/apex",
    "/sys", "*.apex"
]

normalize = r"${f//\/\//\/}"

def build_remote_script(root, excludes):
    excl_str = " ".join(excludes)
    return f"""#!/system/bin/sh
ROOT="{root}"
EXCLUDES="{excl_str}"

should_exclude() {{
  p="$1"
  for ex in $EXCLUDES; do
    case "$p" in "$ex"|"$ex"/*) return 0;; esac
  done
  return 1
}}

walk() {{
  DIR="$1"
  for f in "$DIR"/*; do
    [ -e "$f" ] || continue
    [ -L "$f" ] && continue
    f="{normalize}"  # normalize //
    should_exclude "$f" && continue
    if [ -d "$f" ]; then
      walk "$f"
    elif [ -f "$f" ]; then
      size=$(stat -c %s "$f" 2>/dev/null || echo 0)
      mtime=$(stat -c %Y "$f" 2>/dev/null || echo 0)
      mode=$(stat -c %a "$f" 2>/dev/null || echo 0)
      inode=$(stat -c %i "$f" 2>/dev/null || echo "")
      printf '{MARKER_PREFIX}%s SIZE=%s MTIME=%s MODE=%s INODE=%s>>>\\n' "$f" "$size" "$mtime" "$mode" "$inode"
      cat "$f" 2>/dev/null
      printf '\\n<<<DONE>>>\\n'
    fi
  done
}}

walk "$ROOT"
printf '<<<FINISHED>>>\\n'
"""

def read_line(proc):
    line = bytearray()
    while True:
        ch = proc.stdout.read(1)
        if not ch:
            return None if not line else bytes(line)
        line += ch
        if ch == b'\n':
            return bytes(line)

def read_exact(proc, n):
    buf = bytearray()
    remaining = n
    while remaining > 0:
        chunk = proc.stdout.read(min(512*1024, remaining))
        if not chunk:
            raise IOError("Unexpected EOF while reading bytes")
        buf += chunk
        remaining -= len(chunk)
    return bytes(buf)

def device_has_su() -> bool:
    try:
        result = subprocess.run(
            ["adb", "shell", "which", "su"],
            capture_output=True, text=True
        )
        return result.stdout.strip() != ""
    except Exception:
        return False

def push_temp_script(script_text, mtk_su=False, c_su=False):
    with tempfile.NamedTemporaryFile("w", delete=False, newline="\n") as f:
        f.write(script_text)
        local_path = f.name
    remote_path = "/data/local/tmp/devicedump.sh"
    # push script to device
    subprocess.run(["adb", "push", local_path, remote_path], check=True)
    if device_has_su():
        if c_su:
            subprocess.run(["adb", "shell", "su", "-c", f"chmod 700 {remote_path}"], check=True)
        else:
            subprocess.run(["adb", "shell", "sh", "-c", f"echo 'chmod 700 {remote_path}' | su"],
                          check=True, stdin=subprocess.DEVNULL)
    elif mtk_su == True:
        subprocess.run(["adb", "shell", "/data/local/tmp/mtk-su", "-c", f"chmod 700 {remote_path}"], check=True)
    else:
        subprocess.run(["adb", "shell", f"chmod 700 {remote_path}"], check=True)
    os.unlink(local_path)
    return remote_path

def su_root_ffs(outzip=None, filetext=None, prog_text=None, log=None, change=None, mtk_su=False, c_su=False):
    if outzip == None:
        outzip = "FFS.zip"
    root = "/"
    ffs_size = 0

    excludes = list(dict.fromkeys(DEFAULT_EXCLUDES))
    if change == None:
        print(f"Output ZIP: {outzip}")
        print(f"Remote root: {root}")
        print(f"Excludes ({len(excludes)}): {', '.join(excludes)}")
    else:
        pass

    remote_script_text = build_remote_script(root, excludes)
    remote_script_path = push_temp_script(remote_script_text, mtk_su, c_su)

    if device_has_su():
        if c_su:
            cmd = ["adb", "exec-out", "su", "-c", f"sh {remote_script_path}"]
        else:
            cmd = ["adb", "exec-out", "sh", "-c", f"echo 'sh {remote_script_path}' | su"]
    elif mtk_su == True:
        cmd = ["adb", "exec-out", "/data/local/tmp/mtk-su", "-c", f"{remote_script_path}"]
    else:
        cmd = ["adb", "exec-out", f"sh {remote_script_path}"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, bufsize=0)

    zf = zipfile.ZipFile(outzip, "w", allowZip64=True)
    seen_inodes = set()
    count = 0
    start_time = time.time()

    while True:
        line = read_line(proc)
        if line is None:
            break
        line = line.rstrip(b"\r\n")
        if not line.startswith(MARKER_PREFIX.encode()):
            if line.strip() == b"<<<FINISHED>>>":
                break
            continue
        try:
            header = line.decode(errors="ignore")[len(MARKER_PREFIX):-3]
            parts = header.split(" SIZE=")
            path = parts[0]
            rest = parts[1].split(" MTIME=")
            size = int(rest[0])
            rest2 = rest[1].split(" MODE=")
            mtime = int(rest2[0])
            rest3 = rest2[1].split(" INODE=")
            mode = int(rest3[0])
            inode = rest3[1]
        except Exception as e:
            if log == None:
                print(f"Error parsing marker: {line}, skipping")
            else:
                log(f"Error parsing marker: {line}, skipping")
            read_exact(proc, size)
            read_line(proc)
            continue

        if inode in seen_inodes:
            _ = read_exact(proc, size)
            _ = read_line(proc)
            continue
        seen_inodes.add(inode)
        count += 1
        if filetext == None:
            print(f"[{count}] {path} ({size} bytes)")
        else:
            if len(path) > 60:
                fpath = f"...{path[-57:]}"
            else:
                fpath = path
            filetext.configure(text=f"Extracting available files from the device filesystem.\nFile: {fpath}")

        zi = zipfile.ZipInfo(path)
        try:
            dt = datetime.fromtimestamp(mtime)
            year = max(1980, min(dt.year, 2107))
            zi.date_time = (year, dt.month, dt.day, dt.hour, dt.minute, dt.second)
        except:
            zi.date_time = time.localtime()[:6]
        zi.external_attr = (mode & 0xFFFF) << 16
        zi.compress_type = zipfile.ZIP_DEFLATED if size < 1024*1024 else zipfile.ZIP_STORED

        try:
            with zf.open(zi, "w", force_zip64=True) as zfile:
                remaining = size
                while remaining > 0:
                    to_read = min(512*1024, remaining)
                    chunk = read_exact(proc, to_read)
                    zfile.write(chunk)
                    ffs_size += len(chunk)
                    if prog_text != None:
                        prog_text.configure(text=f"{ffs_size/1024/1024:.1f} MB written")
                    remaining -= len(chunk)
                while True:
                    l2 = read_line(proc)
                    if l2 is None or l2.strip() == b"<<<DONE>>>":
                        break
        except Exception as e:
            if log == None:
                print(f"ERROR reading {path}: {e}")
            else:
                log(f"ERROR reading {path}: {e}")

    zf.close()
    proc.stdout.close()
    proc.stderr.close()
    try: proc.wait(timeout=2)
    except: proc.kill()

    if device_has_su():
        if c_su:
            subprocess.run(["adb", "shell", "su", "-c", f"rm {remote_script_path}"])
        else:
            subprocess.run(["adb", "shell", "sh", "-c", f"echo 'rm {remote_script_path}' | su"],
                          stdin=subprocess.DEVNULL)
    else:
        subprocess.run(["adb", "shell", f"rm {remote_script_path}"])
    elapsed = time.time() - start_time
    if change != None:
        change.set(1)
    else:
        print(f"DONE: files={count}, elapsed={int(elapsed)}s")


if __name__ == "__main__":
    su_root_ffs()