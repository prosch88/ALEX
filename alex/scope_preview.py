#!/usr/bin/env python3
# ALEX - Android Logical Extractor
# Scope preview: what a pull of a folder can reach, before the pull is started.
# For every folder the device counts the files, opens each one for a single byte, and counts what it refuses.
# Read-only: "find", "head", "du" and "wc" on the device, nothing is written or changed.

import shlex

# A file counts as refused when "head" of the device cannot read its first byte. On current Android versions the test
# "[ -r file ]" and the mode bits say "readable" for system files that adb then refuses to open, so the file is opened.
# not_listed: entries whose type the shell cannot read. A pull does not see them, they are missing from its listing.
SCAN_SCRIPT = r'''
d="$1"
if [ ! -e "$d" ]; then echo "exists=0"; exit 0; fi
echo "exists=1"
echo "files=$(find "$d" -type f 2>/dev/null | wc -l)"
if head -q -c 1 /proc/version >/dev/null 2>&1; then
  echo "refused=$(find "$d" -type f -exec head -q -c 1 {} + 2>&1 >/dev/null | grep -c '^head: ')"
else
  echo "refused="
fi
echo "not_listed=$(find "$d" 2>&1 >/dev/null | grep -c '^find: ')"
echo "links=$(find "$d" -type l 2>/dev/null | wc -l)"
echo "kb=$(du -ks "$d" 2>/dev/null | cut -f1)"
'''


def number(value):
    try:
        return int(value.strip())
    except (AttributeError, ValueError):
        return None


def parse_scan(output):
    values = {}
    for line in output.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            values[key.strip()] = value
    return {"exists": values.get("exists", "").strip() == "1", "files": number(values.get("files")), "refused": number(values.get("refused")),
            "not_listed": number(values.get("not_listed")), "links": number(values.get("links")), "kb": number(values.get("kb"))}


def scan_folder(shell, folder):
    """Counts for one folder of the device: {folder, exists, files, refused, not_listed, links, kb}. A count the device did not give is None."""
    result = parse_scan(shell("sh -c " + shlex.quote(SCAN_SCRIPT) + " sh " + shlex.quote(folder)))
    result["folder"] = folder
    return result


def add_up(label, results):
    """One row for a group of folders (e.g. all app folders)."""
    total = {"folder": label, "exists": any(r["exists"] for r in results)}
    for key in ("files", "refused", "not_listed", "links", "kb"):
        values = [r[key] for r in results if r["exists"]]
        total[key] = None if any(v is None for v in values) else sum(values)
    return total


def readable_share(result):
    """Share of the files of the folder a pull can read, 0..1, or None if it is not known."""
    if not result["exists"] or result["files"] is None or result["refused"] is None or result["not_listed"] is None:
        return None
    total = result["files"] + result["not_listed"]
    if total == 0:
        return None
    return (result["files"] - result["refused"]) / total


def size_text(kb):
    if kb is None:
        return "?"
    if kb >= 1024 * 1024:
        return f"{kb / 1024 / 1024:.1f} GB"
    return f"{kb / 1024:.1f} MB"


HEADER = f"{'folder':34} {'size':>9} {'files':>7} {'readable':>8} {'refused':>7} {'not listed':>10} {'links':>6}"


def format_row(result):
    name = result["folder"] if len(result["folder"]) <= 34 else result["folder"][:31] + "..."
    if not result["exists"]:
        return f"{name:34} not found, or no access for the shell"
    show = lambda value: "?" if value is None else str(value)
    share = readable_share(result)
    readable = "?" if result["files"] is None or result["refused"] is None else str(result["files"] - result["refused"])
    percent = "" if share is None else f" ({share * 100:.0f} %)"
    return (f"{name:34} {size_text(result['kb']):>9} {show(result['files']):>7} {readable:>8} {show(result['refused']):>7} "
            f"{show(result['not_listed']):>10} {show(result['links']):>6}{percent}")


def totals_text(results):
    present = [r for r in results if r["exists"]]
    total = add_up("total", present) if present else None
    if total is None or total["files"] is None or total["refused"] is None or total["not_listed"] is None:
        return "Totals are not known for every folder."
    return (f"{total['files'] - total['refused']} of {total['files'] + total['not_listed']} files can be read "
            f"({total['refused']} refused when opened, {total['not_listed']} not listed for the shell), {size_text(total['kb'])} listed.")
