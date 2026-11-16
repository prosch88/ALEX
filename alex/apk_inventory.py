#!/usr/bin/env python3
# ALEX - Android Logical Extractor
# APK capture: the installed APK files of the user-installed apps, with an inventory.
# One line per APK file: package, version, installer, install times, the signing certificate the package manager reports,
# the path on the device, size and SHA-256. Read-only on the device ("pm", "dumpsys package" and the adb file sync).

import csv
import hashlib
import io
import os
import re
import shlex
import struct

FIELDS = ["package", "version_name", "version_code", "installer", "uid", "first_install", "last_update", "signing_version", "signer_sha256",
          "signer_sha256_device", "apk_on_device", "apk_in_zip", "size", "sha256", "status", "note"]

# IDs of the signature schemes in the APK Signing Block, newest first
SIGNATURE_SCHEMES = [(0x1b93ad61, "v3.1"), (0xf05368c0, "v3"), (0x7109871a, "v2")]


def apk_signer_sha256(path):
    """SHA-256 of the first signing certificate in the APK Signing Block of a pulled APK file: (hex digest, scheme), or (None, None).

    Read from the file itself, without the device: the certificate of signature scheme v3.1, v3 or v2. An APK that is only
    signed with the JAR scheme (v1) has no such block. The signature is not verified, the certificate is only read.
    """
    def prefixed(data, offset=0):
        (length,) = struct.unpack_from("<I", data, offset)
        if length > len(data) - offset - 4:
            raise ValueError("length runs past the data")
        return data[offset + 4:offset + 4 + length], offset + 4 + length

    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            tail_size = min(size, 65557)                                         # the end of central directory record, with the longest possible comment
            f.seek(size - tail_size)
            tail = f.read(tail_size)
            eocd = tail.rfind(b"PK\x05\x06")
            if eocd < 0:
                return None, None
            (directory,) = struct.unpack_from("<I", tail, eocd + 16)
            if directory < 32:
                return None, None
            f.seek(directory - 24)
            footer = f.read(24)
            if footer[8:] != b"APK Sig Block 42":
                return None, None
            (block_size,) = struct.unpack_from("<Q", footer, 0)
            if block_size < 24 or block_size > directory - 8 or block_size > 64 * 1024 * 1024:
                return None, None
            f.seek(directory - block_size)
            pairs = f.read(block_size - 24)
        blocks = {}
        offset = 0
        while offset + 12 <= len(pairs):
            (length,) = struct.unpack_from("<Q", pairs, offset)
            (block_id,) = struct.unpack_from("<I", pairs, offset + 8)
            if length < 4 or offset + 8 + length > len(pairs):
                break
            blocks[block_id] = pairs[offset + 12:offset + 8 + length]
            offset += 8 + length
        for block_id, scheme in SIGNATURE_SCHEMES:
            if block_id in blocks:
                signers, _ = prefixed(blocks[block_id])
                signer, _ = prefixed(signers)
                signed_data, _ = prefixed(signer)
                _, after_digests = prefixed(signed_data)
                certificates, _ = prefixed(signed_data, after_digests)
                certificate, _ = prefixed(certificates)
                return hashlib.sha256(certificate).hexdigest(), scheme
    except (OSError, ValueError, struct.error):
        pass
    return None, None

DETAIL_FIELDS = "versionName=|versionCode=|firstInstallTime=|lastUpdateTime=|installerPackageName=|apkSigningVersion=|Signatures: "


def parse_package_list(output):
    """Lines of "pm list packages -f [-3] [-i] [--show-versioncode] [-U]" -> [{package, base_apk, version_code, installer, uid}].

    The path can hold "=" (the random folder names end in "=="), and "installer=" follows later in the line: the package name is what
    follows ".apk=".
    """
    packages = []
    for line in output.splitlines():
        match = re.match(r"package:(.+\.apk)=([A-Za-z0-9_.]+)(.*)$", line.strip())
        if not match:
            continue
        rest = match.group(3)
        find = lambda pattern: (re.search(pattern, rest) or [None, None])[1]
        packages.append({"package": match.group(2), "base_apk": match.group(1), "version_code": find(r"versionCode:(\d+)"),
                         "installer": find(r"installer=(\S+)"), "uid": find(r"uid:(\d+)")})
    return packages


def list_packages(shell, third_party=True):
    flag = " -3" if third_party else ""
    output = shell(f"pm list packages -f{flag} -i --show-versioncode -U 2>/dev/null")
    packages = parse_package_list(output)
    if not packages:                                                            # an old "pm" does not know the newer options
        packages = parse_package_list(shell(f"pm list packages -f{flag} -i 2>/dev/null"))
    return sorted(packages, key=lambda p: p["package"])


def details_script(names):
    quoted = " ".join(shlex.quote(name) for name in names)
    return (f"for p in {quoted}; do echo \"ALEX_PACKAGE $p\"; pm path \"$p\" 2>/dev/null | grep '^package:'; "
            f"dumpsys package \"$p\" 2>/dev/null | grep -E '^ +({DETAIL_FIELDS})'; done")


def parse_details(output):
    """Answer of details_script -> {package: {apks, version_name, first_install, last_update, signing_version, signer_sha256}}.

    Of every field the first line counts: "dumpsys package" repeats the install time once per user of the device.
    signer_sha256 is the certificate digest as the package manager prints it ("Signatures: [..]", in the part on app links).
    It is not printed for every app and not by older Android versions: the field is then empty. pull_apks() reads the
    certificate from the APK file as well.
    """
    details = {}
    current = None
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("ALEX_PACKAGE "):
            current = details.setdefault(line[len("ALEX_PACKAGE "):], {"apks": [], "version_name": None, "first_install": None, "last_update": None,
                                                                       "signing_version": None, "signer_sha256": None})
        elif current is None:
            continue
        elif line.startswith("package:"):
            current["apks"].append(line[len("package:"):])
        else:
            for key, pattern in (("version_name", r"^versionName=(.*)$"), ("first_install", r"^firstInstallTime=(.*)$"), ("last_update", r"^lastUpdateTime=(.*)$"),
                                 ("signing_version", r"^apkSigningVersion=(\d+)"), ("signer_sha256", r"^Signatures: \[([0-9A-Fa-f:, ]+)\]")):
                match = re.match(pattern, line)
                if match and current[key] is None:
                    value = match.group(1).strip()
                    if key == "signer_sha256":
                        value = value.replace(":", "").lower()
                    current[key] = value.split(",")[0].strip() if key == "signer_sha256" else value
    return details


def read_details(shell, packages, batch=40):
    """Adds the APK paths and the details to every package of the list."""
    for start in range(0, len(packages), batch):
        part = packages[start:start + batch]
        details = parse_details(shell(details_script([p["package"] for p in part])))
        for package in part:
            found = details.get(package["package"], {})
            package["apks"] = found.get("apks") or [package["base_apk"]]
            for key in ("version_name", "first_install", "last_update", "signing_version", "signer_sha256"):
                package[key] = found.get(key)
    return packages


def pull_apks(pull_file, packages, zip, temp_folder, log, on_progress=None):
    """Pull every APK file of the packages into the ZIP under apks/<package>/ and return the inventory rows.

    pull_file(device_path, local_path) -> size. A file that cannot be pulled is listed with the reason and is not in the ZIP.
    """
    import zipfile
    rows = []
    total = sum(len(p["apks"]) for p in packages)
    done = 0
    os.makedirs(temp_folder, exist_ok=True)
    local = os.path.join(temp_folder, "pulled.apk")
    for package in packages:
        for apk in package["apks"]:
            row = {"package": package["package"], "version_name": package.get("version_name"), "version_code": package.get("version_code"),
                   "installer": package.get("installer"), "uid": package.get("uid"), "first_install": package.get("first_install"),
                   "last_update": package.get("last_update"), "signing_version": package.get("signing_version"), "signer_sha256": "",
                   "signer_sha256_device": package.get("signer_sha256"),
                   "apk_on_device": apk, "apk_in_zip": "", "size": "", "sha256": "", "status": "", "note": ""}
            try:
                size = pull_file(apk, local)
                signer, scheme = apk_signer_sha256(local)                       # from the file itself, not from what the device says
                if signer:
                    row["signer_sha256"] = signer
                    if row["signer_sha256_device"] and row["signer_sha256_device"] != signer:
                        row["note"] = f"the certificate in the APK ({scheme}) is not the one the package manager reports"
                else:
                    row["note"] = "no APK Signing Block (v2/v3) in the file"
                name = f"apks/{package['package']}/{apk.rsplit('/', 1)[-1]}"
                digest = hashlib.sha256()
                with open(local, "rb") as source, zip.open(zipfile.ZipInfo(name), "w", force_zip64=size >= 2**31) as target:
                    while True:
                        block = source.read(1024 * 1024)
                        if not block:
                            break
                        digest.update(block)
                        target.write(block)
                row.update(apk_in_zip=name, size=size, sha256=digest.hexdigest(), status="ok")
            except Exception as e:
                row.update(status="pull failed", note=f"{type(e).__name__}: {e}")
                log(f"APK not pulled: {apk}: {type(e).__name__}: {e}")
            try:
                os.remove(local)
            except OSError:
                pass
            rows.append(row)
            done += 1
            if on_progress:
                on_progress(done, total, package["package"])
    return rows


def inventory_csv(rows):
    text = io.StringIO(newline="")
    writer = csv.DictWriter(text, fieldnames=FIELDS)
    writer.writeheader()
    for row in rows:
        writer.writerow({key: ("" if row.get(key) is None else row.get(key)) for key in FIELDS})
    return text.getvalue().encode("utf-8", errors="backslashreplace")


def summary(packages, rows):
    ok = [row for row in rows if row["status"] == "ok"]
    differ = sum(1 for row in ok if row.get("signer_sha256") and row.get("signer_sha256_device") and row["signer_sha256"] != row["signer_sha256_device"])
    return (f"{len(packages)} app(s), {len(ok)} APK file(s) pulled ({sum(row['size'] for row in ok)} bytes), {len(rows) - len(ok)} not pulled,\n"
            f"signing certificate read from {sum(1 for row in ok if row.get('signer_sha256'))} file(s),\n"
            f"{differ} file(s) with a certificate other than the one the package manager reports")
