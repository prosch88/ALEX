#!/usr/bin/env python3
# Inspired by: https://github.com/FloatingOctothorpe/dump_android_backup from 'Floating Octothorpe'
# This version isn't using pyaes
import argparse
import io
import os
import shutil
import sys
import tarfile
import tempfile
import zipfile
import zlib
import hashlib
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA1

ANDROID_MAGIC = b"ANDROID BACKUP\n"
PBKDF2_KEY_SIZE = 32

backup_map = {
    "c":    "dump/data/data/{app}/cache/{cont}",
    "db":   "dump/data/data/{app}/databases/{cont}",
    "f":    "dump/data/data/{app}/files/{cont}",
    "nb":   "dump/data/data/{app}/no_backup/{cont}",
    "r":    "dump/data/data/{app}/{cont}",
    "sp":   "dump/data/data/{app}/shared_prefs/{cont}",
    "d_c":  "dump/data/user_de/0/{app}/cache/{cont}",
    "d_db": "dump/data/user_de/0/{app}/databases/{cont}",
    "d_f":  "dump/data/user_de/0/{app}/files/{cont}",
    "d_nb": "dump/data/user_de/0/{app}/no_backup/{cont}",
    "d_r":  "dump/data/user_de/0/{app}/{cont}",
    "d_sp": "dump/data/user_de/0/{app}/shared_prefs/{cont}",
    "k":    "extra/backup/{app}/{cont}",
}

def map_bu_path(path: str):
    parts = path.strip("/").split("/")
    if len(parts) < 3 or parts[0] != "apps":
        return None

    app = parts[1]
    if len(parts) == 3:
        filename = parts[2]
        return f"extra/backup/{app}/{filename}"

    key = parts[2]
    cont = "/".join(parts[3:])
    template = backup_map.get(key)
    if not template:
        return None

    return template.format(app=app, cont=cont)

class AndroidBackupError(Exception):
    pass

def to_utf8_bytes(data: bytes) -> bytes:
    out = bytearray()
    for b in data:
        if b < 0x80:
            out.append(b)
        else:
            out.append(0xEF | (b >> 12))
            out.append(0xBC | ((b >> 6) & 0x3F))
            out.append(0x80 | (b & 0x3F))
    return bytes(out)


def decrypt_master_key_blob(user_key, user_iv, blob):
    cipher = AES.new(user_key, AES.MODE_CBC, user_iv)
    plain = cipher.decrypt(blob)

    bio = io.BytesIO(plain)
    iv_len = bio.read(1)[0]
    master_iv = bio.read(iv_len)

    key_len = bio.read(1)[0]
    master_key = bio.read(key_len)

    chk_len = bio.read(1)[0]
    checksum = bio.read(chk_len)

    return master_iv, master_key, checksum


def parse_header(f, password):
    if f.readline() != ANDROID_MAGIC:
        raise AndroidBackupError("No Android Backup File")

    version = int(f.readline())
    compression = int(f.readline())
    encryption = f.readline().decode().strip()

    header = {
        "version": version,
        "compression": compression,
        "encryption": encryption,
        "payload_offset": f.tell()
    }

    if encryption != "AES-256":
        return header

    if not password:
        raise AndroidBackupError("Password needed!")

    user_salt = bytes.fromhex(f.readline().decode().strip())
    checksum_salt = bytes.fromhex(f.readline().decode().strip())
    rounds = int(f.readline())
    user_iv = bytes.fromhex(f.readline().decode().strip())
    master_key_blob = bytes.fromhex(f.readline().decode().strip())

    user_key = PBKDF2(
        password.encode("utf-8"),
        user_salt,
        dkLen=32,
        count=rounds,
        hmac_hash_module=SHA1
    )

    master_iv, master_key, checksum = decrypt_master_key_blob(
        user_key, user_iv, master_key_blob
    )

    # Check Checksum
    if version > 1:
        mk_for_hmac = to_utf8_bytes(master_key)
    else:
        mk_for_hmac = master_key

    calc_checksum = hashlib.pbkdf2_hmac(
        "sha1",
        mk_for_hmac,
        checksum_salt,
        rounds,
        PBKDF2_KEY_SIZE
    )

    if checksum != calc_checksum:
        raise AndroidBackupError("Wrong password!")

    header.update({
        "master_key": master_key,
        "master_iv": master_iv,
        "payload_offset": f.tell()
    })

    return header


def extract_backup(ab_file, out_file, password, prog_text=None):
    outsize = 0
    with open(ab_file, "rb") as f:
        header = parse_header(f, password)
        f.seek(header["payload_offset"])

        if header["encryption"] == "AES-256":
            cipher = AES.new(
                header["master_key"],
                AES.MODE_CBC,
                header["master_iv"]
            )

            decrypted = b""
            while True:
                chunk = f.read(1024 * 1024)
                outsize += len(chunk)
                if prog_text != None:
                    prog_text.configure(text=f"{outsize/1024/1024:.1f} MB processed")
                if not chunk:
                    break
                decrypted += cipher.decrypt(chunk)
        else:
            decrypted = f.read()

    try:
        tar_data = zlib.decompress(decrypted)
    except zlib.error as e:
        raise AndroidBackupError(f"zlib error: {e}")

    with open(out_file, "wb") as out:
        out.write(tar_data)

    print(f"Extracted: {out_file}")

class PayloadReader:
    """Read the tar stream of a backup: decrypt and decompress in small steps.

    The backup is never held in memory as a whole, so its size is not limited by the RAM of the workstation.
    """
    CHUNK = 1024 * 1024
    TAIL = 64 * 1024            # more than tarfile reads ahead (its buffer is 10 KB)

    def __init__(self, f, header, on_progress=None):
        self.f = f
        self.cipher = None
        if header["encryption"] == "AES-256":
            self.cipher = AES.new(header["master_key"], AES.MODE_CBC, header["master_iv"])
        self.compressed = header["compression"] == 1
        self.decompressor = zlib.decompressobj()
        self.on_progress = on_progress
        self.pending = b""          # read from the file, not yet a full AES block
        self.buffer = bytearray()   # tar data, not yet handed out
        self.processed = 0
        self.eof = False
        self.delivered = 0          # tar bytes handed out
        self.tail = b""             # the last of them, to check the end marker of the tar data

    def _fill(self):
        tail = self.decompressor.unconsumed_tail if self.compressed else b""
        if tail:
            data = tail
        else:
            chunk = self.f.read(self.CHUNK)
            if not chunk:
                self.eof = True
                if self.compressed:
                    self.buffer += self.decompressor.flush()
                    if not self.decompressor.eof:
                        raise AndroidBackupError("The backup ends before the end of its data (incomplete backup)")
                return
            self.processed += len(chunk)
            if self.on_progress:
                self.on_progress(self.processed)
            if self.cipher:
                chunk = self.pending + chunk
                usable = len(chunk) - (len(chunk) % 16)
                self.pending = chunk[usable:]
                chunk = self.cipher.decrypt(chunk[:usable])
            data = chunk
        if self.compressed:
            try:
                self.buffer += self.decompressor.decompress(data, 4 * self.CHUNK)
            except zlib.error as e:
                raise AndroidBackupError(f"zlib error: {e}")
        else:
            self.buffer += data

    def read(self, size=-1):
        while not self.eof and (size < 0 or len(self.buffer) < size):
            self._fill()
        if size < 0:
            size = len(self.buffer)
        out = bytes(self.buffer[:size])
        del self.buffer[:size]
        self.delivered += len(out)
        self.tail = (self.tail + out)[-self.TAIL:]
        return out

    def delivered_block(self, offset):
        """The 512 byte tar block at this offset, if it is among the data handed out last."""
        start = self.delivered - len(self.tail)
        if offset < start:
            return b""
        return self.tail[offset - start:offset - start + 512]


def backup_to_zip(ab_file, zip, password, change, prog_text=None, log=None):
    """Unpack the files of a backup into the ZIP. Returns True if the whole backup was unpacked.

    change is set to 1 on success and to 2 if the backup could not be read to its end.
    Files that were read before an error stay in the ZIP.
    """
    def report(text):
        if log:
            log(text)
        else:
            print(text)

    def on_progress(processed):
        if prog_text:
            prog_text.configure(text=f"{processed/1024/1024:.1f} MB processed")

    count = 0
    complete = False
    zip_name = getattr(zip, "filename", None)
    spool_dir = os.path.dirname(os.path.abspath(zip_name)) if zip_name else None   # large files are buffered next to the ZIP, not in the system temp folder
    try:
        with open(ab_file, "rb") as f:
            header = parse_header(f, password)
            f.seek(header["payload_offset"])
            reader = PayloadReader(f, header, on_progress)
            with tarfile.open(fileobj=reader, mode="r|") as tar:
                for member in tar:
                    if not member.isfile():
                        continue
                    original_path = member.name
                    clean_path = original_path.lstrip("/")
                    new_path = map_bu_path(clean_path)
                    if not new_path:
                        new_path = f"extra/backup/{clean_path}"

                    zip_info = zipfile.ZipInfo(new_path)
                    zip_info.compress_type = zip.compression
                    zip_info.external_attr = 0o600 << 16                    # as ZipFile.writestr() sets it for a name: without it the files unpack with no permissions
                    try:
                        zip_info.date_time = max(datetime.fromtimestamp(member.mtime).timetuple()[:6], (1980, 1, 1, 0, 0, 0))    # keep the file time of the backup
                    except (OverflowError, OSError, ValueError):
                        zip_info.date_time = (1980, 1, 1, 0, 0, 0)
                    source = tar.extractfile(member)
                    # Read the file completely before it goes into the ZIP: a file cut off by an incomplete backup is left out
                    with tempfile.SpooledTemporaryFile(max_size=32 * 1024 * 1024, dir=spool_dir) as spool:
                        shutil.copyfileobj(source, spool, 1024 * 1024)
                        if spool.tell() != member.size:
                            raise AndroidBackupError(f"The backup ends inside the file {member.name} (incomplete backup)")
                        spool.seek(0)
                        with zip.open(zip_info, "w", force_zip64=member.size >= 2**31) as target:
                            shutil.copyfileobj(spool, target, 1024 * 1024)
                    count += 1
                # tarfile stops without an error at a damaged or cut-off header. Only the end marker, a block of zeros, is a regular end.
                marker = reader.delivered_block(tar.offset)
                if len(marker) != 512 or any(marker):
                    raise AndroidBackupError("The tar data of the backup stops without its end marker (damaged or incomplete backup)")
            while reader.read(1024 * 1024):                                 # read to the end: reports a backup whose compressed data is cut off after the last file
                pass
        complete = True
    except Exception as e:
        report(f"Error unpacking the backup {ab_file} after {count} file(s): {type(e).__name__}: {e}")
    finally:
        if complete:
            report(f"Unpacked {count} file(s) from the backup {ab_file}")
        change.set(1 if complete else 2)
    return complete

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input", help="backup.ab")
    ap.add_argument("output", help="backup.tar")
    ap.add_argument("--password", help="Backup Passwort")
    args = ap.parse_args()

    try:
        extract_backup(args.input, args.output, args.password)
    except AndroidBackupError as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
