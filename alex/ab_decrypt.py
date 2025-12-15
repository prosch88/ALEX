#!/usr/bin/env python3
# Inspired by: https://github.com/FloatingOctothorpe/dump_android_backup from 'Floating Octothorpe'
# This version isn't using pyaes
import argparse
import io
import sys
import zlib
import hashlib
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA1

ANDROID_MAGIC = b"ANDROID BACKUP\n"
PBKDF2_KEY_SIZE = 32


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


def extract_backup(ab_file, out_file, password, prog_text = None):
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
