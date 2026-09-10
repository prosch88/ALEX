# alex/dirty_shell.py

from __future__ import annotations

import re
import subprocess
import sys
import threading
import time
from typing import BinaryIO, Callable, List, Optional, Union


def _run(cmd, **kwargs):
    if sys.platform == "win32":
        kwargs.setdefault("creationflags", subprocess.CREATE_NO_WINDOW)
    return subprocess.run(cmd, **kwargs)


def _Popen(cmd, **kwargs):
    if sys.platform == "win32":
        kwargs.setdefault("creationflags", subprocess.CREATE_NO_WINDOW)
    return subprocess.Popen(cmd, **kwargs)

class DirtyShell:
    PROMPT_RE = re.compile(rb"(?m)^[#\$]\s*$")
    PROMPT_ANY = re.compile(rb"[#\$]\s*$")

    def __init__(
        self,
        shell_cmd: List[str],
        adb: str = "adb",
        serial: Optional[str] = None,
        startup_timeout: float = 15.0,
        command_timeout: float = 30.0,
        encoding: str = "utf-8",
        errors: str = "replace",
    ):

        self.shell_cmd = list(shell_cmd)
        self.adb = adb
        self.serial = serial
        self.startup_timeout = startup_timeout
        self.command_timeout = command_timeout
        self.encoding = encoding
        self.errors = errors

        self._proc: Optional[subprocess.Popen] = None
        self._lock = threading.RLock()
        self._buf = bytearray()
        self._buf_cond = threading.Condition(self._lock)
        self._reader: Optional[threading.Thread] = None
        self._alive = False
        self._stop_reader = False

    def start(self) -> None:
        if self._alive:
            return

        cmd = [self.adb]
        if self.serial:
            cmd += ["-s", self.serial]
        cmd += self.shell_cmd

        self._proc = _Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
        )
        assert self._proc.stdin and self._proc.stdout

        self._stop_reader = False
        self._buf.clear()
        self._reader = threading.Thread(target=self._reader_loop, daemon=True)
        self._reader.start()

        deadline = time.monotonic() + self.startup_timeout
        with self._buf_cond:
            while time.monotonic() < deadline:
                if self.PROMPT_ANY.search(self._buf):
                    self._alive = True
                    try:
                        self._write(b"stty -echo 2>/dev/null || true\n")
                        self._buf_cond.wait(0.3)
                        self._buf.clear()
                    except Exception:
                        pass
                    return

                if self._proc.poll() is not None:
                    raise RuntimeError(
                        f"Shell process exited early (code={self._proc.returncode}). "
                        f"Output so far:\n{self._buf.decode(self.encoding, self.errors)}"
                    )
                self._buf_cond.wait(0.2)

        raise TimeoutError(
            f"Timeout waiting for prompt after {self.shell_cmd}. "
            f"Captured output:\n{self._buf.decode(self.encoding, self.errors)}"
        )

    def close(self) -> None:
        with self._lock:
            self._stop_reader = True
            if not self._proc:
                return
            try:
                if self._proc.stdin and self._proc.poll() is None:
                    self._proc.stdin.write(b"exit\n")
                    self._proc.stdin.flush()
            except Exception:
                pass
            try:
                self._proc.terminate()
                self._proc.wait(timeout=2)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
            self._alive = False
            self._proc = None

        if self._reader and self._reader.is_alive():
            self._reader.join(timeout=1.0)
        self._reader = None

    def __enter__(self) -> "DirtyShell":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    @property
    def alive(self) -> bool:
        return (
            self._alive
            and self._proc is not None
            and self._proc.poll() is None
        )

    def _reader_loop(self) -> None:
        try:
            while not self._stop_reader and self._proc and self._proc.stdout:
                try:
                    chunk = self._proc.stdout.read(65536)
                except Exception:
                    break
                if not chunk:
                    break
                with self._buf_cond:
                    self._buf.extend(chunk)
                    self._buf_cond.notify_all()
        finally:
            with self._buf_cond:
                self._buf_cond.notify_all()

    def _write(self, data: bytes) -> None:
        if not self._proc or not self._proc.stdin:
            raise RuntimeError("Shell is not running")
        self._proc.stdin.write(data)
        self._proc.stdin.flush()

    def _read_chunk(self, wait: float = 0.15) -> bytes:
        with self._buf_cond:
            if not self._buf:
                self._buf_cond.wait(wait)
            data = bytes(self._buf)
            self._buf.clear()
            return data

    def _discard_line(self, buf: bytearray, deadline: float) -> bytearray:
        while time.monotonic() < deadline:
            if not buf:
                buf.extend(self._read_chunk(0.1))
                if not buf:
                    if self._proc and self._proc.poll() is not None:
                        break
                    continue
            for sep in (b"\r\n", b"\n", b"\r"):
                nl = buf.find(sep)
                if nl != -1:
                    del buf[: nl + len(sep)]
                    return buf
            more = self._read_chunk(0.1)
            if more:
                buf.extend(more)
            elif self._proc and self._proc.poll() is not None:
                break
        return buf

    def _wait_for_marker(self, marker: bytes, timeout: float) -> bytes:
        deadline = time.monotonic() + timeout
        with self._buf_cond:
            while time.monotonic() < deadline:
                if marker in self._buf:
                    self._buf_cond.wait(0.15)
                    data = bytes(self._buf)
                    self._buf.clear()
                    return data
                if self._proc and self._proc.poll() is not None:
                    break
                remaining = deadline - time.monotonic()
                self._buf_cond.wait(min(0.2, max(0.05, remaining)))
            data = bytes(self._buf)
            self._buf.clear()
            return data

    def execute(
        self,
        cmd: str,
        timeout: Optional[float] = None,
        strip_prompt: bool = True,
    ) -> str:
        """
        Führt ein Text-Kommando aus und gibt die Ausgabe als str zurück.
        """
        if not self.alive:
            raise RuntimeError("Shell is not alive – call start() first")

        timeout = timeout if timeout is not None else self.command_timeout
        marker = f"__ALEX_DONE_{int(time.time() * 1000)}__"
        full_cmd = f"{cmd}\necho {marker}\n"

        with self._lock:
            with self._buf_cond:
                self._buf.clear()

            self._write(full_cmd.encode(self.encoding, self.errors))
            raw = self._wait_for_marker(marker.encode(), timeout)

        marker_b = marker.encode()

        cut_idx = -1
        search_from = 0
        while True:
            idx = raw.find(marker_b, search_from)
            if idx == -1:
                break

            line_start = raw.rfind(b"\n", 0, idx) + 1
            line = raw[line_start:idx + len(marker_b)]
            if not line.strip().startswith(b"echo "):
                cut_idx = idx
            search_from = idx + 1

        if cut_idx != -1:
            raw = raw[:cut_idx]
        else:
            idx = raw.rfind(marker_b)
            if idx != -1:
                raw = raw[:idx]

        text = raw.decode(self.encoding, self.errors)
        lines = text.splitlines(keepends=True)

        if lines:
            first = lines[0].rstrip("\r\n")
            if (
                cmd.strip() in first
                or first.strip() == cmd.strip()
                or first.startswith(cmd.split()[0] if cmd.split() else "")
                or "echo __ALEX_DONE_" in first
            ):
                lines = lines[1:]

        prompt_line_re = re.compile(
            r"^.*[\#\$]\s*$"
            r"|^echo __ALEX_DONE_.*"
            r"|^root@.+$"
            r"|^shell@.+$"
            r"|^.*@.*[:\#\$]\s*$"
        )

        if strip_prompt:
            while lines:
                last = lines[-1].rstrip("\r\n")
                if not last.strip():
                    lines.pop()
                    continue
                if prompt_line_re.match(last) or self.PROMPT_ANY.search(lines[-1].encode()):
                    lines.pop()
                    continue
                if "__ALEX_DONE_" in last and "echo" in last:
                    lines.pop()
                    continue
                break

        result = "".join(lines).rstrip("\r\n")
        return result + ("\n" if result else "")

    def execute_bytes(
        self,
        cmd: str,
        timeout: Optional[float] = None,
    ) -> bytes:
        """Wie execute(), liefert aber rohe bytes."""
        if not self.alive:
            raise RuntimeError("Shell is not alive")

        timeout = timeout if timeout is not None else self.command_timeout
        marker = f"__ALEX_DONE_{int(time.time() * 1000)}__"
        full_cmd = f"{cmd}\necho {marker}\n"

        with self._lock:
            with self._buf_cond:
                self._buf.clear()
            self._write(full_cmd.encode())
            raw = self._wait_for_marker(marker.encode(), timeout)

        marker_b = marker.encode()

        cut_idx = -1
        search_from = 0
        while True:
            idx = raw.find(marker_b, search_from)
            if idx == -1:
                break
            line_start = raw.rfind(b"\n", 0, idx) + 1
            line = raw[line_start:idx + len(marker_b)]
            if not line.strip().startswith(b"echo "):
                cut_idx = idx
            search_from = idx + 1

        if cut_idx != -1:
            raw = raw[:cut_idx]
        else:
            idx = raw.rfind(marker_b)
            if idx != -1:
                raw = raw[:idx]

        if b"\n" in raw:
            first, _, rest = raw.partition(b"\n")
            if (
                cmd.encode() in first
                or b"echo __ALEX_DONE_" in first
                or first.strip() == cmd.encode().strip()
            ):
                raw = rest

        lines = raw.splitlines(keepends=True)
        while lines:
            last = lines[-1].rstrip(b"\r\n")
            if not last.strip():
                lines.pop()
                continue
            if self.PROMPT_ANY.search(lines[-1]) or last.startswith(b"echo __ALEX_DONE_"):
                lines.pop()
                continue
            if b"@" in last and (last.endswith(b"#") or last.endswith(b"$")):
                lines.pop()
                continue
            break

        return b"".join(lines).rstrip(b"\r\n")


    def _to_printf_escapes(self, s: str) -> str:
        return "".join(f"\\x{b:02x}" for b in s.encode("ascii"))

    def stream(
        self,
        cmd: str,
        dest: Union[BinaryIO, Callable[[bytes], None], str],
        timeout: Optional[float] = None,
        chunk_size: int = 1024 * 1024,
        progress: Optional[Callable[[int], None]] = None) -> int:

        if not self.alive:
            raise RuntimeError("Shell is not alive")

        close_dest = False
        if isinstance(dest, str):
            dest = open(dest, "wb")
            close_dest = True

        ts = int(time.time() * 1000)
        end_marker = f"ALEXEND{ts}"
        end_b = end_marker.encode("ascii")
        idle_limit = 300.0 if timeout is None else timeout
        total = 0

        def _read_chunk(wait: float = 0.15) -> bytes:
            with self._buf_cond:
                if not self._buf:
                    self._buf_cond.wait(wait)
                data = bytes(self._buf)
                self._buf.clear()
                return data

        def _discard_line(buf: bytearray, deadline: float) -> bytearray:
            while time.monotonic() < deadline:
                if not buf:
                    buf.extend(_read_chunk(0.1))
                    if not buf:
                        if self._proc and self._proc.poll() is not None:
                            break
                        continue
                for sep in (b"\r\n", b"\n", b"\r"):
                    nl = buf.find(sep)
                    if nl != -1:
                        del buf[: nl + len(sep)]
                        return buf
                more = _read_chunk(0.1)
                if more:
                    buf.extend(more)
                elif self._proc and self._proc.poll() is not None:
                    break
            return buf

        try:
            with self._lock:
                with self._buf_cond:
                    self._buf.clear()

                leftover = bytearray()
                sync_m = f"ALEXSYNC{ts}"
                self._write(f"echo {sync_m}\n".encode())
                sync_deadline = time.monotonic() + 10.0
                while time.monotonic() < sync_deadline:
                    leftover.extend(_read_chunk(0.1))
                    if sync_m.encode() in leftover:
                        idx = leftover.find(sync_m.encode())
                        nl = leftover.find(b"\n", idx)
                        if nl != -1:
                            del leftover[: nl + 1]
                        else:
                            leftover.clear()
                        break
                    if self._proc and self._proc.poll() is not None:
                        break

                self._write(f"E={end_marker}\n".encode())
                leftover = _discard_line(leftover, time.monotonic() + 5.0)

                self._write(f"{cmd}; echo -n \"$E\"\n".encode())
                leftover = _discard_line(leftover, time.monotonic() + 10.0)

                ustar = b"ustar"
                scan_deadline = time.monotonic() + 30.0
                found_tar = False
                while time.monotonic() < scan_deadline:
                    if len(leftover) >= 512:
                        window = bytes(leftover[: 512 + 64])
                        pos = window.find(ustar)
                        if pos != -1:
                            hdr_start = pos - 257
                            if hdr_start < 0:
                                hdr_start = 0
                            del leftover[:hdr_start]
                            found_tar = True
                            break
                        if all(c < 32 or c > 126 for c in leftover[:64]) is False:
                            nl = leftover.find(b"\n")
                            if nl != -1 and nl < 200:
                                del leftover[: nl + 1]
                                continue
                    leftover.extend(_read_chunk(0.15))
                    if self._proc and self._proc.poll() is not None:
                        break

                last_data = time.monotonic()

                while True:
                    if leftover:
                        idx = leftover.find(end_b)
                        if idx != -1:
                            data = bytes(leftover[:idx])
                            if data:
                                if callable(dest):
                                    dest(data)
                                else:
                                    dest.write(data)
                                total += len(data)
                                if progress:
                                    progress(total)
                            break

                        if len(leftover) > len(end_b):
                            flush_len = len(leftover) - len(end_b)
                            data = bytes(leftover[:flush_len])
                            del leftover[:flush_len]
                            if data:
                                if callable(dest):
                                    dest(data)
                                else:
                                    dest.write(data)
                                total += len(data)
                                if progress:
                                    progress(total)

                    chunk = _read_chunk(0.15)
                    if chunk:
                        last_data = time.monotonic()
                        leftover.extend(chunk)
                    else:
                        if time.monotonic() - last_data > idle_limit:
                            if leftover:
                                data = bytes(leftover)
                                if callable(dest):
                                    dest(data)
                                else:
                                    dest.write(data)
                                total += len(data)
                            raise TimeoutError(
                                f"Stream stalled after {idle_limit}s "
                                f"(received {total} bytes)"
                            )
                        if self._proc and self._proc.poll() is not None:
                            if leftover:
                                data = bytes(leftover)
                                if callable(dest):
                                    dest(data)
                                else:
                                    dest.write(data)
                                total += len(data)
                            break

        finally:
            if close_dest and hasattr(dest, "close"):
                try:
                    dest.close()
                except Exception:
                    pass

        return total
    
    def stream_b64(
        self,
        cmd: str,
        dest: Union[BinaryIO, str],
        expected_size: Optional[int] = None,
        progress: Optional[Callable[[int], None]] = None,
        timeout: Optional[float] = None,
    ) -> int:
        import base64
        import re

        if not self.alive:
            raise RuntimeError("Shell is not alive")

        close_dest = False
        if isinstance(dest, str):
            dest = open(dest, "wb")
            close_dest = True

        timeout = 600.0 if timeout is None else timeout
        marker = f"__B64END_{int(time.time() * 1000)}__"
        marker_b = marker.encode()

        b64bin = "base64"
        full_cmd = f"({cmd}) 2>/dev/null | {b64bin}; echo {marker}\n"

        try:
            with self._lock:
                with self._buf_cond:
                    self._buf.clear()

                self._write(full_cmd.encode())

                buf = bytearray()
                deadline = time.monotonic() + timeout
                last = time.monotonic()

                while time.monotonic() < deadline:
                    chunk = self._read_chunk(0.25)
                    if chunk:
                        last = time.monotonic()
                        buf.extend(chunk)
                        if marker_b in buf:
                            break
                    else:
                        if time.monotonic() - last > 60:
                            break
                        if self._proc and self._proc.poll() is not None:
                            break

                raw_text = buf.decode("latin-1", errors="replace")

            if marker in raw_text:
                raw_text = raw_text[: raw_text.find(marker)]

            b64_parts = []
            for line in raw_text.splitlines():
                line = line.strip()
                if not line:
                    continue
                if line.startswith("root@") or line.startswith("shell@"):
                    continue
                if "base64" in line or line.startswith("dd ") or line.startswith("cat "):
                    continue
                if marker[:10] in line:
                    continue
                cleaned = re.sub(r"[^A-Za-z0-9+/=]", "", line)
                if len(cleaned) >= 4:
                    b64_parts.append(cleaned)

            b64_data = "".join(b64_parts)
            if not b64_data:
                raise RuntimeError(
                    "Keine Base64-Daten empfangen. "
                    "Gerät hat evtl. kein base64 (toybox base64 testen)."
                )

            pad = (4 - len(b64_data) % 4) % 4
            data = base64.b64decode(b64_data + "=" * pad, validate=False)

            if expected_size is not None:
                data = data[:expected_size]

            if callable(dest):
                dest(data)
            else:
                dest.write(data)

            if progress:
                progress(len(data))

            return len(data)

        finally:
            if close_dest and hasattr(dest, "close"):
                try:
                    dest.close()
                except Exception:
                    pass

    def stream_to_file(
        self,
        cmd: str,
        path: str,
        timeout: Optional[float] = None,
        progress: Optional[Callable[[int], None]] = None,
    ) -> int:
        with open(path, "wb") as f:
            return self.stream(cmd, f, timeout=timeout, progress=progress)

    def cat(self, remote_path: str, dest: Union[str, BinaryIO], **kw) -> int:
        if isinstance(dest, str):
            return self.stream_to_file(f"cat '{remote_path}'", dest, **kw)
        return self.stream(f"cat '{remote_path}'", dest, **kw)

    def tar(self, remote_path: str, dest: Union[str, BinaryIO], **kw) -> int:
        cmd = f"tar cf - '{remote_path}' 2>/dev/null"
        if isinstance(dest, str):
            return self.stream_to_file(cmd, dest, **kw)
        return self.stream(cmd, dest, **kw)

    def dd(
        self,
        if_path: str,
        dest: Union[str, BinaryIO],
        bs: str = "1M",
        count: Optional[int] = None,
        **kw,
    ) -> int:
        cmd = f"dd if='{if_path}' bs={bs}"
        if count is not None:
            cmd += f" count={count}"
        cmd += " 2>/dev/null"
        if isinstance(dest, str):
            return self.stream_to_file(cmd, dest, **kw)
        return self.stream(cmd, dest, **kw)

    def whoami(self) -> str:
        return self.execute("whoami").strip()

    def id(self) -> str:
        return self.execute("id").strip()

if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="DirtyShell test")
    p.add_argument(
        "shell_cmd",
        nargs="+",
        help='Shell-Befehl nach adb, z. B. shell run-as com.example',
    )
    p.add_argument("-s", "--serial", default=None)
    args = p.parse_args()

    with DirtyShell(args.shell_cmd, serial=args.serial) as sh:
        print("whoami →", repr(sh.whoami()))
        print("id     →", repr(sh.id()))
        print(sh.execute("ls -l /data/data 2>&1 | head -10"))