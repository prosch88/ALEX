"""Binary-safe, bounded-memory filesystem acquisition shared by TAR and ZIP."""
import json
import io
from contextlib import ExitStack
import os
import posixpath
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import uuid
import zipfile
import warnings

from .command_log import log_process

CHUNK = 1024 * 1024


def process(args, *, log_enabled=True, **kwargs):
    if log_enabled:
        log_process(args, **kwargs)
    if sys.platform == 'win32':
        kwargs.setdefault('creationflags', subprocess.CREATE_NO_WINDOW)
    return subprocess.Popen(args, **kwargs)


def log_diagnostics(log, output, diagnostics):
    for line in diagnostics.splitlines():
        if line.strip():
            log(f"Filesystem acquisition [{output}]: {line}")


class DeviceStream:
    def __init__(self, serial=None, c_su=True, mtk_su=False, has_su=True,
                 has_exec_out=True, idle_timeout=120):
        self.adb = ['adb'] + (['-s', serial] if serial else [])
        self.c_su, self.mtk_su, self.has_su = c_su, mtk_su, has_su
        self.transport = ['exec-out'] if has_exec_out else ['shell', '-T']
        self.idle_timeout = idle_timeout
        self.preflight_diagnostics = []

    def root(self, command):
        if self.mtk_su:
            return '/data/local/tmp/mtk-su -c sh -c ' + shlex.quote(command)
        if self.has_su:
            return ('su -c ' + shlex.quote(command) if self.c_su else
                    "printf '%s\\n' " + shlex.quote(command) + ' | su')
        return 'sh -c ' + shlex.quote(command)

    def capture(self, command, transport=None, *, log_enabled=True):
        with process(self.adb + (transport or self.transport) + [self.root(command)],
                     log_enabled=log_enabled,
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                     stdin=subprocess.DEVNULL) as proc:
            try:
                out, err = proc.communicate(timeout=30)
            except BaseException:
                proc.kill()
                proc.communicate()
                raise
            if proc.returncode:
                raise RuntimeError(err.decode(errors='replace') or 'ADB command failed')
            return out

    def preflight(self):
        # Keep every byte in the check: never repair or discard received data.
        expected = bytes(range(256))
        command = "printf '" + ''.join('\\%03o' % n for n in expected) + "'"
        original_su, original_transport = self.c_su, self.transport
        transports = [self.transport]
        if self.transport != ['shell', '-T']:
            transports.append(['shell', '-T'])
        root_modes = [self.c_su]
        if self.has_su and not self.mtk_su:
            root_modes.append(not self.c_su)
        self.preflight_diagnostics = []
        unprivileged = False
        for c_su in root_modes:
            self.c_su = c_su
            if self.mtk_su:
                method = 'mtk-su'
            elif self.has_su:
                method = 'su -c' if c_su else 'piped su'
            else:
                method = 'adbd/sh'
            for transport in transports:
                label = ' '.join(transport) + ' / ' + method
                try:
                    observed = self.capture(command, transport, log_enabled=False)
                    if observed != expected:
                        if observed == expected.replace(b'\n', b'\r\n'):
                            reason = 'LF converted to CRLF'
                        elif expected in observed:
                            prefix = observed.index(expected)
                            reason = f'extra output: {prefix} bytes before, {len(observed) - prefix - 256} after payload'
                        else:
                            offset = next((i for i, pair in enumerate(zip(expected, observed))
                                           if pair[0] != pair[1]), min(len(expected), len(observed)))
                            reason = f'expected 256 bytes, received {len(observed)}; first mismatch at byte {offset}'
                        self.preflight_diagnostics.append(label + ': ' + reason)
                        continue
                    self.transport = transport
                    if self.capture('id -u', log_enabled=False).strip() != b'0':
                        unprivileged = True
                        self.preflight_diagnostics.append(label + ': binary check passed, but UID is not 0')
                        break
                    if self.preflight_diagnostics:
                        self.preflight_diagnostics.insert(0, 'ADB executable: ' + (shutil.which(self.adb[0]) or self.adb[0]))
                        self.preflight_diagnostics.append('Using verified transport: ' + label)
                    return
                except subprocess.TimeoutExpired:
                    self.preflight_diagnostics.append(label + ': command timed out')
                except OSError as error:
                    self.preflight_diagnostics.append(label + ': process error: ' + str(error.strerror or type(error).__name__))
                except RuntimeError as error:
                    detail = ' '.join(str(error).split())[:160]
                    self.preflight_diagnostics.append(label + ': command failed: ' + detail)
        self.c_su, self.transport = original_su, original_transport
        self.preflight_diagnostics.insert(0, 'ADB executable: ' + (shutil.which(self.adb[0]) or self.adb[0]))
        if unprivileged:
            raise RuntimeError('Filesystem acquisition requires verified root (UID 0); selected root methods did not grant root')
        raise RuntimeError('ADB/root transport is not binary-safe; see device log for transport/root diagnostics')


class Reader:
    def __init__(self, pipe, destination=None, progress=None):
        self.pipe, self.destination, self.progress = pipe, destination, progress
        self.total = 0
        self.last = time.monotonic()
        self.updated = 0
        self.tail = b''

    def read(self, size):
        data = self.pipe.read(size)
        if data:
            self.last = time.monotonic()
            self.total += len(data)
            self.tail = (self.tail + data)[-1024:]
            if self.destination:
                self.destination.write(data)
            if self.progress and self.last - self.updated >= 0.25:
                self.progress(self.total)
                self.updated = self.last
        return data


def zip_member(archive, member, source):
    name = member.name.lstrip('/')
    if not name or name == '.':
        return
    if '..' in name.split('/'):
        raise ValueError('Unsafe archive path: ' + member.name)
    name = posixpath.normpath(name)
    info = zipfile.ZipInfo(name.rstrip('/') + ('/' if member.isdir() else ''))
    info.create_system = 3
    dt = time.gmtime(max(315532800, min(member.mtime, 4354819198)))
    info.date_time = dt[:6]
    kind = stat.S_IFDIR if member.isdir() else stat.S_IFLNK if member.issym() else stat.S_IFREG
    info.external_attr = ((kind | member.mode) & 0xffff) << 16
    if member.isdir():
        info.external_attr |= 0x10
        archive.writestr(info, b'')
    elif member.issym():
        archive.writestr(info, member.linkname.encode('utf-8', 'surrogateescape'))
    elif member.islnk():
        # zipfile forbids concurrent reading and writing on one archive.
        with tempfile.TemporaryFile() as cached:
            with archive.open(posixpath.normpath(member.linkname.lstrip('/'))) as original:
                shutil.copyfileobj(original, cached, CHUNK)
            cached.seek(0)
            with archive.open(info, 'w', force_zip64=True) as target:
                shutil.copyfileobj(cached, target, CHUNK)
    elif member.isfile():
        info.file_size = member.size
        with archive.open(info, 'w', force_zip64=True) as target:
            shutil.copyfileobj(source.extractfile(member), target, CHUNK)


def tar_supports_long_names(stream, tar_command, token):
    """Probe GNU/PAX long-name support without logging binary check commands."""
    directory = token + '.probe'
    name = 'alex_' + 'x' * 120
    try:
        stream.capture('mkdir ' + directory + ' && : > ' + directory + '/' + name,
                       log_enabled=False)
        data = stream.capture(tar_command + ' -cf - -C ' + directory + ' ' + name +
                              ' 2>/dev/null | cat', log_enabled=False)
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as archive:
            members = archive.getmembers()
            return len(members) == 1 and members[0].name == name and members[0].size == 0
    except (OSError, RuntimeError, subprocess.TimeoutExpired, tarfile.TarError):
        return False
    finally:
        stream.capture('rm -f ' + directory + '/' + name + '; rmdir ' + directory +
                       ' 2>/dev/null || true', log_enabled=False)


def acquire(output, *, stream, root='/data', excludes=(), output_format='tar',
            progress=None, log=print, zip_backend='auto', on_file=None):
    """Publish only validated output; keep failed acquisitions as *.partial.

    ZIP stores Unix links plus metadata for links/special files in a sidecar.
    Diagnostics are forwarded to the supplied device logger.
    """
    if output_format not in ('tar', 'zip'):
        raise ValueError(output_format)
    output = os.fspath(output)
    partial = output + '.partial'
    token = '/data/local/tmp/alex_ffs_' + uuid.uuid4().hex
    status, errors = token + '.status', token + '.stderr'
    try:
        stream.preflight()
    finally:
        log_diagnostics(log, output, '\n'.join(getattr(stream, 'preflight_diagnostics', ())))
    native_tar = bool(stream.capture('command -v tar || true').strip())
    compatible_tar = (native_tar and zip_backend != 'script' and
                      tar_supports_long_names(stream, 'tar', token))
    if output_format == 'zip' and (zip_backend == 'script' or not compatible_tar):
        from .ffs_script import acquire_script
        if zip_backend != 'script':
            log(f'Filesystem acquisition [{output}]: native tar missing or unable to preserve long names; using script ZIP')
        return acquire_script(output, stream=stream, root=root, excludes=excludes, progress=progress, log=log, on_file=on_file)
    tar_command = 'tar'
    if not compatible_tar:
        log(f'Filesystem acquisition [{output}]: native tar missing or unable to preserve long names; using bundled tar')
        abi = stream.capture('getprop ro.product.cpu.abi').decode().strip()
        arch = 'aarch64' if abi == 'arm64-v8a' else 'armhf' if abi.startswith('armeabi') else None
        if arch is None:
            raise RuntimeError('No device tar or bundled tar for ABI ' + abi)
        binary = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'ressources', 'tar', arch, 'tar')
        tar_command = token + '.tar'
        with process(stream.adb + ['push', binary, tar_command], stdout=subprocess.PIPE, stderr=subprocess.PIPE) as push:
            try:
                push.communicate(timeout=30)
            except BaseException:
                push.kill()
                push.communicate()
                raise
            if push.returncode:
                raise RuntimeError('Could not upload bundled tar')
        stream.capture('chmod 700 ' + tar_command)
        if not tar_supports_long_names(stream, tar_command, token):
            stream.capture('rm -f ' + tar_command)
            raise RuntimeError('Bundled tar cannot create long-name archives on this device')
    # Relative archive paths work with Windows tools; never follow symlinks.
    # Keep ./ on archive members so absolute exclusions are anchored at root.
    # A plain --exclude=system would also prune /data/system on GNU/toybox tar.
    options = ' '.join('--exclude=' + shlex.quote('.' + x if x.startswith('/') else x)
                       for x in excludes)
    archive_root = './' + root.lstrip('/') if root.strip('/') else '.'
    command = tar_command + ' -cf - -C / ' + options + ' ' + shlex.quote(archive_root)
    # Some su implementations allocate a raw PTY even for exec-out. GNU tar
    # refuses a terminal stdout; an inner pipe gives every tar a real pipe.
    # Record tar's status before cat, rather than accepting the pipeline status.
    wrapped = ('(' + command + ' 2>' + errors + '; rc=$?; '
               'printf "%s\\n" "$rc" >' + status + ') | cat')
    proc = None
    done = threading.Event()
    timed_out = threading.Event()
    count = 0
    diagnostics_logged = False
    try:
        with tempfile.TemporaryFile() as local_errors, open(partial, 'w+b') as target, ExitStack() as resources:
            metadata = (resources.enter_context(open(output + '.metadata.jsonl.partial', 'w', encoding='utf-8'))
                        if output_format == 'zip' else None)
            proc = process(stream.adb + stream.transport + [stream.root(wrapped)],
                           stdout=subprocess.PIPE, stderr=local_errors,
                           stdin=subprocess.DEVNULL, bufsize=0)
            reader = Reader(proc.stdout, target if output_format == 'tar' else None, progress)

            def watchdog():
                while not done.wait(1):
                    if time.monotonic() - reader.last > stream.idle_timeout:
                        timed_out.set()
                        proc.kill()
                        return
            watcher = threading.Thread(target=watchdog, daemon=True)
            watcher.start()
            try:
                with zipfile.ZipFile(target, 'w', compression=zipfile.ZIP_STORED,
                                     allowZip64=True) if output_format == 'zip' else _null() as archive:
                    with tarfile.open(fileobj=reader, mode='r|', bufsize=CHUNK) as source:
                        for member in source:
                            count += 1
                            if on_file:
                                on_file(member.name)
                            if archive:
                                with warnings.catch_warnings(record=True) as notes:
                                    warnings.simplefilter('always', UserWarning)
                                    zip_member(archive, member, source)
                                for note in notes:
                                    local_errors.write(('ZIP warning: ' + str(note.message) + '\n').encode('utf-8'))
                                metadata.write(json.dumps(dict(path=member.name, link=member.linkname,
                                    type=member.type.decode('ascii'), mode=member.mode, size=member.size,
                                    uid=member.uid, gid=member.gid, mtime=member.mtime,
                                    pax_headers=member.pax_headers), ensure_ascii=True) + '\n')
                            source.members.clear()
                    # Drain through EOF, including tar padding, before checking process/status.
                    while reader.read(CHUNK):
                        pass
                    proc.wait(timeout=15)
                    if timed_out.is_set():
                        raise TimeoutError('Filesystem stream stalled')
                    if proc.returncode or not count or reader.total % 512 or reader.tail != bytes(1024):
                        raise RuntimeError('Incomplete or invalid TAR stream')
                    local_errors.seek(0)
                    adb_errors = local_errors.read().decode(errors='replace')
                    diagnostics = stream.capture('cat ' + errors).decode(errors='replace')
                    log_diagnostics(log, output, adb_errors + diagnostics)
                    diagnostics_logged = True
                    rc = stream.capture('cat ' + status).strip()
                    # GNU tar returns 1 for changed live files; retain and surface warnings.
                    if rc not in (b'0', b'1') or (rc == b'1' and not diagnostics):
                        raise RuntimeError('Remote tar failed: ' + rc.decode(errors='replace'))
            finally:
                done.set()
                if proc.poll() is None:
                    proc.kill()
                proc.wait()
                proc.stdout.close()
                watcher.join(timeout=2)
        if output_format == 'zip':
            os.replace(output + '.metadata.jsonl.partial', output + '.metadata.jsonl')
        os.replace(partial, output)
        return dict(members=count, bytes=reader.total, warnings=bool(diagnostics or adb_errors), backend='tar')
    except Exception as error:
        log(f"Filesystem acquisition [{output}] failed: {error}")
        if not diagnostics_logged:
            try:
                log_diagnostics(log, output, stream.capture(
                    '[ ! -f ' + errors + ' ] || cat ' + errors).decode(errors='replace'))
            except Exception:
                pass
        raise
    finally:
        done.set()
        try:
            stream.capture('rm -f ' + status + ' ' + errors + ' ' + token + '.tar')
        except Exception as error:
            log('Remote cleanup failed: ' + str(error))


class _null:
    def __enter__(self):
        return None

    def __exit__(self, *args):
        return False
