"""Tar-independent ZIP acquisition with NUL-framed base64 payloads.

Base64 costs 33% wire bandwidth but keeps framing intact when live files change
size, cannot be read, or contain arbitrary bytes. No file is buffered in RAM.
"""
import base64
import json
import os
import shlex
import stat
import subprocess
import tempfile
import threading
import time
import uuid
import zipfile
import warnings as pywarnings

from .ffs import CHUNK, Reader, process, log_diagnostics


def build_script(root, excludes):
    patterns = '|'.join(shlex.quote(x) + '|' + shlex.quote(x) + '/*'
                        for x in excludes if not x.startswith('*'))
    wildcard = '|'.join(x for x in excludes if x.startswith('*'))
    patterns = '|'.join(x for x in (patterns, wildcard) if x)
    exclusion = 'case "$f" in ' + patterns + ') return;; esac' if patterns else ':'
    return '''#!/system/bin/sh
if ! command -v base64 >/dev/null 2>&1; then
  base64() { toybox base64 "$@"; }
fi
if [ "$(printf x 2>/dev/null | head -c 1 2>/dev/null)" = x ]; then
  read_file() { head -c "$2" "$1"; }
else
  # Old Android toolbox head has no -c. Bound growth to one extra block.
  read_file() { dd if="$1" bs=65536 count=$((($2 + 65535) / 65536)) 2>/dev/null; }
fi
emit() {
  local f="$1" meta rc
  f="${f#//}"
  f="/${f#/}"
  ''' + exclusion + '''
  meta=$(stat -c '%s %Y %f %u %g %d %i' "$f") || return 1
  printf '%s\\000%s\\000' "$f" "$meta"
  if [ -L "$f" ]; then
    readlink -n "$f" | base64
    rc=$?
  elif [ -f "$f" ]; then
    read_file "$f" "${meta%% *}" | base64
    rc=$?
  else
    rc=0
  fi
  printf '\\000%s\\000' "$rc"
  if [ -d "$f" ] && [ ! -L "$f" ]; then
    for child in "$f"/* "$f"/.[!.]* "$f"/..?*; do
      [ -e "$child" ] || [ -L "$child" ] || continue
      emit "$child"
    done
  fi
}
printf 'ALEXFFS2\\000'
emit ''' + shlex.quote(root.rstrip('/') or '/') + '''
printf '\\000FINISHED\\000'
'''.replace('local f="$1" meta rc', 'local f="$1" meta rc child')


class Fields:
    def __init__(self, reader):
        self.reader = reader
        self.buffer = b''

    def chunks(self):
        while True:
            pos = self.buffer.find(b'\0')
            if pos >= 0:
                value, self.buffer = self.buffer[:pos], self.buffer[pos + 1:]
                yield value
                return
            if self.buffer:
                yield self.buffer
            self.buffer = self.reader.read(65536)
            if not self.buffer:
                raise EOFError('Truncated script stream')

    def field(self):
        result = bytearray()
        for block in self.chunks():
            result.extend(block)
            if len(result) > CHUNK:
                raise ValueError('Invalid script header')
        return bytes(result)


def acquire_script(output, *, stream, root, excludes, progress=None, log=print, on_file=None):
    if stream.capture('(command -v base64 >/dev/null 2>&1 || toybox base64 --help >/dev/null 2>&1) && command -v stat >/dev/null && command -v dd >/dev/null && printf OK', log_enabled=False).strip() != b'OK':
        raise RuntimeError('Script acquisition requires base64 (standalone or toybox), stat and dd on the device')
    token = '/data/local/tmp/alex_ffs_' + uuid.uuid4().hex
    script, errors = token + '.sh', token + '.stderr'
    done = threading.Event()
    stalled = threading.Event()
    proc = None
    count = 0
    warnings = False
    diagnostics_logged = False
    # / emits paths with // unless normalized here in the shell function.
    text = build_script(root, excludes)
    try:
        with tempfile.NamedTemporaryFile('w', encoding='utf-8', newline='\n', delete=False) as temp:
            temp.write(text)
            local = temp.name
        try:
            with process(stream.adb + ['push', local, script], stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE) as push:
                try:
                    push.communicate(timeout=30)
                except BaseException:
                    push.kill()
                    push.communicate()
                    raise
                if push.returncode:
                    raise RuntimeError('Could not upload filesystem script')
        finally:
            os.unlink(local)
        with tempfile.TemporaryFile() as err, open(output + '.metadata.jsonl.partial', 'w', encoding='utf-8') as meta:
            proc = process(stream.adb + stream.transport + [stream.root('sh ' + script + ' 2>' + errors)],
                           stdout=subprocess.PIPE, stderr=err, stdin=subprocess.DEVNULL, bufsize=0)
            reader = Reader(proc.stdout, progress=progress)
            fields = Fields(reader)

            def watchdog():
                while not done.wait(1):
                    if time.monotonic() - reader.last > stream.idle_timeout:
                        stalled.set()
                        proc.kill()
                        return
            watcher = threading.Thread(target=watchdog, daemon=True)
            watcher.start()
            try:
                if fields.field() != b'ALEXFFS2':
                    raise ValueError('Invalid script protocol')
                with zipfile.ZipFile(output + '.partial', 'w', allowZip64=True) as archive:
                    while True:
                        path = fields.field()
                        if not path:
                            if fields.field() != b'FINISHED':
                                raise ValueError('Missing script completion marker')
                            break
                        size, mtime, mode, uid, gid, dev, inode = fields.field().split()
                        size, mtime, mode = int(size), int(mtime), int(mode, 16)
                        name = path.decode('utf-8', 'surrogateescape').lstrip('/')
                        if not name:
                            name = '.'
                        if on_file:
                            on_file('/' + name)
                        if '..' in name.split('/'):
                            raise ValueError('Unsafe archive path')
                        is_dir = stat.S_ISDIR(mode)
                        supported = is_dir or stat.S_ISREG(mode) or stat.S_ISLNK(mode)
                        info = zipfile.ZipInfo(name + ('/' if is_dir else ''))
                        info.create_system = 3
                        info.external_attr = (mode & 0xffff) << 16 | (0x10 if is_dir else 0)
                        info.date_time = time.gmtime(max(315532800, min(mtime, 4354819198)))[:6]
                        written = 0
                        pending = b''
                        with pywarnings.catch_warnings(record=True) as notes:
                            pywarnings.simplefilter('always', UserWarning)
                            target = archive.open(info, 'w', force_zip64=True) if supported else None
                        for note in notes:
                            err.write(('ZIP warning: ' + str(note.message) + '\n').encode('utf-8'))
                        try:
                            for block in fields.chunks():
                                pending += b''.join(block.split())
                                length = len(pending) // 4 * 4
                                if length:
                                    decoded = base64.b64decode(pending[:length], validate=True)
                                    pending = pending[length:]
                                    if target:
                                        target.write(decoded)
                                    written += len(decoded)
                            if pending:
                                raise ValueError('Truncated base64 payload')
                        finally:
                            if target:
                                target.close()
                        rc = fields.field()
                        warning = rc != b'0' or (stat.S_ISREG(mode) and written != size)
                        warnings |= warning
                        meta.write(json.dumps(dict(path=name, size=size, acquired_size=written, mtime=mtime,
                                                   mode=mode, uid=int(uid), gid=int(gid), device=dev.decode('ascii', errors='replace'),
                                                   inode=int(inode), warning=warning), ensure_ascii=True) + '\n')
                        count += 1
                    while reader.read(CHUNK):
                        pass
                    proc.wait(timeout=15)
                    if stalled.is_set() or proc.returncode or not count:
                        raise RuntimeError('Script acquisition stalled or failed')
                diagnostics = stream.capture('cat ' + errors).decode(errors='replace')
                err.seek(0)
                diagnostics += err.read().decode(errors='replace')
                warnings |= bool(diagnostics)
                log_diagnostics(log, output, diagnostics)
                diagnostics_logged = True
                if warnings:
                    log(f'Filesystem acquisition [{output}]: Live-file/read warnings; see {output}.metadata.jsonl for per-file status.')
            finally:
                done.set()
                if proc.poll() is None:
                    proc.kill()
                proc.wait()
                proc.stdout.close()
                watcher.join(timeout=2)
        os.replace(output + '.metadata.jsonl.partial', output + '.metadata.jsonl')
        os.replace(output + '.partial', output)
        return dict(members=count, bytes=reader.total, warnings=warnings, backend='script')
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
            stream.capture('rm -f ' + script + ' ' + errors)
        except Exception as error:
            log('Remote cleanup failed: ' + str(error))
