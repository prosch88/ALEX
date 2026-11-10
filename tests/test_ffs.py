import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from alex import ffs
from alex.ffs_script import Fields, build_script
from alex import ffs_script


class LocalStream:
    adb = ['adb']
    transport = ['exec-out']
    idle_timeout = 2

    def __init__(self, folder):
        self.folder = folder

    def translate(self, command):
        return command.replace('/data/local/tmp/', self.folder + '/')

    def preflight(self):
        pass

    def root(self, command):
        return self.translate(command)

    def capture(self, command, **kwargs):
        return subprocess.check_output(['sh', '-c', self.translate(command)])


class FFSTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.source = self.folder / 'source'
        self.source.mkdir()
        self.payload = bytes(range(256)) * 8192
        (self.source / 'a file\nwith newline').write_bytes(self.payload)
        (self.source / '.hidden').write_bytes(b'hidden')
        os.link(self.source / '.hidden', self.source / 'hardlink')
        (self.source / 'symlink').symlink_to('.hidden')
        self.stream = LocalStream(self.temp.name)
        self.real_popen = subprocess.Popen

    def run_local(self, argv, **kwargs):
        return self.real_popen(['sh', '-c', argv[-1]], **kwargs)

    def test_tar_and_zip_preserve_binary_hidden_files_and_links(self):
        for fmt in ['tar', 'zip']:
            with self.subTest(format=fmt), patch.object(ffs, 'process', self.run_local):
                output = self.folder / ('out.' + fmt)
                result = ffs.acquire(output, stream=self.stream, root=str(self.source), output_format=fmt)
                self.assertGreater(result['members'], 3)
                if fmt == 'tar':
                    with tarfile.open(output) as archive:
                        name = next(n for n in archive.getnames() if n.endswith('with newline'))
                        self.assertEqual(archive.extractfile(name).read(), self.payload)
                else:
                    with zipfile.ZipFile(output) as archive:
                        self.assertIsNone(archive.testzip())
                        name = next(n for n in archive.namelist() if n.endswith('with newline'))
                        self.assertEqual(archive.read(name), self.payload)
                        self.assertEqual(archive.read(str(self.source / 'hardlink').lstrip('/')), b'hidden')
                        self.assertEqual(archive.read(str(self.source / 'symlink').lstrip('/')), b'.hidden')
                self.assertFalse(Path(str(output) + '.partial').exists())

    def test_duplicate_tar_entries_are_retained_and_only_logged(self):
        import shlex
        import warnings
        fixture = self.folder / 'duplicates.tar'
        with tarfile.open(fixture, 'w') as archive:
            for payload in [b'first', b'second']:
                member = tarfile.TarInfo('data/repeated')
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
        def duplicate_process(argv, **kwargs):
            command = argv[-1]
            start = command.index('tar -cf')
            end = command.index(' 2>', start)
            command = command[:start] + 'cat ' + shlex.quote(str(fixture)) + command[end:]
            return self.real_popen(['sh', '-c', command], **kwargs)
        output = self.folder / 'duplicates.zip'
        entries = []
        with patch.object(ffs, 'process', duplicate_process), warnings.catch_warnings(record=True) as visible:
            warnings.simplefilter('always')
            result = ffs.acquire(output, stream=self.stream, output_format='zip', log=entries.append)
        self.assertEqual(visible, [])
        self.assertTrue(result['warnings'])
        with zipfile.ZipFile(output) as archive:
            self.assertEqual([archive.read(info) for info in archive.infolist()], [b'first', b'second'])
        self.assertTrue(any('Duplicate name' in entry for entry in entries))
        self.assertFalse(list(self.folder.glob('*.log')))

    def test_absolute_exclusions_do_not_prune_same_basename_elsewhere(self):
        nested = self.source / 'data' / 'cache'
        nested.mkdir(parents=True)
        (nested / 'included').write_bytes(b'keep nested cache')
        excluded = self.source / 'cache'
        excluded.mkdir()
        (excluded / 'removed').write_bytes(b'exclude only this cache')
        output = self.folder / 'exclude.zip'
        with patch.object(ffs, 'process', self.run_local):
            ffs.acquire(output, stream=self.stream, root=str(self.source),
                        excludes=(str(excluded),), output_format='zip')
        with zipfile.ZipFile(output) as archive:
            self.assertIn(str(nested / 'included').lstrip('/'), archive.namelist())
            self.assertNotIn(str(excluded / 'removed').lstrip('/'), archive.namelist())

    @unittest.skipUnless(os.name == 'posix', 'PTY regression test requires POSIX')
    def test_tar_works_when_root_shell_allocates_a_terminal(self):
        import errno
        import pty
        import tty
        class TerminalReader:
            def __init__(self, fd):
                self.pipe = os.fdopen(fd, 'rb', buffering=0)
            def read(self, size):
                try:
                    return self.pipe.read(size)
                except OSError as error:
                    if error.errno == errno.EIO:
                        return b''
                    raise
            def close(self):
                self.pipe.close()
        def terminal_process(argv, **kwargs):
            master, slave = pty.openpty()
            tty.setraw(slave)
            proc = self.real_popen(['sh', '-c', argv[-1]], stdout=slave,
                                   stderr=kwargs['stderr'], stdin=subprocess.DEVNULL)
            os.close(slave)
            proc.stdout = TerminalReader(master)
            return proc
        output = self.folder / 'terminal.tar'
        with patch.object(ffs, 'process', terminal_process):
            ffs.acquire(output, stream=self.stream, root=str(self.source))
        with tarfile.open(output) as archive:
            name = next(n for n in archive.getnames() if n.endswith('with newline'))
            self.assertEqual(archive.extractfile(name).read(), self.payload)

    def test_failed_transfer_never_publishes_archive(self):
        for command in ["printf garbage", "sleep 5"]:
            def failing(argv, **kwargs):
                return self.real_popen(['sh', '-c', 'exec ' + command], **kwargs)
            output = self.folder / 'failure.tar'
            with patch.object(ffs, 'process', failing), self.assertRaises((tarfile.TarError, RuntimeError, TimeoutError)):
                ffs.acquire(output, stream=self.stream, root=str(self.source))
            self.assertFalse(output.exists())
            self.assertTrue(Path(str(output) + '.partial').exists())
            self.assertFalse(list(self.folder.glob('*.log')))

    def test_script_protocol_handles_binary_and_hidden_files(self):
        # The script needs no tar: execute it directly with host shell tools.
        script = build_script(str(self.source), ())
        result = subprocess.run(['sh', '-c', script], capture_output=True, check=True)
        fields = Fields(ffs.Reader(io.BytesIO(result.stdout)))
        self.assertEqual(fields.field(), b'ALEXFFS2')
        import base64
        payloads = {}
        while True:
            path = fields.field()
            if not path:
                self.assertEqual(fields.field(), b'FINISHED')
                break
            metadata = fields.field()
            payloads[path.decode()] = base64.b64decode(b''.join(fields.chunks()))
            self.assertEqual(fields.field(), b'0')
        self.assertEqual(payloads[str(self.source / 'a file\nwith newline')], self.payload)
        self.assertEqual(payloads[str(self.source / '.hidden')], b'hidden')

    def test_zip_falls_back_to_script_without_tar(self):
        original_capture = self.stream.capture
        def capture(command, **kwargs):
            if command == 'command -v tar || true':
                return b''
            return original_capture(command)
        self.stream.capture = capture
        def local_process(argv, **kwargs):
            if 'push' in argv:
                return self.real_popen(['cp', argv[-2], self.stream.translate(argv[-1])], **kwargs)
            return self.run_local(argv, **kwargs)
        output = self.folder / 'script.zip'
        with patch.object(ffs_script, 'process', local_process):
            result = ffs.acquire(output, stream=self.stream, root=str(self.source), output_format='zip')
        self.assertEqual(result['backend'], 'script')
        with zipfile.ZipFile(output) as archive:
            self.assertIsNone(archive.testzip())
            name = next(n for n in archive.namelist() if n.endswith('with newline'))
            self.assertEqual(archive.read(name), self.payload)
            self.assertEqual(archive.read(str(self.source / 'symlink').lstrip('/')), b'.hidden')
        self.assertTrue(Path(str(output) + '.metadata.jsonl').exists())

    def test_script_handles_file_shrinking_after_stat(self):
        original_build = build_script
        def shrinking_script(root, excludes):
            text = original_build(root, excludes)
            # The file changes after its metadata was emitted, before reading it.
            return text.replace('  elif [ -f "$f" ]; then',
                                '  elif [ -f "$f" ]; then\n    case "$f" in *newline) : > "$f";; esac')
        def local_process(argv, **kwargs):
            if 'push' in argv:
                return self.real_popen(['cp', argv[-2], self.stream.translate(argv[-1])], **kwargs)
            return self.run_local(argv, **kwargs)
        output = self.folder / 'shrunk.zip'
        entries = []
        with patch.object(ffs_script, 'process', local_process), patch.object(ffs_script, 'build_script', shrinking_script):
            result = ffs.acquire(output, stream=self.stream, root=str(self.source),
                                 output_format='zip', zip_backend='script', log=entries.append)
        self.assertTrue(result['warnings'])
        with zipfile.ZipFile(output) as archive:
            self.assertIsNone(archive.testzip())
            name = next(n for n in archive.namelist() if n.endswith('with newline'))
            self.assertEqual(archive.read(name), b'')
            self.assertEqual(archive.read(str(self.source / '.hidden').lstrip('/')), b'hidden')
        self.assertTrue(any('warnings' in entry for entry in entries))
        self.assertFalse(list(self.folder.glob('*.log')))

    def test_script_supports_legacy_head_without_c(self):
        script = build_script(str(self.source), ())
        script = script.replace('#!/system/bin/sh', '#!/system/bin/sh\nhead() { return 1; }', 1)
        result = subprocess.run(['sh', '-c', script], capture_output=True, check=True)
        fields = Fields(ffs.Reader(io.BytesIO(result.stdout)))
        self.assertEqual(fields.field(), b'ALEXFFS2')
        import base64
        payloads = {}
        while True:
            path = fields.field()
            if not path:
                self.assertEqual(fields.field(), b'FINISHED')
                break
            fields.field()
            payloads[path.decode()] = base64.b64decode(b''.join(fields.chunks()))
            self.assertEqual(fields.field(), b'0')
        self.assertEqual(payloads[str(self.source / 'a file\nwith newline')], self.payload)

    def test_long_name_probe_rejects_truncated_names_and_cleans_up(self):
        from unittest.mock import Mock
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode='w') as archive:
            archive.addfile(tarfile.TarInfo('alex_' + 'x' * 95))
        stream = Mock()
        stream.capture.side_effect = [b'', data.getvalue(), b'']
        self.assertFalse(ffs.tar_supports_long_names(stream, 'tar', '/data/local/tmp/test'))
        self.assertEqual(stream.capture.call_count, 3)
        self.assertIn('rmdir', stream.capture.call_args.args[0])
        self.assertTrue(all(call.kwargs['log_enabled'] is False for call in stream.capture.call_args_list))

    def test_zip_uses_script_when_native_tar_cannot_preserve_long_names(self):
        def local_process(argv, **kwargs):
            if 'push' in argv:
                return self.real_popen(['cp', argv[-2], self.stream.translate(argv[-1])], **kwargs)
            return self.run_local(argv, **kwargs)
        output = self.folder / 'legacy_tar.zip'
        long_file = self.source / ('x' * 125)
        long_file.write_bytes(b'long name preserved')
        with patch.object(ffs, 'tar_supports_long_names', return_value=False), patch.object(ffs_script, 'process', local_process):
            result = ffs.acquire(output, stream=self.stream, root=str(self.source), output_format='zip', log=lambda message: None)
        self.assertEqual(result['backend'], 'script')
        with zipfile.ZipFile(output) as archive:
            self.assertEqual(archive.read(str(long_file).lstrip('/')), b'long name preserved')

    def test_script_uses_toybox_base64_when_standalone_command_is_missing(self):
        import shutil
        import shlex
        import base64
        script = build_script(str(self.source), ())
        script = script.replace('if ! command -v base64 >/dev/null 2>&1; then', 'if true; then', 1)
        toybox = 'toybox() { shift; ' + shlex.quote(shutil.which('base64')) + ' "$@"; }'
        script = script.replace('#!/system/bin/sh', '#!/system/bin/sh\n' + toybox, 1)
        result = subprocess.run(['sh', '-c', script], capture_output=True, check=True)
        fields = Fields(ffs.Reader(io.BytesIO(result.stdout)))
        self.assertEqual(fields.field(), b'ALEXFFS2')
        payloads = {}
        while True:
            path = fields.field()
            if not path:
                self.assertEqual(fields.field(), b'FINISHED')
                break
            fields.field()
            payloads[path.decode()] = base64.b64decode(b''.join(fields.chunks()))
            self.assertEqual(fields.field(), b'0')
        self.assertEqual(payloads[str(self.source / 'a file\nwith newline')], self.payload)

    def test_script_preserves_legacy_hex_device_identifier(self):
        import shutil
        import shlex
        import json
        original_build = build_script
        def legacy_script(root, excludes):
            stat_path = shlex.quote(shutil.which('stat'))
            function = ('stat() { values=$(' + stat_path + ' "$@") || return 1; '
                        'set -- $values; printf "%s %s %s %s %s 100d %s\\n" '
                        '"$1" "$2" "$3" "$4" "$5" "$7"; }')
            return original_build(root, excludes).replace('#!/system/bin/sh', '#!/system/bin/sh\n' + function, 1)
        def local_process(argv, **kwargs):
            if 'push' in argv:
                return self.real_popen(['cp', argv[-2], self.stream.translate(argv[-1])], **kwargs)
            return self.run_local(argv, **kwargs)
        output = self.folder / 'legacy_stat.zip'
        with patch.object(ffs_script, 'build_script', legacy_script), patch.object(ffs_script, 'process', local_process):
            ffs.acquire(output, stream=self.stream, root=str(self.source), output_format='zip', zip_backend='script')
        records = [json.loads(line) for line in Path(str(output) + '.metadata.jsonl').read_text().splitlines()]
        self.assertTrue(all(record['device'] == '100d' for record in records))
        with zipfile.ZipFile(output) as archive:
            self.assertIsNone(archive.testzip())

    def test_truncated_script_protocol_fails(self):
        fields = Fields(ffs.Reader(io.BytesIO(b'header\0unterminated')))
        self.assertEqual(fields.field(), b'header')
        with self.assertRaises(EOFError):
            fields.field()

    def test_reopening_root_menu_retains_confirmed_mtk_method(self):
        import ast
        from unittest.mock import Mock
        path = Path(__file__).resolve().parents[1] / 'alex.py'
        tree = ast.parse(path.read_text())
        app_class = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'MyApp')
        method = next(n for n in app_class.body if isinstance(n, ast.FunctionDef) and n.name == 'show_check_root')
        namespace = dict(ctk=Mock(), show_root=True, mtk_su=True, fb_found='not found', dir_top='/tmp')
        exec(compile(ast.Module(body=[method], type_ignores=[]), str(path), 'exec'), namespace)
        app = Mock()
        namespace['show_check_root'](app)
        self.assertTrue(namespace['mtk_su'])
        app.after.assert_called_once()

    def test_mtk_su_wraps_compound_command_in_shell_and_has_priority(self):
        import shlex
        stream = ffs.DeviceStream(mtk_su=True, has_su=True)
        command = "id; printf '%s' root | cat"
        self.assertEqual(shlex.split(stream.root(command)),
                         ['/data/local/tmp/mtk-su', '-c', 'sh', '-c', command])

    def test_preflight_rejects_binary_safe_but_unprivileged_shell(self):
        stream = ffs.DeviceStream(has_su=False)
        with patch.object(stream, 'capture', side_effect=[bytes(range(256)), b'2000\n']):
            with self.assertRaisesRegex(RuntimeError, 'UID 0'):
                stream.preflight()

    def test_preflight_commands_are_executed_without_logging(self):
        from unittest.mock import MagicMock
        processes = []
        for output in [bytes(range(256)), b'0\n', b'0\n']:
            proc = MagicMock()
            proc.__enter__.return_value = proc
            proc.communicate.return_value = (output, b'')
            proc.returncode = 0
            processes.append(proc)
        stream = ffs.DeviceStream()
        with patch.object(ffs.subprocess, 'Popen', side_effect=processes) as popen, patch.object(ffs, 'log_process') as logger:
            stream.preflight()
            logger.assert_not_called()
            self.assertEqual(popen.call_count, 2)
            stream.capture('id -u')
            logger.assert_called_once()
            self.assertEqual(popen.call_count, 3)
            self.assertTrue(all('log_enabled' not in call.kwargs for call in popen.call_args_list))

    def test_preflight_selects_verified_shell_fallback(self):
        stream = ffs.DeviceStream()
        with patch.object(stream, 'capture', side_effect=[b'root banner', bytes(range(256)), b'0\n']):
            stream.preflight()
        self.assertEqual(stream.transport, ['shell', '-T'])

    def test_preflight_rejects_crlf_translation(self):
        stream = ffs.DeviceStream()
        with patch.object(stream, 'capture', return_value=bytes(range(256)).replace(b'\n', b'\r\n')):
            with self.assertRaisesRegex(RuntimeError, 'binary-safe'):
                stream.preflight()


if __name__ == '__main__':
    unittest.main()
