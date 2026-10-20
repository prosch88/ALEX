import ast
import io
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from alex import command_log
from alex.fastboot import Fastboot
from alex.dirty_shell import DirtyShell


ROOT = Path(__file__).resolve().parents[1]


def load_functions(path, names, namespace):
    tree = ast.parse(path.read_text())
    nodes = [node for node in tree.body
             if isinstance(node, ast.FunctionDef) and node.name in names]
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), 'exec'), namespace)
    return namespace


class Device:
    serial = 'test-device'

    def __init__(self):
        self.calls = []
        self.result = object()

    def shell(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return self.result

    def pull_file(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return self.result

    def screenshot(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return self.result


class CommandLogTests(unittest.TestCase):
    def setUp(self):
        self.entries = []
        command_log.set_logger(self.entries.append)
        self.addCleanup(command_log.set_logger, None)

    def test_disabled_logging_still_executes_once(self):
        command_log.set_logger(None)
        device = Device()
        self.assertIs(command_log.adb_call(device.shell, 'id', timeout=4), device.result)
        command_log.log_process(['adb', 'devices'])
        command_log.log_command(['fastboot', 'devices'])
        self.assertEqual(device.calls, [(('id',), {'timeout': 4})])
        self.assertEqual(self.entries, [])

    def test_shell_preserves_arguments_result_and_order(self):
        device = Device()
        def logger(entry):
            self.assertEqual(device.calls, [])
            self.entries.append(entry)
        command_log.set_logger(logger)
        remote = "find '/sdcard/a b' | head -n 1"
        with patch.object(command_log.sys, 'platform', 'linux'):
            result = command_log.adb_call(device.shell, remote, stream=True, timeout=5)
        self.assertIs(result, device.result)
        self.assertEqual(device.calls, [((remote,), {'stream': True, 'timeout': 5})])
        with patch.object(command_log.sys, 'platform', 'linux'):
            self.assertEqual(shlex.split(self.entries[0].split(': ', 1)[1]),
                             ['adb', '-s', 'test-device', 'shell', remote])

    def test_failed_command_is_logged_and_exception_propagates(self):
        class FailingDevice:
            def shell(self, command):
                raise OSError('disconnected')
        with self.assertRaisesRegex(OSError, 'disconnected'):
            command_log.adb_call(FailingDevice().shell, 'id')
        self.assertEqual(len(self.entries), 1)
        self.assertIn('shell id', self.entries[0])

    def test_pull_paths_are_quoted(self):
        device = Device()
        with patch.object(command_log.sys, 'platform', 'linux'):
            result = command_log.adb_call(device.pull_file, '/sdcard/a b', Path('out a.txt'))
            args = shlex.split(self.entries[0].split(': ', 1)[1])
        self.assertIs(result, device.result)
        self.assertEqual(args, ['adb', '-s', 'test-device', 'pull', '/sdcard/a b', 'out a.txt'])

    def test_screenshot_is_marked_as_equivalent(self):
        device = Device()
        self.assertIs(command_log.adb_call(device.screenshot, error_ok=False), device.result)
        self.assertIn('adbutils equivalent', self.entries[0])
        self.assertEqual(device.calls, [((), {'error_ok': False})])

    def test_process_filter_and_file_redirection(self):
        with patch.object(command_log.sys, 'platform', 'linux'):
            command_log.log_process(['tar', '-cf', 'archive.tar'])
            self.assertEqual(self.entries, [])
            command_log.log_process(['/tools/adb', 'exec-out', 'cat /dev/block/test'],
                                    stdout=type('Output', (), {'name': 'out file.bin'})())
            self.assertEqual(shlex.split(self.entries[0].split(': ', 1)[1]),
                             ['/tools/adb', 'exec-out', 'cat /dev/block/test', '>', 'out file.bin'])

    def test_windows_argument_format(self):
        args = ['adb', 'pull', '/sdcard/a b', 'C:\\Output Files\\file.txt']
        with patch.object(command_log.sys, 'platform', 'win32'):
            self.assertEqual(command_log.format_command(args), subprocess.list2cmdline(args))

    def test_subprocess_helpers_log_once_and_pass_through(self):
        for relative in ['alex.py', 'alex/devdump.py', 'alex/shot_ut.py',
                         'alex/exploits.py', 'alex/wifi_adb.py', 'alex/dirty_shell.py']:
            with self.subTest(module=relative):
                fake = Mock()
                namespace = load_functions(ROOT / relative, {'run', 'Popen', '_run', '_Popen'},
                                           dict(subprocess=fake, sys=sys, log_process=command_log.log_process))
                for name, function in list(namespace.items()):
                    if name not in ('run', 'Popen', '_run', '_Popen'):
                        continue
                    self.entries.clear()
                    command = ['adb', 'shell', 'echo test']
                    result = function(command, stdout=subprocess.PIPE)
                    target = fake.Popen if name.endswith('Popen') else fake.run
                    self.assertIs(result, target.return_value)
                    self.assertEqual(target.call_args.args, (command,))
                    self.assertEqual(target.call_args.kwargs['stdout'], subprocess.PIPE)
                    self.assertEqual(len(self.entries), 1)

    def test_fastboot_logs_before_execution_without_device_access(self):
        result = subprocess.CompletedProcess([], 0, 'test', '')
        with patch('alex.fastboot.subprocess.run', return_value=result) as run:
            fb = Fastboot('/tools/fastboot')
            fb.run('getvar', 'product')
        self.assertEqual(run.call_count, 2)
        self.assertEqual(len(self.entries), 2)
        self.assertIn('--version', self.entries[0])
        self.assertIn('getvar product', self.entries[1])

    def test_interactive_shell_logs_written_commands(self):
        shell = DirtyShell(['shell', 'sh'])
        shell._proc = Mock(stdin=io.BytesIO())
        shell._write(b'echo test\n')
        self.assertEqual(shell._proc.stdin.getvalue(), b'echo test\n')
        self.assertIn('inside active ADB shell', self.entries[0])
        self.assertTrue(self.entries[0].endswith('echo test'))

    def test_log_file_is_created_only_after_cwd_selection(self):
        from datetime import datetime
        namespace = load_functions(ROOT / 'alex.py', {'log'},
                                   dict(cwd_selected=False, snr='test', datetime=datetime))
        with tempfile.TemporaryDirectory() as directory:
            old_cwd = os.getcwd()
            try:
                os.chdir(directory)
                namespace['log']('before')
                self.assertEqual(list(Path(directory).iterdir()), [])
                namespace['cwd_selected'] = True
                namespace['log']('after')
                content = Path('ALEX_log_test.log').read_text()
                self.assertIn('after', content)
                self.assertNotIn('before', content)
            finally:
                os.chdir(old_cwd)

    def test_no_unlogged_direct_adbutils_calls_remain(self):
        names = {'shell', 'pull', 'pull_file', 'iter_directory', 'stat', 'screenshot',
                 'app_info', 'swipe', 'uninstall', 'forward', 'list', 'server_kill'}
        for path in [ROOT / 'alex.py', ROOT / 'alex/exploits.py']:
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                    continue
                receiver = ast.unparse(node.func.value)
                if receiver in {'device', 'device.sync', 'adb', 'self'} and node.func.attr in names:
                    self.fail('{}:{}: unlogged {}'.format(path.name, node.lineno, node.func.attr))

    def test_cwd_selection_enables_logging_before_menu(self):
        tree = ast.parse((ROOT / 'alex.py').read_text())
        app = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'MyApp')
        choose = next(node for node in app.body if isinstance(node, ast.FunctionDef) and node.name == 'choose_cwd')
        logger = Mock()
        namespace = dict(os=os, cwd_selected=False, set_logger=command_log.set_logger, log=logger)
        exec(compile(ast.Module(body=[choose], type_ignores=[]), 'alex.py', 'exec'), namespace)
        command_log.set_logger(None)
        menu = Mock()
        menu.show_main_menu.side_effect = lambda: command_log.log_process(['adb', 'devices'])
        with tempfile.TemporaryDirectory() as directory:
            old_cwd = os.getcwd()
            try:
                namespace['choose_cwd'](menu, Mock(get=Mock(return_value=directory)))
                self.assertTrue(namespace['cwd_selected'])
                self.assertEqual(os.getcwd(), os.path.realpath(directory))
                logger.assert_called_once_with('command: adb devices')
            finally:
                os.chdir(old_cwd)


if __name__ == '__main__':
    unittest.main()
