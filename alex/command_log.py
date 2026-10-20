"""Command logging, enabled only after ALEX's output directory is selected."""

import os
import shlex
import subprocess
import sys


_logger = None


def set_logger(logger):
    global _logger
    _logger = logger


def format_command(command):
    if isinstance(command, str):
        return command
    args = [str(arg) for arg in command]
    if sys.platform == "win32":
        return subprocess.list2cmdline(args)
    return " ".join(shlex.quote(arg) for arg in args)


def log_command(command, stdout=None, context="command"):
    if _logger is None:
        return
    text = format_command(command)
    output_path = getattr(stdout, "name", None)
    if isinstance(output_path, (str, os.PathLike)):
        text += " > " + format_command([output_path])
    _logger("{}: {}".format(context, text))


def log_process(command, **kwargs):
    if _logger is None:
        return
    if isinstance(command, str):
        executable = command.lstrip().split(" ", 1)[0].strip('"')
    else:
        executable = str(command[0]) if command else ""
    if os.path.basename(executable).lower() in ("adb", "adb.exe", "fastboot", "fastboot.exe"):
        log_command(command, stdout=kwargs.get("stdout"))


def adb_call(method, *args, **kwargs):
    """Log the terminal equivalent while preserving the adbutils call itself."""
    if _logger is not None:
        name = method.__name__
        owner = method.__self__
        command = ["adb"]
        serial = getattr(owner, "serial", None) or getattr(owner, "_serial", None)
        if serial:
            command += ["-s", serial]
        context = "command"
        if name == "shell":
            remote = args[0] if args else kwargs["cmdargs"]
            if not isinstance(remote, str):
                remote = " ".join(shlex.quote(str(arg)) for arg in remote)
            command += ["shell", remote]
        elif name in ("pull", "pull_file"):
            command += ["pull", args[0], args[1]]
        elif name == "list":
            command += ["devices"]
            if kwargs.get("extended"):
                command += ["-l"]
        elif name == "server_kill":
            command += ["kill-server"]
        elif name == "forward":
            command += ["forward"] + list(args)
        elif name == "uninstall":
            command += ["uninstall"] + list(args)
        else:
            # These helpers use ADB services or may issue several shell commands.
            context = "command (adbutils equivalent)"
            if name == "screenshot":
                command += ["shell", "screencap -p"]
            elif name == "swipe":
                command += ["shell", "input swipe {} {} {} {} {}".format(
                    args[0], args[1], args[2], args[3], int(args[4] * 1000))]
            elif name == "app_info":
                command += ["shell", "dumpsys package " + shlex.quote(args[0])]
            elif name == "iter_directory":
                command += ["shell", "ls -la " + shlex.quote(str(args[0]))]
            elif name == "stat":
                command += ["shell", "stat " + shlex.quote(str(args[0]))]
            else:
                raise ValueError("Unsupported ADB logging method: " + name)
        log_command(command, context=context)
    return method(*args, **kwargs)
