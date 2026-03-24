#!/usr/bin/env python3

import subprocess
import sys
import re
import numpy as np
from PIL import Image

#subprocess helper
def run(cmd, **kwargs):
    if sys.platform == "win32":
        kwargs.setdefault("creationflags", subprocess.CREATE_NO_WINDOW)

    return subprocess.run(cmd, **kwargs)

def Popen(cmd, **kwargs):
    if sys.platform == "win32":
        kwargs.setdefault("creationflags", subprocess.CREATE_NO_WINDOW)

    return subprocess.Popen(cmd, **kwargs)

def adb_shell(cmd):
    result = run(['adb', 'shell'] + cmd, capture_output=True, text=True)
    return result.stdout.strip()

def adb_shell_raw(cmd):
    result = run(
        ['adb', 'shell'] + cmd,
        capture_output=True
    )
    return result.stdout

def adb_exec_out(cmd):
    result = run(['adb', 'exec-out'] + cmd, capture_output=True)
    return result.stdout

def shot():
    virtual = adb_shell(['cat', '/sys/class/graphics/fb0/virtual_size'])
    vwidth, vheight = map(int, virtual.split(','))

    mode_line = adb_shell(['cat', '/sys/class/graphics/fb0/modes']).splitlines()[0]
    match = re.search(r'(\d+)x(\d+)', mode_line)
    if not match:
        sys.exit(1)
    pwidth, pheight = map(int, match.groups())

    xoffset = (vwidth - pwidth) // 2
    yoffset = 0

    bpp = int(adb_shell(['cat', '/sys/class/graphics/fb0/bits_per_pixel']))
    bytes_per_pixel = bpp // 8

    fb_data = adb_exec_out(['cat', '/dev/fb0'])

    arr = np.frombuffer(fb_data, dtype=np.uint8).reshape((vheight, vwidth, bytes_per_pixel))

    if bytes_per_pixel == 4:
        fbset = adb_shell(['fbset'])
        if "rgba" in fbset.lower():
            order = [0, 1, 2, 3]
        elif "argb" in fbset.lower():
            order = [1, 2, 3, 0]
        elif "bgra" in fbset.lower():
            order = [2, 1, 0, 3]
        elif "abgr" in fbset.lower():
            order = [3, 2, 1, 0]
        else:
            order = [0, 1, 2, 3]
        arr = arr[..., order]
    elif bytes_per_pixel == 3:
        arr = arr[..., :3]

    cropped = arr[yoffset:yoffset+pheight, xoffset:xoffset+pwidth]

    mode = 'RGBA' if bytes_per_pixel == 4 else 'RGB'
    img = Image.fromarray(cropped, mode=mode)
    return img

def shot_alt():
    fbset = adb_shell(['fbset'])
    mode_match = re.search(r'mode\s+"(\d+)x(\d+)-\d+"', fbset)
    if not mode_match:
        raise ValueError("Mode not found")
    width = int(mode_match.group(1))
    height = int(mode_match.group(2))
    if "rgba" in fbset:
        order = [0, 1, 2, 3]
    elif "argb" in fbset:
        order = [1, 2, 3, 0]
    elif "bgra" in fbset:
        order = [2, 1, 0, 3]
    elif "abgr" in fbset:
        order = [3, 2, 1, 0]
    elif "rgbx" in fbset:
        order = [0, 1, 2] + 255
    else:
        order = [0, 1, 2, 3]
    user = adb_shell(['whoami'])
    u_id =  adb_shell([f"id -u {user}"])
    data =  adb_shell_raw([f"mirscreencast -n 1 -m /var/run/user/{u_id}/mir_socket_trusted --stdout"])
    expected = width * height * 4
    if len(data) < expected:
        raise ValueError(f"RAW data too small")
    arr = np.frombuffer(data[:expected], dtype=np.uint8).reshape((height, width, 4))
    img = Image.fromarray(arr[:, :, order], "RGBA")
    return img
