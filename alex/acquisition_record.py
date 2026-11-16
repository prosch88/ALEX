#!/usr/bin/env python3
# ALEX - Android Logical Extractor
# Record of the device at the start and at the end of an acquisition:
# the clock of the device against the clock of the workstation, and the state of the radios and of the lock screen.
# Everything is read with "date", "getprop", "settings get" and "dumpsys". Nothing on the device is changed.

import json
import re
import time
from datetime import datetime, timezone

GLOBAL_SETTINGS = ["airplane_mode_on", "wifi_on", "mobile_data", "bluetooth_on", "adb_wifi_enabled", "auto_time", "auto_time_zone", "stay_on_while_plugged_in"]

STATE_SCRIPT = (
    "echo local=$(date '+%Y-%m-%dT%H:%M:%S%z'); "
    "echo timezone=$(getprop persist.sys.timezone); "
    "echo uptime=$(cut -d' ' -f1 /proc/uptime 2>/dev/null); "
    "for k in " + " ".join(GLOBAL_SETTINGS) + "; do echo setting.$k=$(settings get global $k 2>/dev/null); done; "
    "echo wakefulness=$(dumpsys power 2>/dev/null | grep -m1 -o 'mWakefulness=[A-Za-z]*' | cut -d= -f2); "
    "echo device_locked=$(dumpsys trust 2>/dev/null | grep -m1 -o 'deviceLocked=[01]' | cut -d= -f2); "
    "dumpsys battery 2>/dev/null | grep -E '^ +(level|status|AC powered|USB powered|Wireless powered):' | sed -E 's/^ +/battery./; s/: /=/'"
)

BATTERY_STATUS = {"1": "unknown", "2": "charging", "3": "discharging", "4": "not charging", "5": "full"}


def utc_text(timestamp):
    return datetime.fromtimestamp(timestamp, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def read_clock(shell, now=time.time):
    """Clock of the device against the clock of the workstation.

    The device is asked for its time in one short call. The workstation time is taken before and after the call.
    offset_seconds is the device time minus the middle of the two workstation times: positive means the device is ahead.
    The offset is known to plus or minus uncertainty_seconds (half the duration of the call, 0.5 s more if the device
    only gives whole seconds).
    """
    before = now()
    answer = shell("date +%s.%N").strip()
    after = now()
    clock = {"workstation_utc_before": utc_text(before), "workstation_utc_after": utc_text(after), "device_answer": answer}
    match = re.fullmatch(r"(\d+)(?:\.(\d{1,9}))?.*", answer)
    if not match:
        clock["error"] = "the device gave no time"
        return clock
    whole_seconds = match.group(2) is None                                      # an old "date" does not know %N
    device = int(match.group(1)) + (0.5 if whole_seconds else float("0." + match.group(2)))
    clock["device_utc"] = utc_text(device)
    clock["offset_seconds"] = round(device - (before + after) / 2, 3)
    clock["uncertainty_seconds"] = round((after - before) / 2 + (0.5 if whole_seconds else 0), 3)
    return clock


def parse_state(output):
    """key=value lines of STATE_SCRIPT -> dict. A value the device did not give is None."""
    values = {}
    for line in output.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            value = value.strip()
            values[key.strip()] = None if value in ("", "null") else value
    state = {
        "device_local_time": values.get("local"),
        "timezone": values.get("timezone"),
        "uptime_seconds": None,
        "settings": {key: values.get("setting." + key) for key in GLOBAL_SETTINGS},
        "wakefulness": values.get("wakefulness"),
        "device_locked": {"1": True, "0": False}.get(values.get("device_locked")),
        "battery": {
            "level": values.get("battery.level"),
            "status": BATTERY_STATUS.get(values.get("battery.status"), values.get("battery.status")),
            "ac_powered": values.get("battery.AC powered"),
            "usb_powered": values.get("battery.USB powered"),
            "wireless_powered": values.get("battery.Wireless powered"),
        },
    }
    try:
        state["uptime_seconds"] = float(values.get("uptime"))
    except (TypeError, ValueError):
        pass
    return state


def read_state(shell):
    return parse_state(shell(STATE_SCRIPT))


def snapshot(shell):
    """Clock and state of the device now. A part that cannot be read holds the error, the rest is still recorded."""
    shot = {}
    for name, reader in (("clock", read_clock), ("state", read_state)):
        try:
            shot[name] = reader(shell)
        except Exception as e:
            shot[name] = {"error": f"{type(e).__name__}: {e}"}
    boot = None
    try:
        boot = utc_text(time.time() + shot["clock"]["offset_seconds"] - shot["state"]["uptime_seconds"])
    except (KeyError, TypeError):
        pass
    shot["device_boot_utc"] = boot
    return shot


def on_off(value):
    return {"1": "on", "0": "off", None: "not given"}.get(value, str(value))


def summary(shot):
    """One line for the log."""
    clock, state = shot.get("clock", {}), shot.get("state", {})
    if "offset_seconds" in clock:
        offset = clock["offset_seconds"]
        text = (f"device clock {abs(offset):.3f} s {'ahead of' if offset >= 0 else 'behind'} the workstation "
                f"(+/- {clock['uncertainty_seconds']:.3f} s), device time {clock['device_utc']}")
    else:
        text = "device clock not read"
    settings = state.get("settings", {})
    if settings:
        locked = {True: "locked", False: "unlocked", None: "lock state not given"}[state.get("device_locked")]
        text += (f"; airplane mode {on_off(settings.get('airplane_mode_on'))}, Wi-Fi {on_off(settings.get('wifi_on'))}, "
                 f"mobile data {on_off(settings.get('mobile_data'))}, Bluetooth {on_off(settings.get('bluetooth_on'))}, "
                 f"{locked}, screen {state.get('wakefulness') or 'not given'}, battery {state.get('battery', {}).get('level') or '?'} %")
    return text


class AcquisitionRecord:
    """Snapshot at the start and at the end of an acquisition, written as JSON next to or into the backup."""

    def __init__(self, shell, log, what, serial=None, version=None):
        self.shell = shell
        self.log = log
        self.data = {"_comment": f"Device clock and state at the start and at the end of the acquisition, read over ADB by ALEX {version or ''}".strip(),
                     "acquisition": what, "serial": serial, "start": snapshot(shell), "end": None}
        log(f"{what}, start: {summary(self.data['start'])}")

    def finish(self):
        if self.data["end"] is None:
            self.data["end"] = snapshot(self.shell)
            try:
                self.data["clock_change_seconds"] = round(self.data["end"]["clock"]["offset_seconds"] - self.data["start"]["clock"]["offset_seconds"], 3)
            except (KeyError, TypeError):
                self.data["clock_change_seconds"] = None
            self.log(f"{self.data['acquisition']}, end: {summary(self.data['end'])}")
        return self.data

    def to_json(self):
        return json.dumps(self.finish(), ensure_ascii=False, indent=2)

    def write_into_zip(self, zip_path, name):
        """Add the record to a finished ZIP. Returns True if it was written."""
        import zipfile
        try:
            with zipfile.ZipFile(zip_path, "a", compression=zipfile.ZIP_STORED) as zf:
                zf.writestr(name, self.to_json())
            self.log(f"Acquisition record written to {name} in {zip_path}")
            return True
        except Exception as e:
            self.log(f"Acquisition record could not be written into {zip_path}: {type(e).__name__}: {e}")
            return False

    def write_file(self, path):
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.to_json())
            self.log(f"Acquisition record written to {path}")
            return True
        except Exception as e:
            self.log(f"Acquisition record could not be written to {path}: {type(e).__name__}: {e}")
            return False
