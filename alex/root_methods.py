"""Root method registry, independent of CustomTkinter.

Private forks may provide alex.root_methods_private.configure(methods, order).
"""
from dataclasses import dataclass
from importlib import import_module
from datetime import date
from typing import Callable


@dataclass(frozen=True)
class RootContext:
    software: str
    spl: str
    platform: str
    fingerprint: str
    model: str
    sku: str
    abi: str
    fastboot_available: bool

    @property
    def android_major(self):
        try:
            return int(self.software.split(".")[0])
        except (ValueError, AttributeError):
            return None

    def older_than(self, android, patch):
        # Missing/malformed versions must not advertise exploit compatibility.
        try:
            valid_patch = date.fromisoformat(self.spl)
        except (ValueError, TypeError):
            return False
        return (self.android_major is not None and self.android_major < android
                and valid_patch < date.fromisoformat(patch))


def initroot_device(context):
    try:
        if date.fromisoformat(context.spl) >= date(2017, 6, 1):
            return None
    except (ValueError, TypeError):
        return None
    if "google/shamu" in context.fingerprint:
        return "shamu"
    if "motorola" in context.fingerprint:
        models = {"XT1021": "condor", "XT1032": "falcon", "XT1033": "falcon",
                  "XT1040": "peregrine", "XT1068": "titan", "XT1069": "titan",
                  "XT1072": "thea", "XT1078": "thea", "XT1602": "harpia",
                  "XT1607": "harpia", "XT1622": "athene", "XT1676": "cedric"}
        return models.get(context.model.upper()) or models.get(context.sku.upper())
    return None


@dataclass(frozen=True)
class RootMethod:
    key: str
    compatible: Callable
    run: Callable  # (context, runtime) -> None; runtime.change receives 1 on success
    prompt: str
    progress: str
    failure: str
    success_flag: str


def run_initroot(context, runtime):
    # Resolve through the application's hook so fork-specific device mappings
    # used by the manual initroot flow also apply to automatic root checks.
    runtime.workers["initroot"](runtime.change, runtime.text, runtime.initroot_device())


def run_mtk(context, runtime):
    runtime.workers["mtk_su"](runtime.change)


def run_dirtycow(context, runtime):
    runtime.workers["dshell"](runtime.change)


ROOT_METHOD_ORDER = ["initroot", "mtk_su", "dirtycow"]

METHODS = {
    'initroot': RootMethod('initroot', lambda c: c.fastboot_available and bool(initroot_device(c)), run_initroot,
        'This device may be vulnerable to CVE-2016-10277 (initroot).\nFor temporary root access, a custom initramfs can be loaded via fastboot.\nThere is a risk of causing a bootloop.\n\nDo you want to continue?',
        'Attempt to gain temp-root via CVE-2016-10277 (initroot).\nPlease Wait ...',
        'Root access has not been gained.', 'initroot'),
    'mtk_su': RootMethod('mtk_su', lambda c: c.platform.upper().startswith(("MT67", "MT816", "MT817", "MT6580")) and c.older_than(10, "2020-03-01"), run_mtk,
        "This device may be vulnerable to CVE-2020-0069 (mtk-su).\nFor temporary root access, mtk-su can be copied to the device's\ntmp directory and executed.\n\nDo you want to continue?",
        'Attempt to gain temp-root via CVE-2020-0069 (mtk-su).\nPlease Wait ...',
        'Root access has not been gained.\nDue to the nature of this process, another attempt may be successful.', 'mtk_su'),
    'dirtycow': RootMethod('dirtycow', lambda c: c.older_than(7, "2016-11-06"), run_dirtycow,
        "This device may be vulnerable to CVE-2016-5195 (Dirty COW).\nFor temporary root access, an executable can be copied to the device's\ntmp directory and executed.\n\nDo you want to continue?",
        'Attempt to gain temp-root via CVE-2016-5195 (Dirty COW).\nPlease Wait ...',
        'Root access has not been gained.\nDue to the nature of this process, another attempt may be successful.', 'dshell'),
}


def load_methods():
    methods, order = dict(METHODS), list(ROOT_METHOD_ORDER)
    try:
        extension = import_module("alex.root_methods_private")
    except ModuleNotFoundError as exc:
        if exc.name != "alex.root_methods_private":
            raise
    else:
        extension.configure(methods, order)
    if len(order) != len(set(order)):
        raise ValueError("Duplicate root method in order")
    for key in order:
        if key not in methods or methods[key].key != key:
            raise ValueError(f"Invalid root method: {key}")
        if methods[key].success_flag not in {"su", "initroot", "mtk_su", "dshell"}:
            raise ValueError(f"Unsupported root access mode: {key}")
    return methods, order


def select_method(context, methods, order, skipped=()):
    return next((methods[key] for key in order
                 if key not in skipped and methods[key].compatible(context)), None)
