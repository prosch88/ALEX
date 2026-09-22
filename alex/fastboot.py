from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


@dataclass
class FastbootResult:
    """Result of a fastboot command."""

    returncode: int
    stdout: str
    stderr: str

    @property
    def success(self) -> bool:
        return self.returncode == 0

    @property
    def output(self) -> str:
        """
        Combined textual output.

        fastboot frequently writes getvar output to stderr, so stdout and
        stderr are combined here for convenient consumption.
        """
        if self.stdout and self.stderr:
            return self.stdout + self.stderr

        return self.stdout or self.stderr

    def __bool__(self) -> bool:
        return self.success


class Fastboot:
    """
    Wrapper around the system fastboot executable.

    The executable is automatically located through PATH unless an explicit
    path is supplied.

    Parameters
    ----------
    executable:
        Optional explicit path to the fastboot executable.
    """

    def __init__(self, executable: str | Path | None = None):
        if executable is None:
            self.executable = shutil.which("fastboot")
        else:
            self.executable = str(executable)

    # ------------------------------------------------------------------
    # Availability
    # ------------------------------------------------------------------

    @property
    def available(self) -> bool:
        """
        True if a fastboot executable is available.

        This only checks whether fastboot can be found/executed.
        It does NOT mean that a device is connected.
        """
        if not self.executable:
            return False

        try:
            result = subprocess.run(
                [self.executable, "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
            )

            return result.returncode == 0

        except (
            OSError,
            subprocess.SubprocessError,
        ):
            return False

    @property
    def path(self) -> str | None:
        """Return the path of the fastboot executable."""
        return self.executable

    # ------------------------------------------------------------------
    # Device detection
    # ------------------------------------------------------------------

    def devices(self) -> list[str]:
        """
        Return serial numbers of currently connected fastboot devices.

        Returns an empty list if no device is connected or fastboot is
        unavailable.
        """
        if not self.available:
            return []

        result = self.run("devices")

        if not result.success:
            return []

        devices = []

        for line in result.stdout.splitlines():
            line = line.strip()

            if not line:
                continue

            # Typical output:
            #
            # ABC123456789    fastboot
            #
            parts = line.split()

            if parts:
                devices.append(parts[0])

        return devices

    def is_device_connected(self) -> bool:
        """Return True if at least one fastboot device is connected."""
        return bool(self.devices())

    # ------------------------------------------------------------------
    # Command execution
    # ------------------------------------------------------------------

    def run(
        self,
        *args: str | Path,
        timeout: float | None = 30,
    ) -> FastbootResult:
        """
        Execute an arbitrary fastboot command.

        Example:

            fb.run("reboot")
            fb.run("erase", "userdata")
            fb.run("flash", "boot", "/tmp/boot.img")

        Parameters
        ----------
        args:
            Arguments passed to fastboot.

        timeout:
            Timeout in seconds. None disables the timeout.

        Returns
        -------
        FastbootResult
        """
        if not self.available:
            raise RuntimeError(
                "fastboot executable not found or not executable"
            )

        command = [
            self.executable,
            *(str(arg) for arg in args),
        ]

        try:
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
            )

        except subprocess.TimeoutExpired as exc:
            raise TimeoutError(
                f"fastboot command timed out after {timeout}s: "
                f"{' '.join(command)}"
            ) from exc

        except OSError as exc:
            raise RuntimeError(
                f"Unable to execute fastboot: {exc}"
            ) from exc

        return FastbootResult(
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
        )

    # ------------------------------------------------------------------
    # Common fastboot commands
    # ------------------------------------------------------------------

    def getvar(
        self,
        variable: str,
        timeout: float | None = 10,
    ) -> FastbootResult:
        """
        Read a fastboot variable.

        Example:

            result = fb.getvar("product")
            print(result.output)
        """
        return self.run(
            "getvar",
            variable,
            timeout=timeout,
        )

    def flash(
        self,
        partition: str,
        image: str | Path,
        timeout: float | None = 300,
    ) -> FastbootResult:
        """
        Flash an image to a partition.

        Example:

            fb.flash("boot", "/tmp/boot.img")
        """
        image = Path(image)

        if not image.is_file():
            raise FileNotFoundError(
                f"Image file does not exist: {image}"
            )

        return self.run(
            "flash",
            partition,
            image,
            timeout=timeout,
        )

    def erase(
        self,
        partition: str,
        timeout: float | None = 30,
    ) -> FastbootResult:
        """Erase a partition."""
        return self.run(
            "erase",
            partition,
            timeout=timeout,
        )

    def reboot(
        self,
        target: str | None = None,
        timeout: float | None = 30,
    ) -> FastbootResult:
        """
        Reboot the device.

        Examples:

            fb.reboot()
            fb.reboot("bootloader")
            fb.reboot("recovery")
        """
        args = ["reboot"]

        if target:
            args.append(target)

        return self.run(
            *args,
            timeout=timeout,
        )

    def boot(
        self,
        image: str | Path,
        timeout: float | None = 300,
    ) -> FastbootResult:
        """Boot an image without flashing it."""
        image = Path(image)

        if not image.is_file():
            raise FileNotFoundError(
                f"Image file does not exist: {image}"
            )

        return self.run(
            "boot",
            image,
            timeout=timeout,
        )

    def continue_boot(
        self,
        timeout: float | None = 30,
    ) -> FastbootResult:
        """Continue normal boot."""
        return self.run(
            "continue",
            timeout=timeout,
        )

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    def version(self) -> str | None:
        """Return the installed fastboot version."""
        if not self.available:
            return None

        result = self.run("--version")

        if not result.success:
            return None

        return result.output.strip()