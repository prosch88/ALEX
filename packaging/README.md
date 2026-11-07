# Packaging

ALEX tracks upstream `main`, so every distribution channel below is built
from the latest commit.

| Channel | How "latest" works |
|---|---|
| AUR `alex-git` | VCS package: `pkgver()` = `<a_version>.r<commit-count>.g<short-hash>`. Reinstall with `yay -Syu --devel` to get latest. |
| `.deb` / `.rpm` | Built from git (`packaging/build-*.sh`, also via GitHub Actions on every `main` push / `v*` tag). Version `<a_version>+r<count>.g<hash>` sorts as upgrade. |
| One-liner | `install.sh` clones once, `git pull --ff-only` on re-run / `--update`. |

## AUR (Arch / CachyOS / Manjaro)

The AUR package is `alex-git` (source: `packaging/aur/PKGBUILD`).

```bash
yay -S alex-git            # or: paru -S alex-git
yay -Syu --devel           # refresh -git packages to latest
```

To publish/update it on `aur.archlinux.org` (maintainer only):

```bash
git clone ssh://aur@aur.archlinux.org/alex-git.git
cp packaging/aur/PKGBUILD packaging/aur/.SRCINFO alex-git/
cd alex-git && makepkg --printsrcinfo > .SRCINFO && makepkg -sri
git add PKGBUILD .SRCINFO && git commit -m "upstream $(git -C /path/to/ALEX rev-parse --short HEAD)" && git push
```

`packaging/aur/.SRCINFO` in this repo must be regenerated whenever
`PKGBUILD` changes:

```bash
(cd packaging/aur && makepkg --printsrcinfo > .SRCINFO)
namcap packaging/aur/PKGBUILD
```

## .deb (Debian / Ubuntu / Kali)

```bash
sh packaging/build-deb.sh --out dist
sudo apt install ./dist/alex_*_all.deb
alex
```

Depends (`Depends:` in `packaging/deb/control`): `python3 (>= 3.11)`,
`python3-tk`, `adb | android-tools-adb`, `fastboot | android-tools-fastboot`.
Python deps from `requirements.txt` are vendored at build time into
`/usr/share/alex/lib` (relocatable `PYTHONPATH`, no venv path issues),
so the installed package works offline.

## .rpm (Fedora / RHEL / openSUSE)

```bash
sh packaging/build-rpm.sh --out dist
sudo dnf install ./dist/alex-*.noarch.rpm
alex
```

Spec: `packaging/rpm/alex.spec` (`Requires: python3, python3-tkinter,
android-tools`; same vendoring into `%{_datadir}/alex/lib`).

## One-liner install (any distro / macOS)

Always installs latest `main`:

```bash
curl -fsSL https://raw.githubusercontent.com/prosch88/ALEX/main/install.sh | bash
```

System-wide:

```bash
curl -fsSL https://raw.githubusercontent.com/prosch88/ALEX/main/install.sh | bash -s -- --system
```

Update later:

```bash
~/.local/share/alex/install.sh --update   # user install
# or re-run the curl pipe, or: alex-update equivalent
```

The script installs system deps via `apt`/`dnf`/`pacman`/`zypper`/`apk`/`brew`,
clones to `~/.local/share/alex` (or `/usr/share/alex` with `--system`),
creates `.venv`, pip-installs `requirements.txt`, and writes the `alex`
launcher + desktop entry.
