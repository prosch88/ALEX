Name:           alex
Version:        0.7
Release:        1.git%{gitcount}.g%{githash}%{?dist}
Summary:        Android Logical Extractor (ALEX)
License:        GPL-3.0-or-later
URL:            https://github.com/prosch88/ALEX
Source0:        %{name}-%{version}.tar.gz
BuildArch:      noarch
BuildRequires:  git
BuildRequires:  python3-pip
Requires:       python3
Requires:       python3-tkinter
Requires:       android-tools
Recommends:     usbutils
# Bundled content includes ELF files that are NOT host executables:
# ARM exploit payloads under ressources/ (run on the device) and
# vendored PyPI wheels under %%{_datadir}/alex/lib. Keep this package
# noarch and downgrade the arch-dependent-binaries check to a warning.
%define _binaries_in_noarch_packages_terminate_build 0
# Vendored PyPI deps under %{_datadir}/alex/lib contain x86_64 .so files
# (numpy/scipy/Pillow) and ARM exploit binaries under ressources/.
# They are private to the app: no auto Provides/Requires, no stripping.
AutoReqProv:    no
%define __provides_exclude_from ^%{_datadir}/alex/lib/.*$
%define __requires_exclude_from ^%{_datadir}/alex/lib/.*$
%define __os_install_post %{nil}

%description
ADB-based logical/advanced-logical/filesystem acquisition tool for
Android, FireOS, WearOS and Ubuntu Touch devices.
Python dependencies from requirements.txt are vendored under
%%{_datadir}/alex/lib, so the package works offline after install.

%prep
%autosetup -n %{name}-%{version} -p1 2>/dev/null || true
# rpmbuild -bb with a git checkout (see packaging/build-rpm.sh) copies the
# tree into the build dir; tolerate both tarball and directory sources.
if [ ! -f alex.py ]; then
  if [ -d "%{_topdir}/SOURCES/%{name}-%{version}" ]; then
    cp -a "%{_topdir}/SOURCES/%{name}-%{version}/"* .
  fi
fi

%build
# nothing to compile (pure Python + vendored wheels installed below)

%install
rm -rf %{buildroot}
install -d %{buildroot}%{_datadir}/alex
install -m644 alex.py %{buildroot}%{_datadir}/alex/
cp -a alex %{buildroot}%{_datadir}/alex/
cp -a ressources %{buildroot}%{_datadir}/alex/
cp -a assets %{buildroot}%{_datadir}/alex/
rm -rf %{buildroot}%{_datadir}/alex/assets/__pycache__ \
       %{buildroot}%{_datadir}/alex/alex/__pycache__ 2>/dev/null || true

python3 -m pip install --no-compile \
  --target="%{buildroot}%{_datadir}/alex/lib" -r requirements.txt
find %{buildroot}%{_datadir}/alex/lib -name '__pycache__' -type d \
  -prune -exec rm -rf {} + 2>/dev/null || true
rm -rf %{buildroot}%{_datadir}/alex/lib/bin 2>/dev/null || true
# keep bundled device binaries executable
chmod 755 %{buildroot}%{_datadir}/alex/ressources/cve/2016-5195/*/dirtycow \
  %{buildroot}%{_datadir}/alex/ressources/cve/2016-5195/*/run-as \
  %{buildroot}%{_datadir}/alex/ressources/cve/2020-0069/*/mtk-su \
  %{buildroot}%{_datadir}/alex/ressources/tar/*/* 2>/dev/null || true

install -Dm755 packaging/alex %{buildroot}%{_bindir}/alex
install -Dm644 packaging/alex.desktop %{buildroot}%{_datadir}/applications/alex.desktop
install -Dm644 assets/alex.png %{buildroot}%{_datadir}/pixmaps/alex.png
install -Dm644 LICENSE %{buildroot}%{_datadir}/licenses/%{name}/LICENSE

%files
%{_bindir}/alex
%{_datadir}/alex/
%{_datadir}/applications/alex.desktop
%{_datadir}/pixmaps/alex.png
%{_datadir}/licenses/%{name}/LICENSE

%changelog
* Thu Nov 05 2026 ALEX packaging <https://github.com/prosch88/ALEX> - 0.7-1
- Package ALEX with vendored Python dependencies.
