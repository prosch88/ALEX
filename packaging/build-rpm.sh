#!/bin/sh
# Build a self-contained .rpm from the current git checkout (no fpm needed).
# Usage: packaging/build-rpm.sh [--out dist]
# Result: dist/rpmbuild/RPMS/noarch/alex-0.7-*.noarch.rpm (+ copied to dist/)
set -eu
cd "$(dirname "$0")/.."

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  echo "Usage: packaging/build-rpm.sh [--out dist]"
  exit 0
fi
OUT_DIR="dist"
if [ "${1:-}" = "--out" ]; then OUT_DIR="${2:-dist}"; fi
case "$OUT_DIR" in
  /*) ;; # absolute, keep as-is
  *) OUT_DIR="$PWD/$OUT_DIR" ;;
esac
mkdir -p "$OUT_DIR"

COUNT=$(git rev-list --count HEAD 2>/dev/null || echo 0)
HASH=$(git rev-parse --short HEAD 2>/dev/null || echo nogit)
TOPDIR="$OUT_DIR/rpmbuild"
rm -rf "$TOPDIR"
mkdir -p "$TOPDIR"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

# Stage a versioned source tree for rpmbuild
SRCSTAGE="$TOPDIR/SOURCES/alex-0.7"
mkdir -p "$SRCSTAGE"
git archive HEAD alex.py alex packaging ressources assets README.md LICENSE requirements.txt pyproject.toml 2>/dev/null \
  | tar -x -C "$SRCSTAGE" || {
    # fallback for environments without git archive support of pathspec
    cp -a alex.py alex packaging ressources assets README.md LICENSE requirements.txt pyproject.toml "$SRCSTAGE/"
  }
tar -czf "$TOPDIR/SOURCES/alex-0.7.tar.gz" -C "$TOPDIR/SOURCES" alex-0.7
cp packaging/rpm/alex.spec "$TOPDIR/SPECS/"

rpmbuild --define "_topdir $TOPDIR" \
  --define "gitcount $COUNT" --define "githash $HASH" \
  -bb "$TOPDIR/SPECS/alex.spec"

find "$TOPDIR/RPMS" -name '*.rpm' -exec cp -v {} "$OUT_DIR/" \;
echo "RPM(s) in $OUT_DIR:"
ls -la "$OUT_DIR"/*.rpm
