#!/bin/sh
# Build a self-contained .deb from the current git checkout.
# Usage: packaging/build-deb.sh [--out dist]
# Result: dist/alex_<version>_all.deb
# Versioning: <a_version>+r<commit-count>.g<short-hash>, e.g. 0.7+r12.g7342aed,
# so every rebuild from a newer commit sorts as an upgrade ("latest every time").
set -eu
cd "$(dirname "$0")/.."

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  echo "Usage: packaging/build-deb.sh [--out dist]"
  exit 0
fi
OUT_DIR="${1:-dist}"
if [ "${1:-}" = "--out" ]; then OUT_DIR="${2:-dist}"; fi
case "$OUT_DIR" in
  /*) ;; # absolute, keep as-is
  *) OUT_DIR="$PWD/$OUT_DIR" ;;
esac
mkdir -p "$OUT_DIR"

VER_BASE=$(grep -Po '^a_version\s*=\s*\K[0-9][0-9.]*' alex.py | head -n1)
[ -n "$VER_BASE" ] || VER_BASE="0.7"
COUNT=$(git rev-list --count HEAD 2>/dev/null || echo 0)
HASH=$(git rev-parse --short HEAD 2>/dev/null || echo nogit)
VERSION="${VER_BASE}+r${COUNT}.g${HASH}"

STAGE="$OUT_DIR/deb-stage/alex_${VERSION}_all"
rm -rf "$STAGE"
mkdir -p "$STAGE/DEBIAN" "$STAGE/usr/share/alex" "$STAGE/usr/bin" \
         "$STAGE/usr/share/applications" "$STAGE/usr/share/pixmaps" \
         "$STAGE/usr/share/doc/alex"

sed "s/^Version:.*/Version: $VERSION/" packaging/deb/control > "$STAGE/DEBIAN/control"
cp packaging/deb/postinst packaging/deb/prerm "$STAGE/DEBIAN/"
chmod 755 "$STAGE/DEBIAN/postinst" "$STAGE/DEBIAN/prerm"

install -m644 alex.py "$STAGE/usr/share/alex/"
cp -a alex "$STAGE/usr/share/alex/"
cp -a ressources "$STAGE/usr/share/alex/"
cp -a assets "$STAGE/usr/share/alex/"
rm -rf "$STAGE/usr/share/alex/assets/__pycache__" "$STAGE/usr/share/alex/alex/__pycache__" 2>/dev/null || true

echo "==> vendoring requirements.txt into usr/share/alex/lib"
python3 -m pip install --no-compile --target="$STAGE/usr/share/alex/lib" -r requirements.txt
find "$STAGE/usr/share/alex/lib" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
rm -rf "$STAGE/usr/share/alex/lib/bin" 2>/dev/null || true
chmod 755 "$STAGE/usr/share/alex/ressources/cve/2016-5195/"*/dirtycow \
  "$STAGE/usr/share/alex/ressources/cve/2016-5195/"*/run-as \
  "$STAGE/usr/share/alex/ressources/cve/2020-0069/"*/mtk-su \
  "$STAGE/usr/share/alex/ressources/tar/"*/* 2>/dev/null || true

install -m755 packaging/alex "$STAGE/usr/bin/alex"
install -m644 packaging/alex.desktop "$STAGE/usr/share/applications/alex.desktop"
install -m644 assets/alex.png "$STAGE/usr/share/pixmaps/alex.png"
install -m644 README.md "$STAGE/usr/share/doc/alex/README.md"
install -m644 LICENSE "$STAGE/usr/share/doc/alex/copyright"
cat > "$STAGE/usr/share/doc/alex/changelog" <<EOF
alex ($VERSION) unstable; urgency=medium

  * Automated build from git ${HASH} (commit ${COUNT}).

 -- ALEX packaging <https://github.com/prosch88/ALEX>  $(date -R)
EOF
gzip -9n "$STAGE/usr/share/doc/alex/changelog"

find "$STAGE" -type d -exec chmod 755 {} +
find "$STAGE/usr" -type f -exec chmod 644 {} +
chmod 755 "$STAGE/usr/bin/alex" "$STAGE/DEBIAN/postinst" "$STAGE/DEBIAN/prerm"
chmod 755 "$STAGE/usr/share/alex/ressources/cve/2016-5195/"*/dirtycow \
  "$STAGE/usr/share/alex/ressources/cve/2016-5195/"*/run-as \
  "$STAGE/usr/share/alex/ressources/cve/2020-0069/"*/mtk-su \
  "$STAGE/usr/share/alex/ressources/tar/"*/* 2>/dev/null || true

dpkg-deb --root-owner-group --build "$STAGE" "$OUT_DIR/alex_${VERSION}_all.deb"
echo "Built $OUT_DIR/alex_${VERSION}_all.deb"
dpkg-deb -f "$OUT_DIR/alex_${VERSION}_all.deb" Package Version Architecture Depends
