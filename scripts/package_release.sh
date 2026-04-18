#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   scripts/package_release.sh v1.0.0

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
  echo "Usage: $0 <version>"
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$ROOT_DIR/dist"
PKG_DIR="$OUT_DIR/websandbox-$VERSION"

rm -rf "$PKG_DIR"
mkdir -p "$PKG_DIR"

cp "$ROOT_DIR/docker-compose.yml" "$PKG_DIR/"
cp "$ROOT_DIR/.env.example" "$PKG_DIR/"
cp "$ROOT_DIR/Dockerfile" "$PKG_DIR/"
cp "$ROOT_DIR/requirements.txt" "$PKG_DIR/"
cp -R "$ROOT_DIR/app" "$PKG_DIR/"
mkdir -p "$PKG_DIR/scripts"
cp "$ROOT_DIR/scripts/init_minio.sh" "$PKG_DIR/scripts/"
mkdir -p "$PKG_DIR/release"
cp "$ROOT_DIR/release/DEPLOYMENT.md" "$PKG_DIR/release/"
cp "$ROOT_DIR/release/RELEASE_CHECKLIST.md" "$PKG_DIR/release/"

if [[ -f "$ROOT_DIR/README.md" ]]; then
  cp "$ROOT_DIR/README.md" "$PKG_DIR/"
fi

# Remove runtime/cache artifacts from release payload.
find "$PKG_DIR" -type d -name "__pycache__" -prune -exec rm -rf {} +
find "$PKG_DIR" -type f \( -name "*.pyc" -o -name "*.pyo" \) -delete

mkdir -p "$OUT_DIR"
TAR_FILE="$OUT_DIR/websandbox-$VERSION.tar.gz"
rm -f "$TAR_FILE"

tar -C "$OUT_DIR" -czf "$TAR_FILE" "websandbox-$VERSION"

echo "Release package created: $TAR_FILE"
