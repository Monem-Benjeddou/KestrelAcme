#!/usr/bin/env bash
# Builds Pebble (Let's Encrypt's ACME test server) into .pebble/ for the integration tests.
set -euo pipefail
VERSION="${PEBBLE_VERSION:-v2.10.1}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$ROOT/.pebble"

if [ -x "$DEST/bin/pebble" ] && [ "$(cat "$DEST/VERSION" 2>/dev/null)" = "$VERSION" ]; then
  echo "Pebble $VERSION already built in $DEST"
  exit 0
fi

rm -rf "$DEST"
git clone --quiet --depth 1 --branch "$VERSION" https://github.com/letsencrypt/pebble.git "$DEST/src"
(cd "$DEST/src" && go build -o "$DEST/bin/" ./cmd/pebble ./cmd/pebble-challtestsrv)
echo "$VERSION" > "$DEST/VERSION"
echo "Pebble $VERSION built in $DEST"
