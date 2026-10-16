#!/usr/bin/env bash
# Build the connector bundle FortiSOAR installs:
# dist/fortinet-fortiaigate-<version>.tgz, unpacking to a single
# fortinet-fortiaigate/ directory.
#
# Prefers git-tracked files; before the first commit it falls back to the
# working tree minus tests, packaging furniture and caches.
set -euo pipefail

cd "$(dirname "$0")/.."
NAME=$(python3 -c "import json;print(json.load(open('info.json'))['name'])")
VERSION=$(python3 -c "import json;print(json.load(open('info.json'))['version'])")
OUT="dist/${NAME}-${VERSION}.tgz"

EXCLUDE='^(\.git/|\.gitignore$|dist/|scripts/|tests/|README\.md$|release_notes\.md$|__pycache__/|.*\.pyc$|\.DS_Store$)'

if git rev-parse --is-inside-work-tree >/dev/null 2>&1 && [ -n "$(git ls-files)" ]; then
    mapfile -t FILES < <(git ls-files | grep -Ev "$EXCLUDE")
else
    mapfile -t FILES < <(find . -type f \
        | sed 's|^\./||' \
        | grep -Ev "$EXCLUDE")
fi
if [ ${#FILES[@]} -eq 0 ]; then
    echo "package: no files matched" >&2
    exit 1
fi

for required in info.json connector.py operations.py requirements.txt; do
    printf '%s\n' "${FILES[@]}" | grep -qx "$required" \
        || { echo "package: $required missing from the bundle" >&2; exit 1; }
done

rm -rf dist && mkdir -p "dist/stage/${NAME}"
for f in "${FILES[@]}"; do
    mkdir -p "dist/stage/${NAME}/$(dirname "$f")"
    cp "$f" "dist/stage/${NAME}/$(dirname "$f")/"
done
tar czf "$OUT" -C dist/stage "${NAME}"
rm -rf dist/stage

echo "$OUT ($(printf '%s\n' "${FILES[@]}" | wc -l | tr -d ' ') files, $(du -h "$OUT" | cut -f1))"
