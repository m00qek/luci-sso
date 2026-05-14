#!/bin/bash
# Bidirectional constraint: every cookie name used in any source file must be
# documented in some doc file, and vice versa.
#
# Source anchor:  __Host-* or sysauth* string literals in files/**/*.uc
# Doc anchor:     ### `name` headings inside any ## Cookies section in docs/reference/**/*.md
#
# CI runs this via .github/workflows/lint.yml.

set -euo pipefail
cd "$(dirname "$0")/../.."

fail=0

# Extract cookie names from all .uc source files
src_cookies=$(
    find files/ -name '*.uc' -exec grep -hoE '(__Host-[a-zA-Z0-9_-]+|sysauth(_https)?)' {} + \
    | sort -u
)

# Extract documented cookie names from ## Cookies sections in reference docs only.
# Scoping to docs/reference/ prevents how-to guide examples from being mistaken
# for real constraint declarations.
doc_cookies=$(
    find docs/reference/ -name '*.md' -exec sed -n '/^## Cookies$/,/^---$/p' {} \; \
    | grep -oP '^### `\K[^`]+(?=`)' \
    | sort -u
)

[ -z "$src_cookies" ] && { echo "ERROR: no cookie names found under files/"; exit 1; }
[ -z "$doc_cookies" ] && { echo "ERROR: no cookie headings found in any ## Cookies section under docs/"; exit 1; }

while IFS= read -r name; do
    [ -z "$name" ] && continue
    if ! echo "$doc_cookies" | grep -qxF "$name"; then
        echo "FAIL: cookie '$name' used in source but not documented in any ## Cookies section"
        fail=1
    fi
done <<< "$src_cookies"

while IFS= read -r name; do
    [ -z "$name" ] && continue
    if ! echo "$src_cookies" | grep -qxF "$name"; then
        echo "FAIL: cookie '$name' documented in docs but not used in source"
        fail=1
    fi
done <<< "$doc_cookies"

[ "$fail" -ne 0 ] && {
    printf '\nKeep cookie name strings in source and ### `name` headings in ## Cookies sections in docs in sync.\n'
    exit 1
}
echo "OK: cookie names — files/**/*.uc ↔ docs/**/*.md"
