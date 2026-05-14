#!/bin/bash
# Bidirectional constraint: every LIMIT_* constant in any source file must be
# declared as metadata in some doc file, and vice versa, with matching values.
#
# Source anchor:  const LIMIT_NAME = VALUE   anywhere under files/**/*.uc
# Doc anchor:     <!-- LIMIT_NAME=VALUE -->   anywhere under docs/reference/**/*.md
#
# CI runs this via .github/workflows/lint.yml.

set -euo pipefail
cd "$(dirname "$0")/../.."

fail=0

# Extract LIMIT_NAME=VALUE pairs from all .uc source files (const declarations only)
code_limits=$(
    find files/ -name '*.uc' -exec grep -hoP 'LIMIT_[A-Z_]+\s*=\s*[0-9]+' {} + \
    | sed 's/[[:space:]]//g' \
    | sort -u
)

# Extract LIMIT_NAME=VALUE pairs from metadata comments in reference docs only.
# Scoping to docs/reference/ prevents how-to guide examples from being mistaken
# for real constraint declarations.
doc_limits=$(
    find docs/reference/ -name '*.md' -exec grep -hoP '<!-- \KLIMIT_[A-Z_]+=\d+(?= -->)' {} + \
    | sort -u
)

[ -z "$code_limits" ] && { echo "ERROR: no LIMIT_* constants found under files/"; exit 1; }
[ -z "$doc_limits" ]  && { echo "ERROR: no LIMIT_* metadata comments found under docs/"; exit 1; }

while IFS= read -r entry; do
    [ -z "$entry" ] && continue
    if ! echo "$doc_limits" | grep -qxF "$entry"; then
        name="${entry%%=*}" value="${entry##*=}"
        echo "FAIL: ${name}=${value} defined in source but has no <!-- ${name}=${value} --> comment in any doc"
        fail=1
    fi
done <<< "$code_limits"

while IFS= read -r entry; do
    [ -z "$entry" ] && continue
    if ! echo "$code_limits" | grep -qxF "$entry"; then
        name="${entry%%=*}" value="${entry##*=}"
        echo "FAIL: <!-- ${name}=${value} --> in docs has no matching constant in source"
        fail=1
    fi
done <<< "$doc_limits"

[ "$fail" -ne 0 ] && {
    printf '\nKeep LIMIT_* constants in source and <!-- LIMIT_*=VALUE --> comments in docs in sync.\n'
    exit 1
}
echo "OK: request limits — files/**/*.uc ↔ docs/**/*.md"
