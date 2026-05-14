#!/bin/bash
# Bidirectional constraint: every code exported from errors.uc must be
# documented in log-messages.md, and vice versa.
#
# CI runs this via .github/workflows/lint.yml.

set -euo pipefail
cd "$(dirname "$0")/../.."

ERRORS_UC="files/usr/share/ucode/luci_sso/errors.uc"
LOG_MESSAGES="docs/reference/log-messages.md"

fail=0

# Extract exported constant names: lines like "export const FOO = ..."
code_codes=$(grep -oP 'export const \K[A-Z_]+' "$ERRORS_UC" | sort)

# Extract documented codes: table rows where the first cell is a backtick-quoted
# SCREAMING_SNAKE_CASE identifier, e.g.  | `SOME_ERROR` | description...
doc_codes=$(grep -oP '^[|] `\K[A-Z][A-Z_]+(?=`)' "$LOG_MESSAGES" | sort -u)

[ -z "$code_codes" ] && { echo "ERROR: no exported constants found in $ERRORS_UC"; exit 1; }
[ -z "$doc_codes" ]  && { echo "ERROR: no documented codes found in $LOG_MESSAGES"; exit 1; }

while IFS= read -r code; do
    [ -z "$code" ] && continue
    if ! echo "$doc_codes" | grep -qxF "$code"; then
        echo "FAIL: '$code' exported from $ERRORS_UC but not documented in $LOG_MESSAGES"
        fail=1
    fi
done <<< "$code_codes"

while IFS= read -r code; do
    [ -z "$code" ] && continue
    if ! echo "$code_codes" | grep -qxF "$code"; then
        echo "FAIL: '$code' documented in $LOG_MESSAGES but not exported from $ERRORS_UC"
        fail=1
    fi
done <<< "$doc_codes"

[ "$fail" -ne 0 ] && {
    printf '\nKeep %s and %s in sync.\n' "$ERRORS_UC" "$LOG_MESSAGES"
    exit 1
}
echo "OK: error codes — $ERRORS_UC ↔ $LOG_MESSAGES"
