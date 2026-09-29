#!/bin/bash
# Every link to the published docs (https://m00qek.github.io/luci-sso/) names
# a version, and the right one:
#
#   files/, src/, mod/   the minor of PKG_VERSION in openwrt/luci-sso/Makefile,
#                        so a router links to the docs of the release it runs
#   CHANGELOG.md         the minor of the release section the link is in;
#                        latest under [Unreleased], whose minor has no docs
#                        yet. At release the section gets its number, and
#                        this check asks for the links to be pinned to it
#   anything else        any version, usually latest
#
# A link without a version still works, through the 404 page on gh-pages, but
# always lands on latest. Pages inside docs/ link to each other relatively.
#
# CI runs this via .github/workflows/lint.yml.

set -euo pipefail
cd "$(dirname "$0")/../.."

fail=0
# A <placeholder> segment, as in .../luci-sso/<X.Y>/, is part of the match.
url_re='https?://m00qek\.github\.io/luci-sso(/([^[:space:]"'\''<>)`]|<[^[:space:]>]*>)*)?'

pkg_version=$(sed -n 's/^PKG_VERSION:=//p' openwrt/luci-sso/Makefile)
[[ $pkg_version =~ ^([0-9]+)\.([0-9]+)\. ]] ||
    { echo "ERROR: no PKG_VERSION in openwrt/luci-sso/Makefile"; exit 1; }
pkg_minor=${BASH_REMATCH[1]}.${BASH_REMATCH[2]}

# The version a docs URL names: latest, X.Y, or nothing.
url_version() {
    local rest=${1#*m00qek.github.io/luci-sso}
    rest=${rest#/}
    rest=${rest%%/*}
    rest=${rest%%#*}
    if [[ $rest =~ ^(latest|[0-9]+\.[0-9]+)$ ]]; then
        echo "$rest"
    fi
}

# check FILE LINE URL WANT: WANT is a version, or "any".
check() {
    local file=$1 line=$2 url=$3 want=$4 got
    # A URL pattern that describes the site, not a link.
    [[ $url == *'<'* ]] && return
    got=$(url_version "$url")
    if [ -z "$got" ]; then
        echo "FAIL: $file:$line: $url has no version; use .../luci-sso/${want/any/latest}/..."
        fail=1
    elif [ "$want" != any ] && [ "$got" != "$want" ]; then
        echo "FAIL: $file:$line: $url links to $got; it must link to $want"
        fail=1
    fi
}

# The site itself, and files that must name the unversioned root.
skip='^(mkdocs\.yml|devenv/gh-pages/404\.html|devenv/scripts/check-docs-links\.sh)$'

while IFS=: read -r file line text; do
    [[ $file =~ $skip ]] && continue
    case $file in
        files/*|src/*|mod/*) want=$pkg_minor ;;
        CHANGELOG.md)        continue ;;
        *)                   want=any ;;
    esac
    while read -r url; do
        check "$file" "$line" "$url" "$want"
    done < <(grep -oE "$url_re" <<< "$text")
done < <(git grep -nE "$url_re" -- . || true)

# CHANGELOG.md: a link under "## [X.Y.Z]" names X.Y, one under
# "## [Unreleased]" names latest, and one under any other heading names some
# version.
want=any
line=0
while IFS= read -r text; do
    line=$((line + 1))
    if [[ $text =~ ^##\ \[([0-9]+)\.([0-9]+)\.[0-9]+\] ]]; then
        want=${BASH_REMATCH[1]}.${BASH_REMATCH[2]}
    elif [[ $text =~ ^##\ \[Unreleased\] ]]; then
        want=latest
    elif [[ $text =~ ^##\  ]]; then
        want=any
    fi
    while read -r url; do
        [ -n "$url" ] && check CHANGELOG.md "$line" "$url" "$want"
    done < <(grep -oE "$url_re" <<< "$text" || true)
done < CHANGELOG.md

if [ "$fail" -eq 0 ]; then
    echo "OK: every docs link names its version (shipped files: $pkg_minor)"
fi
exit "$fail"
