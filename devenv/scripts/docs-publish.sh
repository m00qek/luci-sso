#!/bin/bash
# Publish one release's documentation to the gh-pages branch with mike.
#
# Usage: devenv/scripts/docs-publish.sh [--push] vX.Y.Z
#
# The docs of tag vX.Y.Z become version X.Y, titled X.Y.Z, so a patch release
# replaces its minor. The latest alias moves to X.Y only when no newer minor is
# published: a fix to an older minor does not take latest away.
#
# Without --push, mike commits to the local gh-pages branch only; review it
# with `mike serve -F mkdocs.mike.yml` and push it yourself. The docs workflow
# (.github/workflows/docs.yml) runs this with --push for every release tag.
#
# Needs mkdocs-material and mike on PATH, at the versions the workflow pins.

set -euo pipefail

die() { echo "docs-publish: $*" >&2; exit 1; }

push=()
if [ "${1:-}" = --push ]; then
    push=(--push)
    shift
fi
tag=${1:-}
[[ $tag =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] ||
    die "usage: docs-publish.sh [--push] vX.Y.Z (got '$tag')"
release=${tag#v}
version=${BASH_REMATCH[1]}.${BASH_REMATCH[2]}

command -v mike >/dev/null || die "mike is not on PATH"
root=$(git rev-parse --show-toplevel)
cd "$root"

git rev-parse -q --verify "refs/tags/$tag^{commit}" >/dev/null ||
    die "tag $tag does not exist"
pkg_version=$(git show "$tag:openwrt/luci-sso/Makefile" | sed -n 's/^PKG_VERSION:=//p')
[ "$pkg_version" = "$release" ] ||
    die "$tag has PKG_VERSION $pkg_version, not $release"

# Build from a checkout of the tag, not from the working tree. A worktree
# shares the local gh-pages branch, which is where mike commits.
work="$root/bin/docs-publish/$tag"
cleanup() { git -C "$root" worktree remove --force "$work" 2>/dev/null || true; }
trap cleanup EXIT
cleanup
mkdir -p "$(dirname "$work")"
git worktree add --quiet --detach "$work" "$tag"

# Releases from before the versioned site (0.9 and 0.10) have no
# mkdocs.mike.yml. They get this tree's, and its page template, which holds
# the banner for older versions; their template is otherwise the same.
if [ ! -f "$work/mkdocs.mike.yml" ]; then
    cp "$root/mkdocs.mike.yml" "$work/mkdocs.mike.yml"
    cp "$root/docs/overrides/main.html" "$work/docs/overrides/main.html"
fi

cd "$work"

# The newest minor on gh-pages, counting this one. mike list fails when
# nothing is published yet.
published=$(mike list -F mkdocs.mike.yml --json 2>/dev/null |
    python3 -c 'import json, sys; [print(v["version"]) for v in json.load(sys.stdin)]' ||
    true)
newest=$(printf '%s\n' $published "$version" |
    grep -E '^[0-9]+\.[0-9]+$' | sort -V | tail -n 1)

deploy() {
    mike deploy "${push[@]}" -F mkdocs.mike.yml \
        --title "$release" \
        --message "docs: publish $release as $version" \
        "$@"
}

if [ "$newest" = "$version" ]; then
    echo "docs-publish: $tag -> $version, and latest"
    deploy --update-aliases "$version" latest
else
    echo "docs-publish: $tag -> $version; latest stays on $newest"
    deploy "$version"
fi
