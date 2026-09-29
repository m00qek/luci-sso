#!/bin/bash
# Publish the documentation of one minor release to gh-pages with mike.
#
# Usage: devenv/scripts/docs-publish.sh [--push] vX.Y.Z|docs/X.Y
#
#   vX.Y.Z    a release tag: its docs become version X.Y, titled X.Y.Z, so a
#             patch release replaces its minor
#   docs/X.Y  the docs branch of X.Y (the local branch, else origin's): its
#             docs become version X.Y, titled after the newest vX.Y.Z tag it
#             contains. devenv/scripts/check-docs-branch.sh must pass first:
#             the branch changes nothing but the docs since that tag
#
# The latest alias moves to X.Y only when no newer minor is published: a fix
# to an older minor does not take latest away.
#
# Without --push, mike commits to the local gh-pages branch only; review it
# with `mike serve -F mkdocs.mike.yml` and push it yourself. The docs workflow
# (.github/workflows/docs.yml) runs this with --push.
#
# Needs mkdocs-material and mike on PATH, at the versions the workflow pins.

set -euo pipefail

die() { echo "docs-publish: $*" >&2; exit 1; }

push=()
if [ "${1:-}" = --push ]; then
    push=(--push)
    shift
fi
ref=${1:-}

command -v mike >/dev/null || die "mike is not on PATH"
root=$(git rev-parse --show-toplevel)
cd "$root"

# A branch's commit: the local branch, else origin's.
branch_commit() {
    git rev-parse -q --verify "refs/heads/$1^{commit}" ||
        git rev-parse -q --verify "refs/remotes/origin/$1^{commit}"
}

if [[ $ref =~ ^v([0-9]+)\.([0-9]+)\.[0-9]+$ ]]; then
    version=${BASH_REMATCH[1]}.${BASH_REMATCH[2]}
    tag=$ref
    commit=$(git rev-parse -q --verify "refs/tags/$tag^{commit}") ||
        die "tag $tag does not exist"
    # Once docs/X.Y has docs fixes on top of this tag, publishing the tag
    # would take them off the site. A newer patch tag is not on the branch
    # (the branch has cherry-picks, the tag the originals), so this stops
    # only a republish of a tag the branch has moved past.
    if docs_branch=$(branch_commit "docs/$version") &&
       git merge-base --is-ancestor "$commit" "$docs_branch" &&
       ! git diff --quiet "$commit" "$docs_branch" -- docs mkdocs.yml mkdocs.mike.yml; then
        die "docs/$version has docs fixes that $tag lacks; publish docs/$version instead"
    fi
elif [[ $ref =~ ^docs/([0-9]+)\.([0-9]+)$ ]]; then
    version=${BASH_REMATCH[1]}.${BASH_REMATCH[2]}
    commit=$(branch_commit "$ref") ||
        die "no branch $ref, locally or on origin"
    # The title is the release whose code the docs describe: the newest
    # vX.Y.Z tag on the branch, which the check requires anyway. The branch
    # cannot change PKG_VERSION, so the two always agree.
    tag=$("$root/devenv/scripts/check-docs-branch.sh" "$ref" "$commit")
else
    die "usage: docs-publish.sh [--push] vX.Y.Z|docs/X.Y (got '$ref')"
fi
release=${tag#v}

pkg_version=$(git show "$commit:openwrt/luci-sso/Makefile" | sed -n 's/^PKG_VERSION:=//p')
[ "$pkg_version" = "$release" ] ||
    die "$ref has PKG_VERSION $pkg_version, not $release"

# Build from a checkout of the ref, not from the working tree. A worktree
# shares the local gh-pages branch, which is where mike commits.
work="$root/bin/docs-publish/$version"
cleanup() { git -C "$root" worktree remove --force "$work" 2>/dev/null || true; }
trap cleanup EXIT
cleanup
mkdir -p "$(dirname "$work")"
git worktree add --quiet --detach "$work" "$commit"

# Releases from before the versioned site (0.9 and 0.10), and docs branches
# cut from them, have no mkdocs.mike.yml. They get this tree's, and its page
# template, which holds the banner for older versions; their template is
# otherwise the same. The workflow runs this script from main, so every
# publish of such a ref gets the same two files.
if [ ! -f "$work/mkdocs.mike.yml" ]; then
    cp "$root/mkdocs.mike.yml" "$work/mkdocs.mike.yml"
    cp "$root/docs/overrides/main.html" "$work/docs/overrides/main.html"
fi

cd "$work"

# A reproducible build: the sitemap dates are the release's commit date, not
# the build's. The same docs published again, from the tag or from its docs
# branch, give the same files, and mike makes no commit.
export SOURCE_DATE_EPOCH
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct "$tag^{commit}")

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
        --message "docs: publish $ref ($release) as $version" \
        "$@"
}

if [ "$newest" = "$version" ]; then
    echo "docs-publish: $ref ($release) -> $version, and latest"
    deploy --update-aliases "$version" latest
else
    echo "docs-publish: $ref ($release) -> $version; latest stays on $newest"
    deploy "$version"
fi
