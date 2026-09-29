#!/bin/bash
# One-time move of the gh-pages branch from the unversioned site to the
# versioned one. Run it once, from a clone with the release tags, and push the
# result yourself after reviewing it. It never pushes.
#
#   1. Resets the local gh-pages branch to origin/gh-pages.
#   2. Commits a gh-pages root with only 404.html and .nojekyll: the old
#      unversioned pages would otherwise still answer at /luci-sso/<page> and
#      keep the 404 page from sending those links to /luci-sso/latest/<page>.
#   3. Publishes v0.9.1 as 0.9 and v0.10.0 as 0.10, with latest on 0.10.
#   4. Makes /luci-sso/ redirect to latest.
#
# Needs mkdocs-material and mike on PATH, at the versions
# .github/workflows/docs.yml pins.

set -euo pipefail

die() { echo "docs-backfill: $*" >&2; exit 1; }

root=$(git rev-parse --show-toplevel)
cd "$root"
command -v mike >/dev/null || die "mike is not on PATH"

git fetch origin gh-pages
git fetch origin tag v0.9.1 tag v0.10.0
[ "$(git branch --show-current)" != gh-pages ] ||
    die "switch away from gh-pages first"
git branch --force gh-pages origin/gh-pages

if git cat-file -e gh-pages:versions.json 2>/dev/null; then
    die "gh-pages already has versions.json: the backfill has run"
fi

# A commit whose tree is only the root 404 page and .nojekyll.
page=$(git hash-object -w devenv/gh-pages/404.html)
empty=$(git hash-object -w --stdin </dev/null)
tree=$(printf '100644 blob %s\t.nojekyll\n100644 blob %s\t404.html\n' "$empty" "$page" |
    git mktree)
commit=$(git commit-tree "$tree" -p gh-pages \
    -m "docs: remove the unversioned site, add the root 404 redirect")
git update-ref refs/heads/gh-pages "$commit"

devenv/scripts/docs-publish.sh v0.9.1
devenv/scripts/docs-publish.sh v0.10.0
mike set-default -F mkdocs.mike.yml \
    --message "docs: redirect the site root to latest" latest

cat <<'EOF'

gh-pages is ready locally. Review it:

    git log --stat origin/gh-pages..gh-pages
    mike serve -F mkdocs.mike.yml        # http://localhost:8000/

Then publish it:

    git push origin gh-pages
EOF
