#!/bin/bash
# A docs/X.Y branch holds the docs of release X.Y and nothing else: its tree
# may differ from the newest vX.Y.* tag it contains only in what the docs site
# is built from. Code fixes need a release, not a docs branch.
#
# Usage: devenv/scripts/check-docs-branch.sh docs/X.Y [COMMIT]
#
# COMMIT defaults to the branch: the local one, else origin's. On success,
# prints the base tag on stdout. devenv/scripts/docs-publish.sh runs this
# before it publishes a docs/X.Y branch.
#
# Allowed outside docs/ (which includes docs/overrides/):
#   mkdocs.yml                  the site configuration
#   mkdocs.mike.yml             the versioned-site configuration; branches cut
#                               from 0.9.1 and 0.10.0 predate it
#   .github/workflows/docs.yml  GitHub runs a push with the workflow of the
#                               pushed commit, so a branch cut from a tag
#                               older than the versioned site needs the new
#                               one to publish at all

set -euo pipefail

die() { echo "check-docs-branch: $*" >&2; exit 1; }

branch=${1:-}
[[ $branch =~ ^docs/([0-9]+)\.([0-9]+)$ ]] ||
    die "usage: check-docs-branch.sh docs/X.Y [COMMIT] (got '$branch')"
minor=${BASH_REMATCH[1]}.${BASH_REMATCH[2]}

commit=${2:-}
if [ -z "$commit" ]; then
    commit=$(git rev-parse -q --verify "refs/heads/$branch^{commit}" ||
             git rev-parse -q --verify "refs/remotes/origin/$branch^{commit}") ||
        die "no branch $branch, locally or on origin"
fi

# The newest vX.Y.Z tag the branch contains. The glob's trailing dot keeps
# v0.1.* from matching v0.10.0.
tag=$(git tag --merged "$commit" --list "v$minor.*" |
    grep -E "^v[0-9]+\.[0-9]+\.[0-9]+$" | sort -V | tail -n 1 || true)
[ -n "$tag" ] ||
    die "$branch contains no v$minor.* release tag; create it from one: git branch $branch v$minor.0"
git merge-base --is-ancestor "$tag" "$commit" ||
    die "$tag is not an ancestor of $branch"

outside=$(git diff --name-only "$tag" "$commit" |
    grep -vE '^(docs/|mkdocs\.yml$|mkdocs\.mike\.yml$|\.github/workflows/docs\.yml$)' || true)
if [ -n "$outside" ]; then
    echo "$branch changes files outside docs/: $(echo $outside | sed 's/ /, /g'); code fixes need a release" >&2
    exit 1
fi

echo "$tag"
