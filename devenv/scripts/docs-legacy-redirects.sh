#!/bin/sh
# Writes a static redirect page at every page path of the old unversioned
# docs site, pointing to the same page under /latest/. Part of the one-time
# move to the versioned site (see docs-backfill.sh).
#
# The root 404.html already redirects unknown paths, but only with JavaScript
# and behind an HTTP 404: crawlers and no-JS clients see the page as gone.
# These pages answer 200 with a canonical link and a meta refresh, so search
# engines treat them as moved. A tiny script keeps the #anchor, which a meta
# refresh drops.
#
# Usage: docs-legacy-redirects.sh <old-site-ref> <gh-pages-worktree> [version]
#   old-site-ref   git ref of the old unversioned gh-pages (e.g. origin/gh-pages
#                  before the backfill is pushed)
#   worktree       checkout of the new gh-pages branch to write into
#   version        folder that must contain every target page (default: the
#                  folder the latest alias points to)
set -eu

old_ref=$1
out=$2
base=/luci-sso
site=https://m00qek.github.io/luci-sso

version=${3:-$(python3 -c 'import json,sys
for v in json.load(open(sys.argv[1])):
    if "latest" in v["aliases"]: print(v["version"])' "$out/versions.json")}
[ -n "$version" ] || { echo "no version has the latest alias" >&2; exit 1; }

count=0
missing=0
for page in $(git ls-tree -r --name-only "$old_ref" | grep '/index\.html$'); do
	dir=${page%index.html}              # how-to/sysadmin/upgrade/
	case "$dir" in
		latest/*|[0-9]*.[0-9]*/*) continue ;;   # already versioned
	esac
	if [ ! -f "$out/$version/$page" ]; then
		echo "skip (not in $version): $dir" >&2
		missing=$((missing + 1))
		continue
	fi
	target="$base/latest/$dir"
	mkdir -p "$out/$dir"
	cat > "$out/$page" <<EOF
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Moved</title>
<link rel="canonical" href="$site/latest/$dir">
<meta name="robots" content="noindex">
<script>location.replace("$target" + location.search + location.hash);</script>
<meta http-equiv="refresh" content="0; url=$target">
</head>
<body><p>This page moved to <a href="$target">$site/latest/$dir</a>.</p></body>
</html>
EOF
	count=$((count + 1))
done

echo "wrote $count redirect pages to latest ($version); skipped $missing"
