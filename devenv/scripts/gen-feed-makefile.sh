#!/bin/sh
# Generates the luci-sso Makefile for the packages.ucode.dev feed.
#
# The feed builds luci-sso from the release tarball GitHub serves for a tag,
# not from this tree. Its Makefile is openwrt/luci-sso/Makefile with a fixed
# set of changes:
#
#   1. after PKG_RELEASE, the source lines: PKG_SOURCE, PKG_SOURCE_URL,
#      PKG_HASH (the tarball's sha256) and PKG_BUILD_DIR;
#   2. after PKG_LICENSE, PKG_LICENSE_FILES:=LICENSE;
#   3. after each package's TITLE, URL:=<the project page>;
#   4. Build/Prepare unpacks the tarball, then lifts mod/ to the build root;
#   5. every ./files/ and ./src/ path points into $(PKG_BUILD_DIR) instead.
#
# It fails closed: if any change has no anchor to apply to, if an anchor is
# not in the shape the change expects, or if a line other than a comment still
# names a path relative to ./ after the changes, it prints why and writes
# nothing. An edit to openwrt/luci-sso/Makefile that the changes do not cover
# stops the release; it never publishes a broken feed Makefile.
#
# Usage:
#   gen-feed-makefile.sh [-o OUT] VERSION
#       Download the v<VERSION> tarball, hash it, and transform the Makefile
#       inside it.
#   gen-feed-makefile.sh [-o OUT] --tarball PATH VERSION
#       The same, from a tarball already on disk.
#   gen-feed-makefile.sh [-o OUT] --hash SHA256 [--source MAKEFILE] VERSION
#       Offline: use SHA256 as PKG_HASH and transform MAKEFILE (default:
#       openwrt/luci-sso/Makefile in this tree). Nothing checks that the hash
#       matches the tag.
#
# Without -o the Makefile goes to standard output. `make feed-makefile` wraps
# this script; `devenv/scripts/check-feed-makefile.sh` tests it.

set -eu

REPO_URL=https://github.com/m00qek/luci-sso
ARCHIVE_URL=$REPO_URL/archive/refs/tags/
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

die() {
	printf 'gen-feed-makefile: %s\n' "$*" >&2
	exit 1
}

usage() {
	sed -n '/^# Usage:/,/^#$/p' "$0" | sed 's/^# \{0,1\}//' >&2
	exit 2
}

sha256_of() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | cut -d' ' -f1
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | cut -d' ' -f1
	else
		die "neither sha256sum nor shasum is installed"
	fi
}

version= tarball= hash= source= out=
while [ $# -gt 0 ]; do
	case $1 in
		--tarball) [ $# -ge 2 ] || usage; tarball=$2; shift 2 ;;
		--hash)    [ $# -ge 2 ] || usage; hash=$2; shift 2 ;;
		--source)  [ $# -ge 2 ] || usage; source=$2; shift 2 ;;
		-o|--output) [ $# -ge 2 ] || usage; out=$2; shift 2 ;;
		-h|--help) usage ;;
		-*) die "unknown option: $1" ;;
		*) [ -z "$version" ] || die "more than one VERSION: $version, $1"; version=$1; shift ;;
	esac
done

[ -n "$version" ] || usage
printf '%s\n' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$' \
	|| die "VERSION must look like 1.2.3 (no leading v): $version"
[ -z "$tarball" ] || [ -z "$hash" ] || die "--tarball and --hash are mutually exclusive"
[ -z "$source" ] || [ -n "$hash" ] \
	|| die "--source needs --hash: with a tarball, the Makefile inside it is the source"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM

# The prefix GitHub gives the paths in a tag's tarball: the tag without its v.
prefix=luci-sso-$version

if [ -n "$hash" ]; then
	printf '%s\n' "$hash" | grep -Eq '^[0-9a-f]{64}$' \
		|| die "--hash must be 64 lowercase hex digits: $hash"
	[ -n "$source" ] || source=$SCRIPT_DIR/../../openwrt/luci-sso/Makefile
	[ -f "$source" ] || die "no such source Makefile: $source"
	cp "$source" "$work/source.mk"
else
	if [ -z "$tarball" ]; then
		url=${ARCHIVE_URL}v$version.tar.gz
		tarball=$work/v$version.tar.gz
		curl -fsSL --retry 3 -o "$tarball" "$url" \
			|| die "could not download $url: is v$version tagged and pushed?"
	fi
	[ -f "$tarball" ] || die "no such tarball: $tarball"
	tar -tzf "$tarball" > "$work/listing" 2>/dev/null \
		|| die "not a gzipped tarball: $tarball"
	grep -qx "$prefix/openwrt/luci-sso/Makefile" "$work/listing" \
		|| die "$tarball has no $prefix/openwrt/luci-sso/Makefile: is it the v$version tarball?"
	tar -xzOf "$tarball" "$prefix/openwrt/luci-sso/Makefile" > "$work/source.mk"
	hash=$(sha256_of "$tarball")
fi

# The source must be the release asked for, so a stale tree or a mistyped
# VERSION cannot pair one release's file list with another's hash.
src_name=$(sed -n 's/^PKG_NAME:=//p' "$work/source.mk")
src_version=$(sed -n 's/^PKG_VERSION:=//p' "$work/source.mk")
[ "$src_name" = luci-sso ] || die "source PKG_NAME is '$src_name', expected luci-sso"
[ "$src_version" = "$version" ] \
	|| die "source PKG_VERSION is '$src_version', expected $version"

LC_ALL=C awk -v hash="$hash" -v archive_url="$ARCHIVE_URL" -v repo_url="$REPO_URL" '
function fail(msg) {
	printf "gen-feed-makefile: %s\n", msg > "/dev/stderr"
	failed = 1
	exit 1
}

# The generator owns these; one already in the source would end up twice.
/^(PKG_SOURCE[A-Z_]*|PKG_HASH|PKG_MIRROR_HASH|PKG_BUILD_DIR|PKG_LICENSE_FILES)[ \t]*[:?+]?=/ {
	fail("line " NR ": the source already sets " $1 "; the generator adds it")
}
/^[ \t]*URL[ \t]*[:?+]?=/ {
	fail("line " NR ": the source already sets URL; the generator adds it after each TITLE")
}

# 4. Build/Prepare: the body must be exactly the in-tree one, or the
# replacement would silently drop whatever was added to it.
in_prepare {
	body = body $0 "\n"
	if ($0 != "endef")
		next
	if (body != "\tmkdir -p $(PKG_BUILD_DIR)\n\t$(CP) ./mod/* $(PKG_BUILD_DIR)/\nendef\n")
		fail("Build/Prepare is not the two-line mkdir + $(CP) ./mod/* block the generator replaces:\n" body)
	print "# The release tarball keeps the C sources under mod/, but cmake.mk expects"
	print "# CMakeLists.txt at the root of PKG_BUILD_DIR. Unpack normally, then lift mod/"
	print "# up one level — the in-tree Makefile copies ./mod/* for the same reason."
	print "define Build/Prepare"
	print "\t$(call Build/Prepare/Default)"
	print "\t$(CP) $(PKG_BUILD_DIR)/mod/. $(PKG_BUILD_DIR)/"
	print "endef"
	in_prepare = 0
	next
}
$0 == "define Build/Prepare" {
	if (prepares++)
		fail("line " NR ": a second define Build/Prepare")
	in_prepare = 1
	body = ""
	next
}

# 1. The source lines, after PKG_RELEASE.
/^PKG_RELEASE:=/ {
	releases++
	print
	print ""
	print "PKG_SOURCE:=v$(PKG_VERSION).tar.gz"
	print "PKG_SOURCE_URL:=" archive_url
	print "PKG_HASH:=" hash
	print "PKG_BUILD_DIR:=$(BUILD_DIR)/luci-sso-$(PKG_VERSION)"
	next
}

# 2. The license file, after PKG_LICENSE.
/^PKG_LICENSE:=/ {
	licenses++
	print
	print "PKG_LICENSE_FILES:=LICENSE"
	next
}

# 3. The project page, after each package TITLE.
/^  TITLE:=/ {
	titles++
	print
	print "  URL:=" repo_url
	next
}

/^define Package\/[^\/]+$/ { packages++ }
/^\$\(eval \$\(call BuildPackage,/ { builds++ }

# 5. Paths into the unpacked tarball.
{
	gsub(/ \.\/files\//, " $(PKG_BUILD_DIR)/files/")
	gsub(/ \.\/src\//, " $(PKG_BUILD_DIR)/src/")
	print
}

END {
	if (failed)
		exit 1
	if (in_prepare)
		fail("define Build/Prepare has no endef")
	if (releases != 1)
		fail("expected one PKG_RELEASE:= line, found " releases + 0)
	if (licenses != 1)
		fail("expected one PKG_LICENSE:= line, found " licenses + 0)
	if (prepares != 1)
		fail("expected one define Build/Prepare, found " prepares + 0)
	if (packages < 1)
		fail("found no define Package/<name> block")
	if (titles != packages)
		fail("found " packages " define Package/<name> blocks but " titles + 0 " \"  TITLE:=\" lines: each package needs exactly one, indented two spaces")
	if (builds != packages)
		fail("found " packages " define Package/<name> blocks but " builds + 0 " BuildPackage calls")
}
' "$work/source.mk" > "$work/feed.mk" || die "refusing to generate the feed Makefile (see above)"

# Nothing may still name a path relative to the package directory: the feed
# has no files/, src/ or mod/ next to its Makefile. Comments may.
if grep -nE '(^|[[:space:]=,:])\.\.?/' "$work/feed.mk" | grep -vE '^[0-9]+:[[:space:]]*#' > "$work/relative"; then
	cat "$work/relative" >&2
	die "these lines still use a path relative to ./ (only ./files/ and ./src/ are rewritten)"
fi

# With the tarball at hand, every path the Makefile copies from must be in it.
if [ -f "$work/listing" ]; then
	grep -oE '\$\(PKG_BUILD_DIR\)/[^[:space:]]+' "$work/feed.mk" \
		| sed 's|^\$(PKG_BUILD_DIR)/||; s|/\.$||; s|/$||' | sort -u > "$work/paths"
	missing=
	while IFS= read -r p; do
		[ -n "$p" ] || continue
		grep -qxF -e "$prefix/$p" -e "$prefix/$p/" "$work/listing" || missing="$missing $p"
	done < "$work/paths"
	[ -z "$missing" ] || die "the Makefile copies paths the v$version tarball lacks:$missing"
fi

if [ -n "$out" ]; then
	# Write beside the target, then rename, so a failure never leaves half a file.
	tmp_out=$(mktemp "$out.XXXXXX") || die "cannot write next to $out"
	cp "$work/feed.mk" "$tmp_out" && mv "$tmp_out" "$out" || { rm -f "$tmp_out"; die "cannot write $out"; }
else
	cat "$work/feed.mk"
fi
