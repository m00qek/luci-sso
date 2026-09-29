#!/bin/bash
# Tests devenv/scripts/gen-feed-makefile.sh, offline:
#
#   golden       the 0.10.0 source Makefile and tarball hash produce, byte for
#                byte, the feed Makefile packages.ucode.dev published for
#                0.10.0 (testdata/feed-makefile/0.10.0/)
#   current      openwrt/luci-sso/Makefile in this tree still has every anchor
#                the generator needs, so the next release can be generated
#   fail-closed  each broken source makes the generator exit non-zero and
#                write nothing
#
# CI runs this via .github/workflows/lint.yml.

set -euo pipefail
cd "$(dirname "$0")/../.."

gen=devenv/scripts/gen-feed-makefile.sh
golden=devenv/scripts/testdata/feed-makefile/0.10.0
golden_hash=c8b77f7fad42492e6b13a0f6e1c9b64f76d2c8396811aabc7f311ce47bcaeceb
dummy_hash=0000000000000000000000000000000000000000000000000000000000000000

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail=0

# golden
if ! sh "$gen" --hash "$golden_hash" --source "$golden/source.mk" -o "$work/golden.mk" 0.10.0; then
	echo "FAIL: golden: the generator refused the 0.10.0 source"
	fail=1
elif ! cmp -s "$work/golden.mk" "$golden/expected.mk"; then
	echo "FAIL: golden: output differs from the published 0.10.0 feed Makefile:"
	diff -u "$golden/expected.mk" "$work/golden.mk" || true
	fail=1
fi

# current
version=$(sed -n 's/^PKG_VERSION:=//p' openwrt/luci-sso/Makefile)
if ! sh "$gen" --hash "$dummy_hash" -o "$work/current.mk" "$version"; then
	echo "FAIL: current: openwrt/luci-sso/Makefile no longer has the shape the generator transforms."
	echo "      Update devenv/scripts/gen-feed-makefile.sh with it, or the next release cannot reach the feed."
	fail=1
fi

# fail-closed: <name> <expected error> <sed script applied to the golden source>
# The error text is matched too, so each case fails for the reason it tests.
refuses() {
	local name=$1 reason=$2 edit=$3
	sed "$edit" "$golden/source.mk" > "$work/$name.src"
	if cmp -s "$work/$name.src" "$golden/source.mk"; then
		echo "FAIL: fail-closed: $name: the edit changed nothing, so it tests nothing"
		fail=1
		return
	fi
	if sh "$gen" --hash "$dummy_hash" --source "$work/$name.src" -o "$work/$name.out" 0.10.0 2>"$work/$name.err"; then
		echo "FAIL: fail-closed: $name: the generator accepted it"
		fail=1
	elif ! grep -qF -- "$reason" "$work/$name.err"; then
		echo "FAIL: fail-closed: $name: refused, but not with \"$reason\":"
		sed 's/^/      /' "$work/$name.err"
		fail=1
	elif [ -e "$work/$name.out" ] || compgen -G "$work/$name.out.*" >/dev/null; then
		echo "FAIL: fail-closed: $name: the generator failed but left output behind"
		fail=1
	fi
}

refuses no-release         'one PKG_RELEASE:= line, found 0' '/^PKG_RELEASE:=/d'
refuses two-releases       'one PKG_RELEASE:= line, found 2' '/^PKG_RELEASE:=/p'
refuses no-license         'one PKG_LICENSE:= line, found 0' '/^PKG_LICENSE:=/d'
refuses no-prepare         'one define Build/Prepare, found 0' '/^define Build\/Prepare$/,/^endef$/d'
refuses prepare-changed    'Build/Prepare is not the two-line' '/^\t\$(CP) \.\/mod\/\*/a\	touch $(PKG_BUILD_DIR)/.prepared'
refuses title-missing      '"  TITLE:=" lines' '0,/^  TITLE:=/{/^  TITLE:=/d}'
refuses title-tab-indented '"  TITLE:=" lines' 's/^  TITLE:=/\tTITLE:=/'
refuses relative-mod-path  'path relative to ./' '/luci-sso-cleanup \$(1)/a\	$(CP) ./mod/extra $(1)/usr/lib/'
refuses relative-dot-dot   'path relative to ./' '/luci-sso-cleanup \$(1)/a\	$(CP) ../other $(1)/usr/lib/'
refuses has-pkg-hash       'already sets PKG_HASH' '/^PKG_RELEASE:=/a\PKG_HASH:=skip'
refuses has-pkg-source     'already sets PKG_SOURCE' '/^PKG_RELEASE:=/a\PKG_SOURCE:=x.tar.gz'
refuses has-url            'already sets URL' '/^  TITLE:=OIDC/a\  URL:=https://example.com'
refuses package-no-build   'BuildPackage calls' '/^\$(eval \$(call BuildPackage,\$(PKG_NAME)-crypto-openssl))$/d'
refuses version-mismatch   "PKG_VERSION is '0.9.1', expected 0.10.0" 's/^PKG_VERSION:=0\.10\.0$/PKG_VERSION:=0.9.1/'

[ "$fail" -ne 0 ] && {
	printf '\nThe feed Makefile generator (%s) is out of step with openwrt/luci-sso/Makefile or its tests.\n' "$gen"
	exit 1
}
echo "OK: feed Makefile — generator reproduces 0.10.0, accepts openwrt/luci-sso/Makefile, fails closed"
