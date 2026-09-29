# How to Release a New Version

This guide takes a release from a version bump to the packages in the [package feed](https://github.com/m00qek/packages.ucode.dev). The feed builds `luci-sso` from the tarball GitHub serves for the release tag, with its own copy of the package Makefile. You generate that copy from `openwrt/luci-sso/Makefile`; never edit it by hand.

---

## Prerequisites

- Push access to `m00qek/luci-sso` and `m00qek/packages.ucode.dev`
- A clone of `packages.ucode.dev`
- `curl`, `tar` and `sha256sum` (or `shasum`) on the host

---

## 1. Bump the version

Before you start, go through the [open issues labelled `next-release`](https://github.com/m00qek/luci-sso/issues?q=is%3Aissue+is%3Aopen+label%3Anext-release). Ship each item in this release, or move it to a later one on purpose.

1. Set `PKG_VERSION` in `openwrt/luci-sso/Makefile` to the new version. Reset `PKG_RELEASE` to `1`.
2. Find the places that name the old version, such as package file names, and update them:

    ```bash
    git grep -F '0.10.0' -- ':!CHANGELOG.md' ':!devenv/scripts/testdata/'
    ```

    Leave `devenv/scripts/testdata/` alone: it holds a fixed release that the lint checks compare against.

3. Add the release to `CHANGELOG.md`.
4. Run `make lint`. It also checks that the feed Makefile generator still accepts `openwrt/luci-sso/Makefile` (see [If the generator refuses the Makefile](#if-the-generator-refuses-the-makefile)).
5. Commit as `chore(release): <version>` and merge to `main` through a pull request.

## 2. Tag the release

Tag the merge commit on `main` and push the tag:

```bash
git switch main
git pull
git tag v0.11.0
git push origin v0.11.0
```

The tag name is `v` followed by `PKG_VERSION`. The feed downloads `https://github.com/m00qek/luci-sso/archive/refs/tags/v<version>.tar.gz`, so the tag must be on GitHub before the next step.

## 3. Generate the feed Makefile

Write the feed Makefile straight into your `packages.ucode.dev` clone:

```bash
make feed-makefile VERSION=0.11.0 OUT=../packages.ucode.dev/luci-sso/Makefile
```

The target downloads the tag's tarball, takes `openwrt/luci-sso/Makefile` from it, and adds the tarball's SHA-256 as `PKG_HASH`. It writes nothing if the tag does not exist or the Makefile in the tarball is not in the shape it expects. Without `OUT`, it prints the Makefile.

To work offline, give it the tarball, or only the hash:

```bash
# A tarball already on disk
make feed-makefile VERSION=0.11.0 TARBALL=v0.11.0.tar.gz OUT=...

# Only the hash: transforms openwrt/luci-sso/Makefile from this tree
make feed-makefile VERSION=0.11.0 HASH=<sha256> OUT=...
```

With `HASH`, nothing checks that the hash or the Makefile match the tag. The feed's CI checks both before it publishes.

## 4. Publish to the feed

In the `packages.ucode.dev` clone, review the diff and commit:

```bash
git diff luci-sso/Makefile
git add luci-sso/Makefile
git commit -m "chore: bump luci-sso to 0.11.0"
git push
```

A push to `main` that changes `luci-sso/` runs the feed's `luci-sso` workflow. Its first job regenerates the Makefile with the generator from the `v<version>` tag and fails if the committed one differs. Only then does the workflow build the packages for each architecture and OpenWrt release and publish them.

---

## If the generator refuses the Makefile

The generator applies a fixed set of changes to `openwrt/luci-sso/Makefile`. When an anchor for one of them is missing or has changed, it stops and names the line, rather than publish a Makefile that cannot build. `make lint` runs it against the current tree, so you see this in the pull request that changes the Makefile, not at release time.

| Error | Cause | Fix |
| :--- | :--- | :--- |
| `expected one PKG_RELEASE:= line` or `PKG_LICENSE:= line` | The line was removed, renamed or duplicated. | Restore a single `PKG_RELEASE:=` and `PKG_LICENSE:=` line. |
| `Build/Prepare is not the two-line ... block` | `define Build/Prepare` has a new step. | Add the step to the replacement block in `devenv/scripts/gen-feed-makefile.sh`, with its paths under `$(PKG_BUILD_DIR)`. |
| `"  TITLE:=" lines` | A `define Package/<name>` block has no `TITLE:=` indented two spaces. | Give each package one `  TITLE:=` line. |
| `BuildPackage calls` | A package is defined but not built, or the other way round. | Add the missing `define` or `BuildPackage` line. |
| `path relative to ./` | A recipe line copies from `./` outside `./files/` and `./src/`. | Move the file under `files/` or `src/`, or teach the generator the new directory. |
| `the source already sets ...` | The Makefile sets a variable the generator adds. | Remove it from `openwrt/luci-sso/Makefile`. |

After changing the generator, run `make lint`. `devenv/scripts/check-feed-makefile.sh` checks that it still reproduces the published 0.10.0 feed Makefile byte for byte, and that each broken Makefile above is still refused.
