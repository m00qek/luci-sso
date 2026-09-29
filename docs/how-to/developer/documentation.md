# How to Write Documentation

This guide describes how to contribute to the `luci-sso` documentation using the provided toolkit.

---

## Prerequisites
*   **Docker** (or Podman) installed on your machine.
*   **make** utility.

## Working Locally

The documentation uses **MkDocs** with the **Material** theme. We provide a `docs/Makefile` that wraps these tools in a Docker container, so you don't need to install Python locally.

### 1. Start the Live-Reload Server
This is the best way to write documentation. It will automatically refresh your browser whenever you save a file in `docs/` or modify `mkdocs.yml`.

```bash
make -C docs serve
```

Then open **http://localhost:8000** in your browser.

### 2. Build the Static Site
If you want to verify the final production output:

```bash
make -C docs build
```

The output will be generated in the `bin/site/` directory in the project root. The build is strict: any warning, such as a link to a missing page, fails it. CI builds the site the same way.

### 3. Clean Up
To remove the generated `bin/site/` directory:

```bash
make -C docs clean
```

### 4. Update the Screenshots
The LuCI screenshots in `docs/assets/screenshots/` are captured from the CI stack, not drawn. Retake them after a change to the LuCI pages they show:

```bash
make compile
make up
make screenshots
```

`make screenshots` runs `test/e2e/screenshots.capture.js` in the Playwright browser container, copies the PNGs into `docs/assets/screenshots/` and compresses them losslessly with `oxipng`. The script sets up the state each image needs, such as example SSO settings and a read-only role, and restores the router afterwards. It is not part of `make e2e-test`.

Look at every image before committing it: the capture shows whatever the pages show, including dates and the uptime. If a page changes what an image shows, update the image's `alt` text and title too. To add or change a shot, edit the script; each shot is one function.

The identity provider screenshots in `docs/assets/screenshots/idp/` come from real Keycloak, Authelia, Pocket ID and Authentik instances. Retake them when a provider guide moves to a newer IdP release:

```bash
make idp-screenshots                    # every IdP, one after the other
make idp-screenshots IDP=authentik      # one IdP
```

The target needs no running stack, only the browser image (`make build-images`). For each IdP, `devenv/scripts/idp-screenshots/<idp>.sh` starts the pinned image in its own containers and network, under an `example.com` host name, with generated passwords and secrets. Then `<idp>.js` walks the admin pages through the guide's steps and crops each shot. Secrets are masked before a capture. The script removes the containers and network when it ends, even on failure. To move to a newer IdP release, change the image tag in `<idp>.sh`, retake the shots, check the guide's steps against the new UI, and update the release the guide names.

### 5. Preview the Versioned Site
`make -C docs serve` shows one version, without the version selector. To see your working tree as a version of the published site, next to the released versions, build it with [mike](https://github.com/jimporter/mike) into a throwaway branch. mike runs on the host, in a Python virtual environment, at the versions `.github/workflows/docs.yml` pins:

```bash
python3 -m venv bin/venv
bin/venv/bin/pip install mkdocs-material==9.5.17 mike==2.2.0
export PATH="$PWD/bin/venv/bin:$PATH"

git fetch origin gh-pages
git branch --force docs-preview origin/gh-pages
mike deploy -F mkdocs.mike.yml -b docs-preview dev
mike serve -F mkdocs.mike.yml -b docs-preview
```

Then open **http://localhost:8000/dev/**. The selector lists `dev` with the released versions. When you are done, delete the branch with `git branch -D docs-preview`. Never pass `--push`, and never use the `gh-pages` branch for a preview.

`mike serve` does not serve the site's `404.html`, so it cannot show the redirect of unversioned links.

---

## Publish the Docs

The site has one version per minor release, at `https://m00qek.github.io/luci-sso/<X.Y>/`, and `/latest/` points to the newest. The docs workflow publishes a version when a release tag is pushed, and at no other time. Merges to `main` only build the site, with `--strict`.

### Publish a release

1. Before the release commit, run `make lint`. The docs link check fails if a link in `files/`, `src/` or `mod/` names another minor than `PKG_VERSION`, or if a `CHANGELOG.md` link names another minor than its release. Change those links to the new minor, for example from `/luci-sso/0.10/` to `/luci-sso/0.11/`.
2. Push the release tag, `vX.Y.Z`. The **Publish Docs** workflow runs `devenv/scripts/docs-publish.sh --push vX.Y.Z`. It publishes the docs of the tag as version `X.Y`, titled `X.Y.Z`, and moves `latest` to it if no newer minor is published.
3. Open `https://m00qek.github.io/luci-sso/latest/` and check that the version selector shows the new release.

A patch release replaces the docs of its minor. A patch to an older minor, such as `v0.9.2` after `0.10` is out, replaces `0.9` and leaves `latest` on `0.10`.

### Publish a release again

To publish the docs of an existing tag again, for example after a failed run, start the workflow by hand:

```bash
gh workflow run docs.yml -f tag=v0.10.0
```

This builds the docs from the tag, not from `main`. A fix to the docs of a release reaches the site with the next patch release of that minor.

### Link to the published docs

Pages inside `docs/` link to each other with relative links. A link from outside `docs/` to the site names a version; see [Links to the Published Docs](../../reference/style-guide.md#4-links-to-the-published-docs).

---

## Standards & Style
Before submitting a PR, ensure your changes follow our [Documentation Standards](../../reference/style-guide.md#documentation-standards):

- **Diataxis:** Place your file in the correct quadrant (Tutorial, How-to, Reference, or Explanation).
- **Accessibility:** Add descriptive `alt` text to all images.
- **Diagrams:** Use Mermaid.js for diagrams and provide a textual fallback.

### Reuse a shared block

Blocks that appear on many pages live in `docs/_snippets/` and are included with [pymdownx.snippets](https://facelessuser.github.io/pymdown-extensions/extensions/snippets/). Put the marker on a line of its own, at column 0. In the example below, the leading `;` only stops the marker from being expanded on this page; leave it out in yours:

```text
;--8<-- "check-log.md"
```

| Snippet | Content |
| :--- | :--- |
| `check-log.md` | The **Browser (LuCI)** / **Terminal (SSH)** tabs for reading the `luci-sso` log. |
| `probe-enabled.md` | The `?action=enabled` probe run on the router, expecting `{"enabled": true}`. |

Keep the page's own lead-in sentence and follow-up outside the snippet. If a page needs a different command (another filter, another expected answer), write the block inline rather than adding a variant. A missing snippet file fails the build (`check_paths: true`).
