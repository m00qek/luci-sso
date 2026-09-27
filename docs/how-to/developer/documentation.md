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

The output will be generated in the `bin/site/` directory in the project root. The build is strict: any warning, such as a link to a missing page, fails it. The CI docs build is not strict, so this local build is the one that catches broken links.

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
