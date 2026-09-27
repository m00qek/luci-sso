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

The output will be generated in the `bin/site/` directory in the project root. The build is strict: any warning, such as a link to a missing page, fails it, the same way CI does.

### 3. Clean Up
To remove the generated `bin/site/` directory:

```bash
make -C docs clean
```

---

## Standards & Style
Before submitting a PR, ensure your changes follow our [Documentation Standards](../../reference/style-guide.md#documentation-standards):

- **Diataxis:** Place your file in the correct quadrant (Tutorial, How-to, Reference, or Explanation).
- **Accessibility:** Add descriptive `alt` text to all images.
- **Diagrams:** Use Mermaid.js for diagrams and provide a textual fallback.

### Reuse a shared block

Blocks that appear on many pages live in `docs/_snippets/` and are included with [pymdownx.snippets](https://facelessuser.github.io/pymdown-extensions/extensions/snippets/). Put the marker on a line of its own, at column 0:

```text
;--8<-- "check-log.md"
```

| Snippet | Content |
| :--- | :--- |
| `check-log.md` | The **Browser (LuCI)** / **Terminal (SSH)** tabs for reading the `luci-sso` log. |
| `probe-enabled.md` | The `?action=enabled` probe run on the router, expecting `{"enabled": true}`. |

Keep the page's own lead-in sentence and follow-up outside the snippet. If a page needs a different command (another filter, another expected answer), write the block inline rather than adding a variant. A missing snippet file fails the build (`check_paths: true`).
