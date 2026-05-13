# docs/

Source for the [luci-sso documentation site](https://m00qek.github.io/luci-sso/).

Built with [MkDocs Material](https://squidfunk.github.io/mkdocs-material/). Structured using the [Diátaxis framework](https://diataxis.fr/) — tutorials, how-to guides, reference, and explanation.

## Build and preview

```bash
make -C docs install   # Install Python dependencies (first time only)
make -C docs serve     # Live preview at http://localhost:8000
make -C docs build     # Build static site to bin/site/
```

## Structure

```
docs/
├── tutorials/     # Learning-oriented — guided first-time experiences
├── how-to/        # Goal-oriented — recipes for specific tasks
├── reference/     # Information-oriented — UCI schema, HTTP API, log messages
└── explanation/   # Understanding-oriented — architecture, security model, OIDC flow
```

For contribution guidelines, see [How to Write Documentation](https://m00qek.github.io/luci-sso/how-to/developer/documentation/).
