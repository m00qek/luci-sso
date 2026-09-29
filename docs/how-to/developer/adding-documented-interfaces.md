# How to add error codes, limit constants, and cookies

Three categories of interface are enforced by bidirectional lint checks: error codes, request limit constants, and cookie names. Adding any of them requires changes in both code and documentation. CI will fail if the two sides are out of sync.

Run the checks locally before pushing:

```bash
make lint
```

---

## Add an error code

**1. Export the constant from `errors.uc`:**

```javascript
export const MY_NEW_ERROR = "MY_NEW_ERROR";
```

Place it in the appropriate section comment. The string value must match the constant name exactly.

**2. Add a row to `docs/reference/log-messages.md`:**

Add to the relevant table. The code must appear in the first column, backtick-quoted:

```markdown
| `MY_NEW_ERROR` | What triggers it | What it means and how to resolve it |
```

The lint check (`check-error-codes.sh`) enforces that every `export const` in `errors.uc` has a matching first-column entry in `log-messages.md`, and vice versa.

---

## Add a request limit constant

**1. Declare the constant with the `LIMIT_` prefix:**

```javascript
const LIMIT_MY_THING = 42;
```

The `LIMIT_` prefix is what the lint check uses to discover the constant. Every `.uc` file under `src/` is scanned.

**2. Add a metadata comment to the relevant doc:**

Place `<!-- LIMIT_MY_THING=42 -->` in the reference page that describes the limit; only files under `docs/reference/` are scanned. For client-facing limits, that is `docs/reference/http-api.md`; for back-channel limits, use the Back-channel limits section of the same file. The comment is invisible when rendered.

```html
<!-- LIMIT_MY_THING=42 -->
```

The lint check (`check-request-limits.sh`) matches `LIMIT_NAME=VALUE` pairs in the `.uc` files under `src/` against the `<!-- LIMIT_NAME=VALUE -->` comments in the `.md` files under `docs/reference/`. Both the name and the value must match exactly.

If you change the value of an existing constant, update the metadata comment to match.

---

## Add a cookie

**1. Use the cookie name as a string literal in source:**

```javascript
"Set-Cookie": `__Host-my_cookie=${value}; HttpOnly; Secure; SameSite=Lax; Path=/`
```

The lint check (`check-cookie-names.sh`) scans the `.uc` files under `src/` for `__Host-*` names and the literal names `sysauth` and `sysauth_https`. If your cookie follows a different naming convention, add it to the grep pattern in `devenv/scripts/check-cookie-names.sh`.

**2. Add a cookie heading inside a `## Cookies` section in a doc:**

```markdown
## Cookies

### `__Host-my_cookie`

Description of what the cookie carries and its security attributes.

| Attribute | Value |
| :--- | :--- |
| `HttpOnly` | Yes |
| `Secure` | Yes |
| `SameSite` | `Lax` |
| `Path` | `/` |
```

The doc does not have to be `http-api.md`, but it must be under `docs/reference/`: the lint check scans those `.md` files for `## Cookies` sections and collects the `### \`name\`` headings within them, up to the next `---` line.
