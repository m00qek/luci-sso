#!/bin/bash
# Checks the code style rules that tooling can decide on its own
# (docs/reference/style-guide.md, "ucode Style" and "C Code Style").
#
# Production ucode (src/**/*.uc, files/**/*.uc, files/www/cgi-bin/luci-sso,
# files/usr/libexec/luci-sso/connection-test):
#   indent    no line is indented with spaces; tabs, then spaces for
#             alignment, are fine
#   func-end  an exported function ends with `};`, a private top-level
#             function with `}`
#   quotes    no single-quoted string, except import specifiers and strings
#             that contain a double quote
# C (mod/*.c, mod/*.h, test/fuzz_test.c) and browser JS (files/www/**/*.js):
#   indent    no line is indented with spaces, except a continuation line:
#             one whose previous line ends mid-expression (with `,`, `(`, an
#             operator...), such as a parameter list aligned under `(`
#
# Comments and template literals are skipped. Prints file:line: rule: detail
# for each violation and exits non-zero if there is any.
#
# CI runs this via .github/workflows/lint.yml.

set -euo pipefail
cd "$(dirname "$0")/../.."

exec python3 - "$@" <<'PY'
import glob, re, sys

UCODE = sorted(set(glob.glob("src/**/*.uc", recursive=True)
                   + glob.glob("files/**/*.uc", recursive=True)
                   + ["files/www/cgi-bin/luci-sso", "files/usr/libexec/luci-sso/connection-test",
                      "files/usr/libexec/luci-sso/rpcd-reload"]))
C_JS = sorted(set(glob.glob("mod/*.c") + glob.glob("mod/*.h") + ["test/fuzz_test.c"]
                  + glob.glob("files/www/**/*.js", recursive=True)))

REGEX_AFTER = {"return", "typeof", "in", "case", "delete", "void", "throw", "else", "do"}
CONTINUATION = re.compile(r"(,|\(|\[|&&|\|\||[=+\-*/%&|^?:<>!~])\s*$")


def tokens(src):
    """Yields (kind, start, end) for comments, strings, templates and regexes."""
    i, n, prev = 0, len(src), "op"
    while i < n:
        c = src[i]
        if c in " \t\r\n":
            i += 1
        elif src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j < 0 else j
            yield ("comment", i, j)
            i = j
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            yield ("comment", i, j)
            i = j
        elif c in "'\"":
            j = i + 1
            while j < n and src[j] != c and src[j] != "\n":
                j += 2 if src[j] == "\\" else 1
            yield ("string", i, j + 1)
            i, prev = j + 1, "value"
        elif c == "`":
            j, depth = i + 1, 0
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if depth == 0 and src[j] == "`":
                    break
                if src.startswith("${", j):
                    depth += 1
                    j += 1
                elif depth and src[j] == "}":
                    depth -= 1
                j += 1
            yield ("template", i, j + 1)
            i, prev = j + 1, "value"
        elif c == "/" and prev == "op":
            j, in_class = i + 1, False
            while j < n and src[j] != "\n":
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == "[":
                    in_class = True
                elif src[j] == "]":
                    in_class = False
                elif src[j] == "/" and not in_class:
                    break
                j += 1
            j += 1
            while j < n and src[j].isalpha():
                j += 1
            yield ("regex", i, j)
            i, prev = j, "value"
        else:
            m = re.compile(r"[A-Za-z_$][\w$]*|\d[\w.]*").match(src, i)
            if m:
                prev = "op" if m.group(0) in REGEX_AFTER else "value"
                i = m.end()
            else:
                prev = "value" if c in ")]}" else "op"
                i += 1


def skipped_lines(src, toks):
    """Line numbers that start inside a block comment or template literal."""
    skip = set()
    for kind, s, e in toks:
        if kind in ("comment", "template"):
            first = src.count("\n", 0, s) + 1
            last = src.count("\n", 0, e) + 1
            skip.update(range(first + 1, last + 1))
    return skip


def code_only(line):
    """The line without a trailing // comment (good enough for continuation checks)."""
    return re.sub(r"\s*//[^'\"]*$", "", line).rstrip()


violations = []


def report(path, lineno, rule, detail):
    violations.append(f"{path}:{lineno}: {rule}: {detail}")


for path in C_JS:
    src = open(path, encoding="utf-8").read()
    skip = skipped_lines(src, list(tokens(src)))
    prev = ""
    for no, line in enumerate(src.split("\n"), 1):
        if no in skip:
            continue
        if re.match(r"^ +\S", line) and not CONTINUATION.search(prev):
            report(path, no, "indent", "indented with spaces; use tabs")
        if line.strip() and not line.lstrip().startswith(("//", "/*", "*")):
            prev = code_only(line)

for path in UCODE:
    src = open(path, encoding="utf-8").read()
    toks = list(tokens(src))
    skip = skipped_lines(src, toks)
    lines = src.split("\n")

    for no, line in enumerate(lines, 1):
        if no not in skip and re.match(r"^ +\S", line):
            report(path, no, "indent", "indented with spaces; use tabs")

    for no, line in enumerate(lines, 1):
        m = re.match(r"^(export\s+)?function\s+(\w+)", line)
        if not m:
            continue
        end = next((k for k in range(no, len(lines)) if lines[k].startswith("}")), None)
        if end is None:
            continue
        want = "};" if m.group(1) else "}"
        if lines[end].rstrip() != want:
            kind = "exported" if m.group(1) else "private"
            report(path, end + 1, "func-end", f"{kind} function {m.group(2)} must end with `{want}`")

    for kind, s, e in toks:
        if kind != "string" or src[s] != "'":
            continue
        line_start = src.rfind("\n", 0, s) + 1
        before = src[line_start:s]
        if re.match(r"\s*import\b", before) or re.search(r"\bfrom\s*$", before):
            continue
        if '"' in src[s + 1:e - 1]:
            continue
        report(path, src.count("\n", 0, s) + 1, "quotes", f"{src[s:e]} must use double quotes")

for v in violations:
    print(v)

if violations:
    print(f"FAIL: {len(violations)} code style violation(s); see docs/reference/style-guide.md")
    sys.exit(1)
print(f"OK: code style — {len(UCODE)} ucode, {len(C_JS)} C/JS files")
PY
