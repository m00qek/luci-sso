#!/usr/bin/env python3
"""
Migrate luci-sso test files from homegrown testing framework to utest.

Transformations:
  import { test, ... } from 'testing'  -> import { it, assert, truthy } from 'utest'
  test('name', fn)                     -> it('name', fn)
  test_skip('name', fn)               -> skip('name', fn)  [+ add skip to import]
  assert_eq(actual, expected, msg?)   -> assert.match(expected, actual, msg?)
  assert(cond, msg?)                  -> assert.match(truthy(), cond, msg?)
  assert_throws(fn, msg?)             -> assert.throws(fn) / assert.throws(fn, null, msg)
  assert_fail(msg)                    -> die(msg)
  assert_match(actual, re, msg?)      -> LEFT AS-IS (handled manually, 2 files only)
"""

import re
import os
import glob
import sys


def find_call_end(s, pos):
    """Given s and pos (index after the opening paren), return index after the closing paren."""
    depth = 1
    in_string = False
    string_char = None
    i = pos
    while i < len(s) and depth > 0:
        c = s[i]
        if in_string:
            if c == '\\' and i + 1 < len(s):
                i += 2
                continue
            if c == string_char:
                in_string = False
        elif c in ('"', "'", '`'):
            in_string = True
            string_char = c
        elif c == '(':
            depth += 1
        elif c == ')':
            depth -= 1
        i += 1
    return i  # position after ')'


def split_args(s):
    """Split s by top-level commas, stripping leading whitespace from each arg."""
    args = []
    current = []
    depth = 0
    in_string = False
    string_char = None
    i = 0
    while i < len(s):
        c = s[i]
        if in_string:
            if c == '\\' and i + 1 < len(s):
                current.append(c)
                current.append(s[i + 1])
                i += 2
                continue
            if c == string_char:
                in_string = False
            current.append(c)
        elif c in ('"', "'", '`'):
            in_string = True
            string_char = c
            current.append(c)
        elif c in ('(', '[', '{'):
            depth += 1
            current.append(c)
        elif c in (')', ']', '}'):
            depth -= 1
            current.append(c)
        elif c == ',' and depth == 0:
            args.append(''.join(current))
            current = []
            i += 1
            while i < len(s) and s[i] == ' ':
                i += 1
            continue
        else:
            current.append(c)
        i += 1
    if current or args:
        args.append(''.join(current))
    return args


def is_word_boundary_before(s, i):
    """Return True if the char before index i is not a word character or '.'."""
    if i == 0:
        return True
    c = s[i - 1]
    return not (c.isalnum() or c in ('_', '.'))


def transform(content):
    result = []
    i = 0
    n = len(content)

    while i < n:
        # assert_eq(
        if content[i:i+10] == 'assert_eq(' and is_word_boundary_before(content, i):
            end = find_call_end(content, i + 10)
            inner = content[i+10:end-1]
            args = split_args(inner)
            if len(args) == 2:
                result.append(f'assert.match({args[1]}, {args[0]})')
            elif len(args) >= 3:
                result.append(f'assert.match({args[1]}, {args[0]}, {args[2]})')
            else:
                result.append(content[i:end])
            i = end
            continue

        # assert_throws(
        if content[i:i+14] == 'assert_throws(' and is_word_boundary_before(content, i):
            end = find_call_end(content, i + 14)
            inner = content[i+14:end-1]
            args = split_args(inner)
            if len(args) == 1:
                result.append(f'assert.throws({args[0]})')
            elif len(args) >= 2:
                result.append(f'assert.throws({args[0]}, null, {args[1]})')
            else:
                result.append(content[i:end])
            i = end
            continue

        # assert_fail(  -- leave as die()
        if content[i:i+12] == 'assert_fail(' and is_word_boundary_before(content, i):
            end = find_call_end(content, i + 12)
            inner = content[i+12:end-1]
            result.append(f'die({inner})')
            i = end
            continue

        # assert_match( -- leave as-is (only 2 files, manual fix)
        if content[i:i+13] == 'assert_match(' and is_word_boundary_before(content, i):
            result.append(content[i])
            i += 1
            continue

        # assert( -- but NOT assert.match( or assert.throws( or assert_*
        if content[i:i+7] == 'assert(' and is_word_boundary_before(content, i):
            end = find_call_end(content, i + 7)
            inner = content[i+7:end-1]
            args = split_args(inner)
            if len(args) == 1:
                result.append(f'assert.match(truthy(), {args[0]})')
            elif len(args) >= 2:
                result.append(f'assert.match(truthy(), {args[0]}, {args[1]})')
            else:
                result.append(content[i:end])
            i = end
            continue

        # test_skip(
        if content[i:i+10] == 'test_skip(' and is_word_boundary_before(content, i):
            result.append('skip(')
            i += 10
            continue

        # test(  -- rename to it(, but not testSomething( etc.
        if content[i:i+5] == 'test(' and is_word_boundary_before(content, i):
            result.append('it(')
            i += 5
            continue

        result.append(content[i])
        i += 1

    return ''.join(result)


def fix_import(content):
    """Replace the 'from testing' import with the appropriate utest import."""
    has_skip = bool(re.search(r'\bskip\(', content))

    imports = ['it']
    if has_skip:
        imports.append('skip')
    imports.append('assert')
    imports.append('truthy')

    import_line = "import { " + ', '.join(imports) + " } from 'utest';"

    content = re.sub(
        r"import \{[^}]+\} from 'testing';",
        import_line,
        content
    )
    return content


def process_file(path):
    with open(path, 'r') as f:
        content = f.read()

    if "from 'testing'" not in content:
        return False  # not a test file using the old framework

    content = transform(content)
    content = fix_import(content)

    with open(path, 'w') as f:
        f.write(content)

    return True


def main():
    base = os.path.dirname(os.path.abspath(__file__))
    test_dir = os.path.join(base, 'test')

    files = sorted(glob.glob(os.path.join(test_dir, 'tier*', '*.uc')))

    changed = 0
    for path in files:
        if process_file(path):
            print(f"  migrated: {os.path.relpath(path, base)}")
            changed += 1

    print(f"\n{changed} files migrated.")


if __name__ == '__main__':
    main()
