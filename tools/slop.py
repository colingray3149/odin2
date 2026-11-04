#!/usr/bin/env python3
"""slop.py — slop findings against the shrink-only baseline in slop-baseline.txt.

Kinds: mega (non-test Rust under crates/*/src or own-code TS over CAP lines), marker (TODO/FIXME/XXX, todo!,
unimplemented!), escape (allow(dead_code), allow(unused), allow(clippy::too_many_arguments); Rust only).
Vendored code (view/omp, view/shim, extension/generated) and test files are out of scope. A mega file over CAP
that is not baselined fails, as does a baselined file above its recorded count; a baselined file at or under CAP
(or gone) fails until its baseline line is deleted — the baseline only shrinks, by editing it in a reviewed commit. Markers and escapes always
fail. Prints `<kind> <path>:<line> <detail>` per finding.
"""
import os
import pathlib
import re
import subprocess
import sys

CAP = 1500
BASELINE = pathlib.Path(__file__).with_name("slop-baseline.txt")
# An inline test module, or a file-scope test function (#[test], #[tokio::test], #[sqlx::test]).
TEST_MODULE = re.compile(
    r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]\s*(?:#\[[^\]]*\]\s*)*"
    r"(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+\s*\{"
    r"|#\s*\[\s*(?:\w+\s*::\s*)?test\s*(?:\([^\]]*\))?\s*\]\s*(?:#\[[^\]]*\]\s*)*"
    r"(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+\w+[^{;]*\{")
RUST_LITERAL = re.compile(
    r'//[^\n]*|/\*|\b(?:br|cr|r)(?P<hashes>#{0,255})"|"(?:\\[\s\S]|[^"\\])*"'
    r"|'(?:\\(?:u\{[0-9a-fA-F_]+\}|x[0-9a-fA-F]{2}|[^\n])|[^'\\\n])'")
MARKER = re.compile(r"\b(TODO|FIXME|XXX)\b|\b(todo|unimplemented)!\s*\(")
ESCAPE = re.compile(r"allow\((?:dead_code|unused|clippy::too_many_arguments)")
VENDORED = ("view/omp/", "view/shim/", "extension/generated/")


def test_module_spans(source, path):
    """Byte spans of inline #[cfg(test)] modules, literals blanked so braces inside them do not count."""
    structure = list(source)
    cursor = 0
    while match := RUST_LITERAL.search(source, cursor):
        start, end = match.span()
        if match.group() == "/*":
            depth = 1
            while depth:
                boundary = re.search(r"/\*|\*/", source[end:])
                if boundary is None:
                    raise ValueError(f"{path}: unterminated Rust comment")
                depth += 1 if boundary.group() == "/*" else -1
                end += boundary.end()
        elif match.group("hashes") is not None:
            delimiter = '"' + match.group("hashes")
            close = source.find(delimiter, end)
            if close < 0:
                raise ValueError(f"{path}: unterminated Rust raw string")
            end = close + len(delimiter)
        structure[start:end] = ["\n" if c == "\n" else " " for c in source[start:end]]
        cursor = end
    structure = "".join(structure)
    spans = []
    cursor = 0
    while match := TEST_MODULE.search(structure, cursor):
        depth = 1
        for brace in re.compile(r"[{}]").finditer(structure, match.end()):
            depth += 1 if brace.group() == "{" else -1
            if depth == 0:
                cursor = brace.end()
                spans.append((match.start(), cursor))
                break
        else:
            raise ValueError(f"{path}: unterminated inline test module")
    return spans


def non_test_lines(path):
    """Preserve source line numbers while excluding only inline test-module spans."""
    source = path.read_text()
    spans = test_module_spans(source, path)
    # Newline placeholders keep diagnostics on the original source lines. Partial
    # lines retain production code on either side of a one-line test module.
    visible = list(source)
    for start, end in spans:
        visible[start:end] = ["\n" if c == "\n" else "\0" for c in source[start:end]]
    lines = "".join(visible).splitlines()
    offset = 0
    for number, original in enumerate(source.splitlines(keepends=True)):
        end = offset + len(original.rstrip("\r\n"))
        if any(start <= offset and end <= stop for start, stop in spans):
            lines[number] = None
        elif "\0" in lines[number]:
            retained = lines[number].replace("\0", "")
            lines[number] = retained if retained.strip() else None
        offset += len(original)
    return lines


def rust_scope(path):
    return path.endswith(".rs") and "/src/" in path and not (
        "/tests/" in path or path.endswith(("/tests.rs", "_tests.rs")) or "/benches/" in path)


def ts_scope(path):
    return (path.endswith(".ts") and not path.startswith(VENDORED) and "/node_modules/" not in path
            and "/tests/" not in path and "/test/" not in path and not path.endswith((".test.ts", "_test.ts")))


def scan():
    findings, counts = [], {}
    for path in subprocess.check_output(["git", "ls-files"], text=True).splitlines():
        if rust_scope(path):
            lines = non_test_lines(pathlib.Path(path))
        elif ts_scope(path):
            lines = pathlib.Path(path).read_text().splitlines()
        else:
            continue
        counts[path] = sum(line is not None for line in lines)
        for number, line in enumerate(lines, 1):
            if line is None:
                continue
            if MARKER.search(line):
                findings.append(("marker", path, number, line.strip()))
            if ESCAPE.search(line):
                findings.append(("escape", path, number, line.strip()))
    return findings, counts


def main():
    os.chdir(subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip())
    caps = {}
    for entry in BASELINE.read_text().splitlines():
        if entry.strip():
            kind, path, recorded = entry.split()
            if kind != "mega" or int(recorded) <= CAP or path in caps:
                raise ValueError(f"invalid baseline entry: {entry}")
            caps[path] = int(recorded)
    findings, counts = scan()
    failures = [f"{kind} {path}:{number} {detail}".rstrip() for kind, path, number, detail in findings]
    baselined = 0
    for path, count in sorted(counts.items()):
        if count <= CAP:
            continue
        recorded = caps.pop(path, None)
        if recorded is None:
            failures.append(f"mega {path}:0 {count} non-test lines (cap {CAP}; split it)")
        elif count > recorded:
            failures.append(f"mega {path}:0 {count} non-test lines (baseline {recorded}; split it)")
        else:
            baselined += 1
    failures += [f"stale-baseline {path}: {counts.get(path, 0)} non-test lines; delete its line from "
                 f"{BASELINE.name}" for path in caps if counts.get(path, 0) <= CAP]
    for failure in failures:
        print(failure)
    if not failures:
        print(f"ok: no slop findings; {baselined} mega file(s) under baseline")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
