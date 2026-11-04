#!/usr/bin/env python3
"""Write one report source from stdin to one export path. No shell, no eval."""

import pathlib
import sys
import tempfile

MAX_BYTES = 256 * 1024


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: odin-source PATH.typ|PATH.md")
    value = sys.argv[1]
    path = pathlib.PurePosixPath(value)
    if (
        "\x00" in value
        or path.suffix not in (".typ", ".md")
        or any(part in ("", ".", "..") for part in path.parts)
        or pathlib.PurePosixPath("/export") not in path.parents
    ):
        fail(f"path must be a .typ or .md file under /export: {value}")
    target = pathlib.Path(value)
    root = pathlib.Path("/export").resolve()
    current = root
    for part in target.relative_to("/export").parts:
        current = current / part
        if current.is_symlink():
            resolved = current.resolve(strict=False)
            if resolved != root and root not in resolved.parents:
                fail(f"symlink leaves /export: {value}")
    body = sys.stdin.buffer.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES:
        fail(f"source is over the {MAX_BYTES}-byte limit")
    if not body or b"\x00" in body:
        fail("source is empty or holds a NUL byte")
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as error:
        fail(f"source is not UTF-8: {error}")
    target.parent.mkdir(parents=True, exist_ok=True)
    output = tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=target.parent, prefix=f".{target.name}.", delete=False
    )
    temporary = pathlib.Path(output.name)
    try:
        with output:
            output.write(text)
        temporary.replace(target)
    finally:
        temporary.unlink(missing_ok=True)
    print(f"wrote {target} {len(body)} bytes")


if __name__ == "__main__":
    main()
