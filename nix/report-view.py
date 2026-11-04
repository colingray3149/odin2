#!/usr/bin/env python3
"""Read one exported page PNG onto stdout so the host can show it. No shell.

A successful read appends the path to /export/report-review.json. Raster bytes
alone are not a view; a receipt that cannot be written fails the call.
"""

import json
import pathlib
import sys

MAX_BYTES = 25 * 1024 * 1024


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: odin-view PAGE.png")
    value = sys.argv[1]
    path = pathlib.PurePosixPath(value)
    if (
        "\x00" in value
        or path.suffix != ".png"
        or any(part in ("", ".", "..") for part in path.parts)
        or pathlib.PurePosixPath("/export") not in path.parents
    ):
        fail(f"path must be a PNG under /export: {value}")
    page = pathlib.Path(value)
    if page.is_symlink():
        resolved = page.resolve(strict=False)
        root = pathlib.Path("/export").resolve()
        if resolved != root and root not in resolved.parents:
            fail(f"symlink leaves /export: {value}")
    if not page.is_file():
        fail(f"page is missing: {page}")
    size = page.stat().st_size
    if size > MAX_BYTES:
        fail(f"{page} is over the {MAX_BYTES}-byte limit")
    data = page.read_bytes()
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        fail(f"{page} is not a PNG")
    record_view(value)
    sys.stdout.buffer.write(data)


def record_view(path: str) -> None:
    receipt = pathlib.Path("/export/report-review.json")
    seen: list[str] = []
    if receipt.is_file():
        try:
            loaded = json.loads(receipt.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            fail(f"the page review receipt is not JSON: {error}")
        pages = loaded.get("pages") if isinstance(loaded, dict) else None
        if not isinstance(pages, list) or not all(isinstance(item, str) for item in pages):
            fail("the page review receipt pages field is not a list of paths")
        seen = pages
    if path not in seen:
        seen.append(path)
    temporary = receipt.with_name(".report-review.json.writing")
    try:
        temporary.write_text(
            json.dumps({"pages": seen, "reviewer": "pod"}, indent=2) + "\n",
            encoding="utf-8",
        )
        temporary.replace(receipt)
    except OSError as error:
        fail(f"the page review receipt could not be written: {error}")


if __name__ == "__main__":
    main()
