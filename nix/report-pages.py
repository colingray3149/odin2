#!/usr/bin/env python3
"""Rasterize one exported PDF to one PNG per page. No shell."""

import json
import os
import pathlib
import subprocess
import sys

PDFTOPPM = os.environ["ODIN_PDFTOPPM"]
DPI = 144


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


def export_path(value: str, suffix: str | None) -> pathlib.Path:
    path = pathlib.PurePosixPath(value)
    if (
        "\x00" in value
        or any(part in ("", ".", "..") for part in path.parts)
        or pathlib.PurePosixPath("/export") not in path.parents
    ):
        fail(f"path must be under /export: {value}")
    if suffix is not None and not str(path).endswith(suffix):
        fail(f"path must end in {suffix}: {value}")
    return pathlib.Path(value)


def main() -> None:
    if len(sys.argv) != 3:
        fail("usage: odin-pages PDF DIR")
    pdf = export_path(sys.argv[1], ".pdf")
    directory = export_path(sys.argv[2], None)
    if not pdf.is_file():
        fail(f"PDF is missing: {pdf}")
    directory.mkdir(parents=True, exist_ok=True)
    for stale in directory.glob("page-*.png"):
        stale.unlink()
    completed = subprocess.run(
        [
            PDFTOPPM,
            "-png",
            "-r",
            str(DPI),
            str(pdf),
            str(directory / "page"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        sys.stderr.write(completed.stderr or completed.stdout)
        raise SystemExit(completed.returncode or 1)
    files = []
    for path in sorted(directory.glob("page-*.png")):
        page = int(path.stem.removeprefix("page-"))
        header = path.read_bytes()[:24]
        width = height = None
        if header.startswith(b"\x89PNG\r\n\x1a\n") and header[12:16] == b"IHDR":
            width = int.from_bytes(header[16:20], "big")
            height = int.from_bytes(header[20:24], "big")
        files.append(
            {
                "page": page,
                "path": f"{directory}/{path.name}",
                "bytes": path.stat().st_size,
                "width": width,
                "height": height,
            }
        )
    if not files:
        fail(f"{pdf} produced no pages")
    receipt = {"pdf": str(pdf), "dpi": DPI, "pages": len(files), "files": files}
    (directory / "pages.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    json.dump({"pages": len(files), "dir": str(directory), "dpi": DPI}, sys.stdout)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
