"""Keep the complete bounded ast-grep preview in capsule scratch, not the effector's short receipt."""

import json
import os
from pathlib import PurePosixPath
import subprocess
import sys

MAX_BYTES = 4 * 1024 * 1024


def main():
    output = PurePosixPath(sys.argv[1])
    if output.parent != PurePosixPath(".odin-eval") or not output.name.startswith("rewrite-"):
        raise ValueError("preview output is not authority-selected capsule scratch")
    try:
        os.mkdir(".odin-eval", 0o700)
    except FileExistsError:
        pass
    directory = os.open(".odin-eval", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open(
            output.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory,
        )
    finally:
        os.close(directory)
    with os.fdopen(fd, "wb") as target:
        with subprocess.Popen(sys.argv[2:], stdout=subprocess.PIPE) as child:
            size = 0
            while chunk := child.stdout.read(65536):
                size += len(chunk)
                if size > MAX_BYTES:
                    child.kill()
                    child.wait()
                    print(
                        "ast-grep preview exceeded 4 MiB; narrow paths for a complete count",
                        file=sys.stderr,
                    )
                    return 2
                target.write(chunk)
            status = child.wait()
    print(json.dumps({"stdout_path": str(output)}))
    return status if status >= 0 else 128 - status


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError) as error:
        print(f"ast-grep preview: {error}", file=sys.stderr)
        sys.exit(2)
