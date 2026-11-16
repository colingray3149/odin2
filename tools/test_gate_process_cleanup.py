"""An early gate failure must not leave background descendants holding its lock."""

import fcntl
import os
import signal
import subprocess
import tempfile
import time
import unittest
from pathlib import Path


class GateProcessCleanupTests(unittest.TestCase):
    def test_failure_kills_background_process_group_and_releases_lock(self):
        gate = Path(__file__).with_name("gate.sh").read_text()
        # Exercise the actual background/join/EXIT implementation without running the gate's checks.
        helpers = gate[gate.index("now_ms()") : gate.index("step install")]
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            (root / "tools").mkdir()
            (root / "tools/gate-results.py").write_text("pass\n")
            lock_path = root / "lock"
            ready = root / "ready"
            script = root / "exercise.sh"
            script.write_text(
                "set -euo pipefail\n"
                f"cd {root!s}\n"
                "outcomes=$(mktemp)\ncurrent=''\nbegan=0\nstart=test\nSTEPS=()\n"
                + helpers
                + "background python bash -c '\n"
                + "  sleep 60 &\n"
                + f"  echo $! > {ready!s}\n"
                + "  wait\n'\n"
                + f"while [ ! -s {ready!s} ]; do sleep 0.01; done\n"
                + "exit 1\n"
            )
            with lock_path.open("w") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                process = subprocess.Popen(
                    ["bash", str(script)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=(lock.fileno(),)
                )
                try:
                    stdout, stderr = process.communicate(timeout=10)
                    lock.close()
                    self.assertEqual(process.returncode, 1, (stdout, stderr))
                    descendant = int(ready.read_text())
                    with lock_path.open("w") as contender:
                        fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    # A killed orphan can briefly remain as a zombie until its new parent reaps it.
                    stat = Path(f"/proc/{descendant}/stat")
                    deadline = time.monotonic() + 2
                    while stat.exists() and stat.read_text().split()[2] != "Z" and time.monotonic() < deadline:
                        time.sleep(0.01)
                    if stat.exists():
                        self.assertEqual(stat.read_text().split()[2], "Z")
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait()
                    if ready.exists():
                        try:
                            pid = int(ready.read_text())
                            stat = Path(f"/proc/{pid}/stat")
                            if stat.exists() and stat.read_text().split()[2] != "Z":
                                os.kill(pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass


if __name__ == "__main__":
    unittest.main()
