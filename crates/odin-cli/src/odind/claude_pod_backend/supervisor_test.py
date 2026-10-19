"""Controlled subprocess coverage; no Claude binary or credentials are used.

Run explicitly with: python3 -m unittest discover -s <this directory> -p supervisor_test.py
Tests exercise the real socket loop, pipes, process groups and filesystem journal.
"""
import base64
import importlib.util
import json
import multiprocessing
import os
from pathlib import Path
import signal
import socket
import sys
import tempfile
import time
import unittest
import uuid

spec = importlib.util.spec_from_file_location("pod_supervisor", Path(__file__).with_name("supervisor.py"))
supervisor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(supervisor)


def serve(state, workspace, ready, limit, isolated):
    owner = supervisor.Supervisor(state, workspace, sys.executable, limit,
                                  test_same_identity=not isolated)
    ready.send(True)
    ready.close()
    owner.run()


class SupervisorTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.state = os.path.join(self.directory.name, "private")
        self.session = str(uuid.uuid4())
        self.process = None
        self.child_pid = None
        self.launch()

    def launch(self, limit=supervisor.MAX_SPOOL, isolated=False):
        context = multiprocessing.get_context("fork")
        ready, child = context.Pipe(duplex=False)
        self.process = context.Process(target=serve, args=(
            self.state, self.directory.name, child, limit, isolated))
        self.process.start()
        child.close()
        self.assertTrue(ready.poll(5), "supervisor did not become ready")
        self.assertTrue(ready.recv())
        ready.close()

    def tearDown(self):
        if self.process is not None and self.process.is_alive():
            try:
                self.request("shutdown")
            except OSError:
                pass
            self.process.join(5)
            if self.process.is_alive():
                self.process.kill()
                self.process.join(5)
        if self.child_pid is not None:
            try:
                os.killpg(self.child_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        self.directory.cleanup()

    def connect(self):
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conn.settimeout(20)
        conn.connect(os.path.join(self.state, "control.sock"))
        return conn

    def request(self, op, **fields):
        with self.connect() as conn:
            conn.sendall(json.dumps(dict(op=op, session=self.session, **fields)).encode())
            conn.shutdown(socket.SHUT_WR)
            chunks = []
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
        return json.loads(b"".join(chunks))

    def start(self, code):
        result = self.request("start", argv=[sys.executable, "-u", "-c", code])
        self.assertTrue(result["ok"], result)
        return result

    def await_output(self, count):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            response = self.request("read", offset=0, limit=supervisor.MAX_READ)
            if response["output_bytes"] >= count:
                return response
            time.sleep(0.01)
        self.fail("child output deadline exceeded")

    def test_disconnect_duplicate_replay_and_freeze(self):
        self.start("import sys\nfor line in sys.stdin:\n sys.stdout.write(line); sys.stdout.flush()")
        payload = '{"message":"private"}\n'
        # Drop the response entirely: retry must not write to child a second time.
        with self.connect() as conn:
            conn.sendall(json.dumps(dict(op="write", session=self.session,
                                         seq=1, data=payload)).encode())
            conn.shutdown(socket.SHUT_WR)
        replay = self.request("write", seq=1, data=payload)
        self.assertEqual(replay["status"], "duplicate")
        output = self.await_output(len(payload))
        self.assertEqual(base64.b64decode(output["data"]), payload.encode())
        self.assertEqual(self.request("read", offset=0)["data"], output["data"])
        self.assertEqual(self.request("write", seq=1, data='{"different":1}\n')["error"], "sequence_conflict")
        self.assertEqual(self.request("freeze")["state"], "frozen")
        self.assertEqual(self.request("write", seq=2, data=payload)["error"], "child_not_writable")
        self.assertEqual(self.request("thaw")["state"], "running")
        self.assertEqual(self.request("shutdown")["state"], "exited")
        self.process.join(5)
        self.launch()
        self.assertEqual(self.request("read", offset=0)["data"], output["data"])
        self.assertEqual(self.request("write", seq=2, data=payload)["error"], "child_not_writable")

    def test_partial_delivery_crash_is_never_replayed(self):
        self.start("import os,time\nprint(os.getpid(),flush=True)\ntime.sleep(60)")
        output = self.await_output(1)
        self.child_pid = int(base64.b64decode(output["data"]))
        payload = json.dumps({"value": "x" * 800000}) + "\n"
        conn = self.connect()
        conn.sendall(json.dumps(dict(op="write", session=self.session, seq=1, data=payload)).encode())
        conn.shutdown(socket.SHUT_WR)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            with open(os.path.join(self.state, "session.json")) as stream:
                record = json.load(stream)
            if record["writes"].get("1", {}).get("status") == "pending":
                break
            time.sleep(0.01)
        else:
            self.fail("delivery fence was not persisted")
        self.process.kill()
        self.process.join(5)
        conn.close()
        os.killpg(self.child_pid, signal.SIGKILL)
        self.child_pid = None
        self.launch()
        self.assertEqual(self.request("inspect")["state"], "uncertain")
        self.assertEqual(self.request("write", seq=1, data=payload)["error"], "write_uncertain")
        self.assertEqual(self.request("freeze")["error"], "freeze_unavailable")

    def test_spool_limit_terminates_child_without_truncation_claim(self):
        self.process.kill()
        self.process.join(5)
        self.launch(limit=4096)
        self.start("import os,time\nos.write(1,b'x'*8192)\ntime.sleep(60)")
        self.process.join(8)
        self.assertFalse(self.process.is_alive(), "spool exhaustion did not stop owner")
        with open(os.path.join(self.state, "session.json")) as stream:
            record = json.load(stream)
        self.assertTrue(record["uncertain"])
        self.assertLessEqual(os.stat(os.path.join(self.state, "stdout")).st_size, 4096)


    def test_second_owner_cannot_replace_live_socket(self):
        # Separate interpreter avoids inheriting the owner's flock descriptor.
        import subprocess
        code = (
            "import importlib.util,sys; "
            "s=importlib.util.spec_from_file_location('owner',sys.argv[1]); "
            "m=importlib.util.module_from_spec(s); s.loader.exec_module(m); "
            "m.Supervisor(sys.argv[2],sys.argv[3],sys.executable,test_same_identity=True)"
        )
        result = subprocess.run(
            [sys.executable, "-c", code, str(Path(__file__).with_name("supervisor.py")),
             self.state, self.directory.name], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=5, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.request("inspect")["state"], "empty")

    def test_version_is_fixed_bounded_and_prelaunch_only(self):
        response = self.request("version", argv=["ignored"], data="ignored")
        self.assertTrue(response["ok"])
        self.assertTrue(response["version"].startswith("Python "))
        self.assertLessEqual(len(response["version"].encode()), 4096)
        self.assertEqual(self.request("inspect")["state"], "empty")
        self.start("import time; time.sleep(60)")
        self.assertEqual(self.request("version")["error"], "version_after_start")

    @unittest.skipUnless(os.geteuid() == 0, "requires root identity transition")
    def test_child_cannot_forge_owner_authority(self):
        self.process.kill()
        self.process.join(5)
        os.chmod(self.directory.name, 0o755)
        self.launch(isolated=True)
        self.assertTrue(self.request("version")["version"].startswith("Python "))
        code = """
import json,os,socket
state = STATE_VALUE
denied = []
for operation in (
    lambda: open(os.path.join(state,'session.json'),'wb'),
    lambda: socket.socket(socket.AF_UNIX).connect(os.path.join(state,'control.sock')),
    lambda: os.kill(os.getppid(),0),
):
    try:
        operation()
        denied.append(False)
    except PermissionError:
        denied.append(True)
with open('/proc/self/status') as stream:
    status = dict(line.split(':',1) for line in stream if ':' in line)
print(json.dumps(dict(uid=os.getresuid(),gid=os.getresgid(),groups=os.getgroups(),
    denied=denied,caps=[int(status[k].strip(),16) for k in
    ('CapEff','CapPrm','CapInh','CapAmb')],nnp=status['NoNewPrivs'].strip())),flush=True)
""".replace("STATE_VALUE", repr(self.state))
        self.start(code)
        response = self.await_output(1)
        proof = json.loads(base64.b64decode(response["data"]))
        self.assertEqual(proof["uid"], [1000, 1000, 1000])
        self.assertEqual(proof["gid"], [1000, 1000, 1000])
        self.assertEqual(proof["groups"], [])
        self.assertEqual(proof["denied"], [True, True, True])
        self.assertEqual(proof["caps"], [0, 0, 0, 0])
        self.assertEqual(proof["nnp"], "1")
        self.assertTrue(self.request("inspect")["ok"])

    def test_dirty_git_inspection_thaws_same_child(self):
        import subprocess
        repository = Path(self.directory.name) / "repository"
        repository.mkdir()
        environment = dict(os.environ, GIT_CONFIG_NOSYSTEM="1",
                           GIT_CONFIG_GLOBAL=os.devnull,
                           GIT_CONFIG_SYSTEM=os.devnull, GIT_OPTIONAL_LOCKS="0")
        for key in tuple(environment):
            if key.startswith("GIT_") and key not in (
                    "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL",
                    "GIT_CONFIG_SYSTEM", "GIT_OPTIONAL_LOCKS"):
                del environment[key]
        subprocess.run(["git", "init", "--quiet", str(repository)],
                       env=environment, check=True, capture_output=True, timeout=5)
        self.start("import os,sys\nprint(os.getpid(),flush=True)\n"
                   "for line in sys.stdin:\n print(os.getpid(),flush=True)")
        initial = self.await_output(1)
        pid_line = base64.b64decode(initial["data"])
        self.child_pid = int(pid_line)
        self.assertEqual(self.request("freeze")["state"], "frozen")
        (repository / "untracked.txt").write_text("unpublished change\n")
        status = subprocess.run(
            ["git", "-C", str(repository), "status", "--porcelain=v1", "-z",
             "--untracked-files=all"], env=environment, check=True,
            capture_output=True, timeout=5)
        self.assertEqual(status.stdout, b"?? untracked.txt\0")
        # Dirty admission is rejected by the Rust broker; its recovery action
        # must resume this exact process, not create a replacement conversation.
        self.assertEqual(self.request("thaw")["state"], "running")
        self.assertEqual(self.request("write", seq=1, data='{"continue":true}\n')["status"],
                         "written")
        replay = self.await_output(2 * len(pid_line))
        self.assertEqual(base64.b64decode(replay["data"]), pid_line * 2)
        self.assertEqual(self.request("inspect")["session"], self.session)

    def test_malformed_peer_output_does_not_block_clean_stop(self):
        import subprocess
        repository = Path(self.directory.name) / "clean-repository"
        repository.mkdir()
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith("GIT_")}
        environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                           GIT_CONFIG_SYSTEM=os.devnull, GIT_OPTIONAL_LOCKS="0",
                           GIT_AUTHOR_NAME="Supervisor Test", GIT_AUTHOR_EMAIL="test@example.invalid",
                           GIT_COMMITTER_NAME="Supervisor Test",
                           GIT_COMMITTER_EMAIL="test@example.invalid")
        def git(*args):
            return subprocess.run(
                ["git", "-C", str(repository), "-c", "core.hooksPath=/dev/null",
                 "-c", "commit.gpgSign=false", *args], env=environment,
                check=True, capture_output=True, timeout=5)
        git("init", "--quiet")
        (repository / "baseline.txt").write_text("clean committed baseline\n")
        git("add", "baseline.txt")
        git("commit", "--quiet", "-m", "controlled baseline")
        malformed = b'{not-valid-json}\n'
        self.start("import sys,time\nsys.stdout.buffer.write(" + repr(malformed)
                   + ");sys.stdout.flush()\ntime.sleep(60)")
        output = self.await_output(len(malformed))
        self.assertEqual(base64.b64decode(output["data"]), malformed)
        with self.assertRaises(json.JSONDecodeError):
            json.loads(malformed)
        self.assertEqual(self.request("freeze")["state"], "frozen")
        self.assertEqual(git("status", "--porcelain=v1", "-z",
                             "--untracked-files=all").stdout, b"")
        # Malformed output must not prevent shutdown.
        stopped = self.request("shutdown")
        self.assertTrue(stopped["ok"])
        self.assertEqual(stopped["state"], "exited")
        self.assertIsNotNone(stopped["exit_code"])
        self.assertFalse(stopped["uncertain"])
        self.process.join(5)
        self.assertFalse(self.process.is_alive())

    def test_invalid_requests_are_private_and_session_is_immutable(self):
        self.start("import time; time.sleep(60)")
        secret = "private-input-not-for-errors"
        response = self.request("write", seq=1, data=secret)
        self.assertEqual(response, {"ok": False, "error": "invalid_ndjson"})
        other = self.request("start", argv=[sys.executable, "-c", secret])
        self.assertEqual(other["error"], "session_immutable")
        self.assertEqual(self.request("read", offset=-1)["error"], "invalid_offset")
        self.assertEqual(os.stat(self.state).st_mode & 0o777, 0o700)
        self.assertEqual(os.stat(os.path.join(self.state, "control.sock")).st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
