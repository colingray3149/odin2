#!/usr/bin/env python3
"""PID1 Claude owner and bounded exec client (Python standard library only).

The carrier must authenticate/UID-prove exec access before invoking client mode.
Socket peer credentials additionally restrict callers to root. Claude runs as
uid/gid1000, without supplementary groups or capabilities, under no_new_privs.
No request content, child diagnostics, or exception details are logged.
Durable pending writes are never retried: their delivery is uncertain.

Serve is the container's foreground PID1, never a detached exec child. The
carrier mounts this file at /run/odin-material/supervisor.py. Authenticated exec
uses /bin/python3 -I <script> client with one JSON object on stdin followed by EOF.
Replies are one JSON object: ok plus operation fields, or a fixed error code.
start binds canonical session UUID and argv (first entry /odin/bin/claude);
write binds monotonically increasing seq and one NDJSON data line; read returns
base64 data from offset with limit <=262144 and next_offset. inspect exposes
session/state/exit_code/uncertain/last_seq/output_bytes. freeze/thaw/shutdown
require the bound session. eof means current spool end, not process exit.
version is prelaunch-only: fixed --version under the same child privilege drop,
with a 10-second deadline, 4096-byte stdout cap and no retained stderr. Root
control state lives separately from child files at /run/odin-supervisor (0700).

An attach disconnect does not affect ownership. Restarting PID1 never relaunches
an existing session: only a durable exited record is known terminal, otherwise
delivery is uncertain. The 256MiB output limit fails closed rather than silently
discarding replay history. Writes are capped at 100000 to bound journal storage.
State and pipes remain private; stdout is the sole replay stream.
"""
import base64
import ctypes
import fcntl
import hashlib
import json
import os
import selectors
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
import uuid

STATE = "/run/odin-supervisor"
WORKSPACE = "/workspace/repo"
BINARY = "/odin/bin/claude"
MAX_REQUEST = 1024 * 1024
MAX_READ = 262144
MAX_SPOOL = 256 * 1024 * 1024
MAX_WRITES = 100000


class Refusal(Exception):
    pass


def canonical_session(value):
    if not isinstance(value, str):
        raise Refusal("invalid_session")
    try:
        if str(uuid.UUID(value)) != value:
            raise ValueError()
    except ValueError:
        raise Refusal("invalid_session") from None
    return value


def integer(value):
    return isinstance(value, int) and not isinstance(value, bool)


def encode(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode()


def drop_child_authority():
    """Single-threaded owner's pre-exec fence; failure prevents exec entirely."""
    libc = ctypes.CDLL(None, use_errno=True)
    # Explicit variadic argument widths avoid ABI-dependent prctl coercions.
    def prctl(option, arg=0):
        if libc.prctl(ctypes.c_int(option), ctypes.c_ulong(arg),
                      ctypes.c_ulong(0), ctypes.c_ulong(0), ctypes.c_ulong(0)) < 0:
            raise OSError(ctypes.get_errno(), "privilege_fence")

    prctl(38, 1)  # PR_SET_NO_NEW_PRIVS, inherited across exec.
    prctl(47, 4)  # PR_CAP_AMBIENT / PR_CAP_AMBIENT_CLEAR_ALL.
    prctl(8, 0)   # PR_SET_KEEPCAPS: do not retain capabilities across setuid.
    os.setgroups([])
    os.setresgid(1000, 1000, 1000)
    os.setresuid(1000, 1000, 1000)

    class Header(ctypes.Structure):
        _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]

    class Caps(ctypes.Structure):
        _fields_ = [("effective", ctypes.c_uint32),
                    ("permitted", ctypes.c_uint32), ("inheritable", ctypes.c_uint32)]

    header = Header(0x20080522, 0)  # Linux capability ABI v3, two words.
    caps = (Caps * 2)()
    if libc.capset(ctypes.byref(header), ctypes.byref(caps)) != 0:
        raise OSError(ctypes.get_errno(), "privilege_fence")
    if libc.capget(ctypes.byref(header), ctypes.byref(caps)) != 0:
        raise OSError(ctypes.get_errno(), "privilege_fence")
    if any(word.effective or word.permitted or word.inheritable for word in caps):
        raise Refusal("privilege_fence")
    with open("/proc/self/status", "r") as stream:
        status = dict(line.split(":", 1) for line in stream if ":" in line)
    if (int(status["CapAmb"].strip(), 16) != 0
            or status["NoNewPrivs"].strip() != "1"
            or os.getresuid() != (1000, 1000, 1000)
            or os.getresgid() != (1000, 1000, 1000) or os.getgroups()):
        raise Refusal("privilege_fence")


class Supervisor:
    def __init__(self, state=STATE, workspace=WORKSPACE, binary=BINARY,
                 max_spool=MAX_SPOOL, *, test_same_identity=False):
        # No CLI/environment escape hatch exists for the fixture-only mode.
        if not test_same_identity and os.geteuid() != 0:
            raise Refusal("root_owner_required")
        self.child_setup = None if test_same_identity else drop_child_authority
        self.directory = state
        self.workspace = workspace
        self.binary = binary
        self.max_spool = max_spool
        self.child = None
        self.stopping = False
        self.frozen = False
        self.selector = selectors.DefaultSelector()
        os.umask(0o077)
        os.makedirs(state, mode=0o700, exist_ok=True)
        info = os.lstat(state)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            raise Refusal("unsafe_state_directory")
        os.chmod(state, 0o700)
        self.dirfd = os.open(state, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        if not test_same_identity:
            os.fchdir(self.dirfd)  # Root never uses the child-writable worktree cwd.
        self.lock = self.open_private("owner.lock", os.O_RDWR | os.O_CREAT)
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise Refusal("owner_exists") from None
        self.record = {"session": None, "argv": None, "state": "empty",
                       "exit_code": None, "writes": {}, "last_seq": 0,
                       "uncertain": False}
        try:
            fd = self.open_private("session.json", os.O_RDONLY)
        except FileNotFoundError:
            pass
        else:
            with os.fdopen(fd, "r") as stream:
                self.record = json.load(stream)
            if self.record["session"] is not None and self.record["state"] != "exited":
                self.record["state"] = "uncertain"
                self.record["uncertain"] = True
                self.persist()
        self.spool = self.open_private("stdout", os.O_RDWR | os.O_CREAT | os.O_APPEND)
        self.output_bytes = os.fstat(self.spool).st_size
        if self.output_bytes > max_spool:
            raise Refusal("spool_limit")
        self.socket_path = os.path.join(state, "control.sock")
        try:
            os.unlink(self.socket_path)
        except FileNotFoundError:
            pass
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(self.socket_path)
        os.chmod(self.socket_path, 0o600)
        self.listener.listen(8)
        self.listener.setblocking(False)
        self.selector.register(self.listener, selectors.EVENT_READ, "accept")

    def open_private(self, name, flags):
        fd = os.open(name, flags | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                     dir_fd=self.dirfd)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            os.close(fd)
            raise Refusal("unsafe_state_file")
        os.fchmod(fd, 0o600)
        return fd

    def persist(self):
        fd = self.open_private("session.next", os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
        with os.fdopen(fd, "wb") as stream:
            stream.write(encode(self.record))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace("session.next", "session.json", src_dir_fd=self.dirfd,
                   dst_dir_fd=self.dirfd)
        os.fsync(self.dirfd)

    def status(self):
        return {key: self.record[key] for key in
                ("session", "state", "exit_code", "uncertain", "last_seq")} | {
                    "output_bytes": self.output_bytes}

    def require_session(self, request):
        if canonical_session(request.get("session")) != self.record["session"]:
            raise Refusal("session_mismatch")

    def start(self, request):
        session = canonical_session(request.get("session"))
        argv = request.get("argv")
        if (not isinstance(argv, list) or not argv or len(argv) > 256
                or argv[0] != self.binary or any(not isinstance(arg, str)
                or "\0" in arg or len(arg) > 65536 for arg in argv)):
            raise Refusal("invalid_argv")
        if self.record["session"] is not None:
            if session != self.record["session"] or argv != self.record["argv"]:
                raise Refusal("session_immutable")
            return self.status()
        self.record.update(session=session, argv=argv, state="uncertain", uncertain=True)
        self.persist()  # A crash after this point must never launch another child.
        try:
            self.child = subprocess.Popen(argv, cwd=self.workspace,
                                          stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE, start_new_session=True,
                                          close_fds=True, bufsize=0,
                                          preexec_fn=self.child_setup)
        except (OSError, ValueError, subprocess.SubprocessError):
            raise Refusal("launch_failed") from None
        for stream, kind in ((self.child.stdout, "stdout"), (self.child.stderr, "stderr")):
            os.set_blocking(stream.fileno(), False)
            self.selector.register(stream, selectors.EVENT_READ, kind)
        os.set_blocking(self.child.stdin.fileno(), False)
        self.record.update(state="running", uncertain=False)
        self.persist()
        return self.status()

    def signal_group(self, sig):
        if self.child is not None:
            try:
                os.killpg(self.child.pid, sig)
            except ProcessLookupError:
                pass

    def drain(self, key):
        chunk = os.read(key.fileobj.fileno(), 65536)
        if not chunk:
            self.selector.unregister(key.fileobj)
            key.fileobj.close()
            return
        if key.data == "stdout":
            if self.output_bytes + len(chunk) > self.max_spool:
                self.fail_closed()
                raise Refusal("spool_limit")
            view = memoryview(chunk)
            while view:
                count = os.write(self.spool, view)
                view = view[count:]
                self.output_bytes += count
            os.fsync(self.spool)
        # Stderr is drained in bounded chunks and deliberately never retained.

    def pump(self, timeout=0):
        for key, _ in self.selector.select(timeout):
            if key.data != "accept":
                self.drain(key)
        if (self.child is not None and self.child.poll() is not None
                and not any(key.data in ("stdout", "stderr")
                            for key in self.selector.get_map().values())):
            if self.record["state"] not in ("exited", "uncertain"):
                self.record.update(state="exited", exit_code=self.child.returncode)
                self.persist()

    def fail_closed(self):
        self.signal_group(signal.SIGKILL)
        self.record.update(state="uncertain", uncertain=True)
        self.persist()

    def write_input(self, request):
        seq, data = request.get("seq"), request.get("data")
        if not integer(seq) or seq < 1 or not isinstance(data, str):
            raise Refusal("invalid_write")
        if not data.endswith("\n") or "\n" in data[:-1] or "\r" in data:
            raise Refusal("invalid_ndjson")
        try:
            json.loads(data)
            payload = data.encode("utf-8")
        except (ValueError, UnicodeError):
            raise Refusal("invalid_ndjson") from None
        digest = hashlib.sha256(payload).hexdigest()
        previous = self.record["writes"].get(str(seq))
        if previous is not None:
            if previous["digest"] != digest:
                raise Refusal("sequence_conflict")
            if previous["status"] != "written":
                raise Refusal("write_uncertain")
            return {"seq": seq, "status": "duplicate"}
        if self.record["uncertain"]:
            raise Refusal("write_uncertain")
        if seq != self.record["last_seq"] + 1:
            raise Refusal("sequence_gap")
        if seq > MAX_WRITES:
            raise Refusal("write_limit")
        if self.child is None or self.child.poll() is not None or self.frozen:
            raise Refusal("child_not_writable")
        self.record["writes"][str(seq)] = {"digest": digest, "status": "pending"}
        self.record["last_seq"] = seq
        self.persist()  # Durable delivery fence precedes even the first pipe byte.
        try:
            remaining = memoryview(payload)
            deadline = time.monotonic() + 10
            while remaining:
                if self.stopping or time.monotonic() > deadline:
                    raise Refusal("write_uncertain")
                try:
                    count = os.write(self.child.stdin.fileno(), remaining)
                    remaining = remaining[count:]
                except BlockingIOError:
                    self.pump(0.01)
            self.record["writes"][str(seq)]["status"] = "written"
            self.persist()
        except (OSError, Refusal):
            self.fail_closed()
            raise Refusal("write_uncertain") from None
        return {"seq": seq, "status": "written"}

    def group_stopped(self):
        found = False
        for entry in os.scandir("/proc"):
            if not entry.name.isdecimal():
                continue
            try:
                with open(os.path.join(entry.path, "stat"), "r") as stream:
                    fields = stream.read().rsplit(")", 1)[1].split()
            except FileNotFoundError:
                continue
            if int(fields[2]) == self.child.pid:
                found = True
                if fields[0] not in ("T", "t", "Z", "X"):
                    return False
        # A reaped leader with no remaining group needs no further stop signal.
        return found or self.child.poll() is not None

    def version(self):
        if self.record["session"] is not None:
            raise Refusal("version_after_start")
        try:
            probe = subprocess.Popen(
                [self.binary, "--version"], cwd=self.workspace,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, start_new_session=True,
                close_fds=True, bufsize=0, preexec_fn=self.child_setup)
        except (OSError, ValueError, subprocess.SubprocessError):
            raise Refusal("version_unavailable") from None
        output = bytearray()
        deadline = time.monotonic() + 10
        os.set_blocking(probe.stdout.fileno(), False)
        try:
            with selectors.DefaultSelector() as reader:
                reader.register(probe.stdout, selectors.EVENT_READ)
                while True:
                    if self.stopping or time.monotonic() >= deadline:
                        raise Refusal("version_unavailable")
                    if not reader.select(min(0.1, deadline - time.monotonic())):
                        continue
                    chunk = os.read(probe.stdout.fileno(), 4097 - len(output))
                    if not chunk:
                        break
                    output.extend(chunk)
                    if len(output) > 4096:
                        raise Refusal("version_unavailable")
            if probe.wait(timeout=max(0.001, deadline - time.monotonic())) != 0:
                raise Refusal("version_unavailable")
            try:
                return {"version": output.decode("utf-8").strip()}
            except UnicodeError:
                raise Refusal("version_unavailable") from None
        except subprocess.TimeoutExpired:
            raise Refusal("version_unavailable") from None
        finally:
            try:
                os.killpg(probe.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            probe.wait()
            probe.stdout.close()

    def dispatch(self, request):
        if not isinstance(request, dict):
            raise Refusal("invalid_request")
        self.pump()
        op = request.get("op")
        if op == "version":
            return self.version()
        if op == "inspect":
            return self.status()
        if op == "start":
            return self.start(request)
        self.require_session(request)
        if op == "read":
            offset, limit = request.get("offset"), request.get("limit", MAX_READ)
            if (not integer(offset) or not integer(limit) or offset < 0
                    or offset > self.output_bytes or not 1 <= limit <= MAX_READ):
                raise Refusal("invalid_offset")
            data = os.pread(self.spool, limit, offset)
            return self.status() | {"data": base64.b64encode(data).decode("ascii"),
                                    "next_offset": offset + len(data),
                                    "eof": offset + len(data) == self.output_bytes}
        if op == "write":
            return self.write_input(request)
        if op == "freeze":
            if self.child is None or self.record["uncertain"]:
                raise Refusal("freeze_unavailable")
            self.signal_group(signal.SIGSTOP)
            deadline = time.monotonic() + 5
            while not self.group_stopped():
                if time.monotonic() > deadline or self.stopping:
                    self.signal_group(signal.SIGCONT)
                    raise Refusal("freeze_unavailable")
                self.pump(0.01)
            self.frozen = True
            self.record["state"] = "frozen"
            self.persist()
            return self.status()
        if op == "thaw":
            if self.record["uncertain"]:
                raise Refusal("thaw_unavailable")
            self.signal_group(signal.SIGCONT)
            self.frozen = False
            if self.child is not None and self.child.poll() is None:
                self.record["state"] = "running"
                self.persist()
            return self.status()
        if op == "shutdown":
            self.stop_child()
            self.stopping = True
            return self.status()
        raise Refusal("unknown_operation")

    def stop_child(self):
        if self.child is None:
            return
        self.signal_group(signal.SIGTERM)
        self.signal_group(signal.SIGCONT)
        deadline = time.monotonic() + 3
        try:
            while self.child.poll() is None and time.monotonic() < deadline:
                self.pump(0.02)
        finally:
            # Kill remaining members even if the leader exited first, including
            # when draining or persistence failed during graceful shutdown.
            self.signal_group(signal.SIGKILL)
            self.child.wait()
        deadline = time.monotonic() + 2
        while any(k.data in ("stdout", "stderr") for k in self.selector.get_map().values()):
            if time.monotonic() > deadline:
                self.record["uncertain"] = True
                break
            self.pump(0.01)
        self.record.update(state="exited", exit_code=self.child.returncode)
        self.persist()
        while True:
            try:
                pid, _ = os.waitpid(-1, os.WNOHANG)
                if pid == 0:
                    break
            except ChildProcessError:
                break

    def serve_connection(self, conn):
        with conn:
            conn.settimeout(5)
            _, uid, _ = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            try:
                if uid != os.getuid():
                    raise Refusal("unauthorized")
                data = bytearray()
                deadline = time.monotonic() + 5
                while True:
                    if time.monotonic() >= deadline:
                        raise Refusal("request_timeout")
                    conn.settimeout(max(0.001, deadline - time.monotonic()))
                    chunk = conn.recv(min(65536, MAX_REQUEST + 1 - len(data)))
                    if not chunk:
                        break
                    data.extend(chunk)
                    if len(data) > MAX_REQUEST:
                        raise Refusal("request_limit")
                try:
                    request = json.loads(data)
                except (ValueError, UnicodeError):
                    raise Refusal("invalid_json") from None
                response = {"ok": True} | self.dispatch(request)
            except Refusal as error:
                response = {"ok": False, "error": str(error)}
            except (OSError, ValueError, KeyError, TypeError):
                self.fail_closed()
                response = {"ok": False, "error": "supervisor_failure"}
            try:
                conn.sendall(encode(response) + b"\n")
            except OSError:
                pass  # Durable state, not transport acknowledgment, owns delivery.

    def run(self):
        try:
            while not self.stopping:
                for key, _ in self.selector.select(0.1):
                    if key.data == "accept":
                        conn, _ = self.listener.accept()
                        self.serve_connection(conn)
                    else:
                        self.drain(key)
                self.pump()
        finally:
            try:
                self.stop_child()
            finally:
                self.close()

    def close(self):
        for key in list(self.selector.get_map().values()):
            self.selector.unregister(key.fileobj)
            key.fileobj.close()
        self.selector.close()
        if self.child is not None and self.child.stdin is not None:
            self.child.stdin.close()
        os.close(self.spool)
        os.close(self.lock)
        os.close(self.dirfd)


def client():
    if os.geteuid() != 0:
        raise Refusal("root_client_required")
    request = sys.stdin.buffer.read(MAX_REQUEST + 1)
    if len(request) > MAX_REQUEST:
        raise Refusal("request_limit")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(20)
        conn.connect(os.path.join(STATE, "control.sock"))
        conn.sendall(request)
        conn.shutdown(socket.SHUT_WR)
        response = bytearray()
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                break
            response.extend(chunk)
            if len(response) > MAX_REQUEST:
                raise Refusal("response_limit")
    sys.stdout.buffer.write(response)
    sys.stdout.buffer.flush()


def main():
    try:
        if sys.argv[1:] == ["client"]:
            client()
        elif sys.argv[1:] == ["serve"]:
            owner = Supervisor()
            def terminate(_sig, _frame):
                owner.stopping = True
            signal.signal(signal.SIGTERM, terminate)
            signal.signal(signal.SIGINT, terminate)
            owner.run()
        else:
            raise Refusal("invalid_mode")
    except (Exception, KeyboardInterrupt):
        # Never emit exception strings: they can include argv, input, or output.
        sys.stdout.buffer.write(b'{"ok":false,"error":"supervisor_unavailable"}\n')
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
