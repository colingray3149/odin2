"""Target-side human Claude lifecycle. Input is stdin JSON; credentials are never read."""
import fcntl
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time
import stat
import shlex
import tempfile

PROCESS_LAUNCH = '''import fcntl,json,os,subprocess,sys,time
directory,session,unit=sys.argv[1:4]
lock=open(directory+'/launch.lock','a');fcntl.flock(lock,fcntl.LOCK_EX)
if os.path.exists(directory+'/process.json'): sys.exit(0)
if sys.argv[4]=='outer':
 os.execvp('systemd-run',['systemd-run','--user','--scope','--quiet','--unit='+unit,'--property=KillMode=control-group','--','python3','-c',sys.argv[5],directory,session,unit,*sys.argv[6:]])
pid=os.getpid()
start=open('/proc/self/stat').read().rsplit(')',1)[1].split()[19]
boot=open('/proc/sys/kernel/random/boot_id').read().strip()
props=subprocess.check_output(['systemctl','--user','show',unit,'--property=InvocationID','--property=ControlGroup']).decode()
props=dict(line.split('=',1) for line in props.splitlines())
group='/sys/fs/cgroup'+props['ControlGroup']
if not props['InvocationID']: raise RuntimeError('scope identity unavailable')
if sys.argv[4]=='sandbox':
 if not os.access(group+'/cgroup.kill',os.W_OK) or not os.access(group+'/cgroup.freeze',os.W_OK): raise RuntimeError('scope cgroup is not killable and freezable')
 os.execvp(sys.argv[5],sys.argv[5:])
pending=directory+'/process.pending'
fd=os.open(pending,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
with os.fdopen(fd,'w') as out:
 json.dump(dict(pid=pid,start_time=start,boot_id=boot,started_at_ns=time.time_ns(),session=session,scope=dict(unit=unit,invocation_id=props['InvocationID'],control_group=props['ControlGroup'])),out);out.flush();os.fsync(out.fileno())
os.link(pending,directory+'/process.json');os.unlink(pending)
fd=os.open(directory,os.O_RDONLY);os.fsync(fd);os.close(fd)
os.execvp(sys.argv[4],sys.argv[4:])
'''

LAUNCH_ACCOUNT = '''import os,stat
for relative,is_directory in account_paths:
 parts=relative.split('/')
 if relative.startswith('/') or '..' in parts: raise RuntimeError('unsafe account path')
 fd=os.open('/',os.O_PATH|os.O_DIRECTORY)
 try:
  components=os.path.expanduser('~').split('/')[1:]+parts
  for index,part in enumerate(components):
   child=os.open(part,os.O_PATH|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=child
   mode=os.fstat(fd).st_mode
   if not (stat.S_ISDIR(mode) if index<len(components)-1 or is_directory else stat.S_ISREG(mode)): raise RuntimeError('unsafe account metadata')
 finally: os.close(fd)
'''

def same_process(identity):
    try:
        boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        start = Path('/proc', str(identity['pid']), 'stat').read_text().rsplit(')', 1)[1].split()[19]
        return boot == identity['boot_id'] and start == identity['start_time']
    except FileNotFoundError:
        return False


# Claude Code's page for a Remote Control session, by its bridge session id.
CLAUDE_CODE_URL = 'https://claude.ai/code/'


def run(argv, ok=True, **options):
    p = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=30, check=False, **options)
    if ok and p.returncode:
        raise Refusal("target_command_failed", argv[0] + " failed")
    return p


class Refusal(Exception):
    def __init__(self, code, message):
        self.code, self.message = code, message


def require(value, code, message):
    if not value:
        raise Refusal(code, message)


def git(root, *args):
    return run(["git", "-C", str(root), *args]).stdout.decode().strip()


def zellij(session, *args):
    return run(["zellij", "--session", session, "action", *args]).stdout


def panes(session):
    """The terminal panes of a Claude tab's hub session; none once it has ended."""
    if not session:
        return []
    listed = run(["zellij", "list-sessions", "--no-formatting"], False).stdout.decode().splitlines()
    if not any(line.split(" ", 1)[0] == session and "EXITED" not in line for line in listed):
        return []
    rows = json.loads(zellij(session, "list-panes", "--all", "--json"))
    return [row for row in rows if not row.get("is_plugin")]


def start_session(session, layout):
    """Starts the hub session `hub.<host>.claude-<name>-<id>` in its own user scope, so it outlives this ssh login,
    with the desktop's display so Claude's copy reaches the clipboard."""
    env = dict(os.environ)
    shown = run(["systemctl", "--user", "show-environment"]).stdout.decode().splitlines()
    env.update(line.split("=", 1) for line in shown if line.startswith(("WAYLAND_DISPLAY=", "DISPLAY=")))
    run(["systemd-run", "--user", "--scope", "--quiet", "--collect", "--", "zellij", "attach",
         "--create-background", session, "options", "--default-layout", str(layout),
         "--session-serialization", "false", "--pane-frames", "false"], env=env)


def session_record(receipt):
    """Claude Code's own record for this tab's process: the session id and cwd it names."""
    record = Path(receipt.get("claude_dir") or Path.home() / ".claude") / "sessions" / (str(receipt["process"]["pid"]) + ".json")
    try:
        if record.stat().st_mtime_ns < receipt["process"].get("started_at_ns", 0):
            return None
        return json.loads(record.read_text())
    except (OSError, ValueError):
        return None


def remote_control(receipt):
    """The Remote Control session Claude recorded for this tab's process, if it has one yet."""
    bridge = (session_record(receipt) or {}).get("bridgeSessionId")
    return dict(session_url=CLAUDE_CODE_URL + bridge, bridge_session_id=bridge) if bridge else None


# Each on-demand page has bounded input, output and work, including a malformed line.
TRANSCRIPT_MAX_EVENTS = 256
TRANSCRIPT_MAX_BYTES = 256 * 1024
TRANSCRIPT_MAX_LINE = 128 * 1024


def transcript_page(receipt, since, expected_session=None, expected_source=None):
    """Read only this verified process's transcript. Byte offsets acknowledge whole JSONL frames."""
    record = session_record(receipt) or {}
    session_id, cwd = record.get("sessionId"), record.get("cwd")
    if not session_id or not cwd:
        return dict(unavailable="transcript_not_open")
    require(isinstance(session_id, str) and re.fullmatch(r"[0-9a-f-]{36}", session_id),
            "transcript_identity_mismatch", "invalid Claude session id")
    require(Path(cwd).resolve() == Path(receipt["cwd"]).resolve(),
            "transcript_identity_mismatch", "Claude cwd differs from the owned tab")
    require(expected_session is None or expected_session == session_id,
            "transcript_identity_mismatch", "Claude session changed")
    require(type(since) is int and since >= 0,
            "transcript_cursor_invalid", "invalid transcript cursor")
    project = "".join(c if c.isascii() and c.isalnum() else "-" for c in cwd)
    # Walk without following symlinks: transcript metadata cannot redirect a read to credentials.
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in [*Path(receipt["claude_dir"]).parts[1:], "projects", project]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        transcript = os.open(session_id + ".jsonl", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
    except FileNotFoundError:
        return dict(unavailable="transcript_absent")
    finally:
        os.close(fd)
    with os.fdopen(transcript, "rb") as file:
        info = os.fstat(file.fileno())
        require(stat.S_ISREG(info.st_mode), "transcript_identity_mismatch", "not a transcript file")
        source = dict(device=info.st_dev, inode=info.st_ino)
        require(expected_source is None or expected_source == source,
                "transcript_identity_mismatch", "transcript replaced")
        require(since <= info.st_size, "transcript_cursor_invalid", "transcript shortened")
        if since:
            file.seek(since - 1)
            require(file.read(1) == b"\n", "transcript_cursor_invalid", "cursor is not a frame boundary")
        else:
            file.seek(0)
        events, cursor, consumed = [], since, 0
        while len(events) < TRANSCRIPT_MAX_EVENTS:
            line = file.readline(TRANSCRIPT_MAX_LINE + 1)
            require(len(line) <= TRANSCRIPT_MAX_LINE,
                    "transcript_frame_too_large", "transcript frame exceeds bounded read capacity")
            if not line.endswith(b"\n"):
                break  # Never acknowledge a partially written frame.
            if consumed + len(line) > TRANSCRIPT_MAX_BYTES:
                break
            try:
                frame = json.loads(line)
            except ValueError:
                raise Refusal("transcript_unreadable", "invalid transcript frame")
            require(isinstance(frame, dict) and frame.get("sessionId", session_id) == session_id,
                    "transcript_identity_mismatch", "transcript frame belongs to another session")
            frame["driver_cursor"] = cursor + len(line)
            size = len(json.dumps(frame).encode())
            if consumed + size > TRANSCRIPT_MAX_BYTES:
                break
            cursor += len(line)
            consumed += size
            events.append(frame)
        file.seek(cursor)
        following = file.readline(TRANSCRIPT_MAX_LINE + 1)
        has_more = following.endswith(b"\n") or len(following) > TRANSCRIPT_MAX_LINE
    return dict(session_id=session_id, source=source, events=events, cursor=cursor, has_more=has_more)


def save(directory, receipt):
    fd, name = tempfile.mkstemp(dir=directory)
    try:
        with os.fdopen(fd, "w") as out:
            json.dump(receipt, out)
            out.flush()
            os.fsync(out.fileno())
        os.replace(name, directory / "receipt.json")
        fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def metadata_path(home, relative, directory=False):
    parts = Path(relative).parts
    require(parts and not Path(relative).is_absolute() and '..' not in parts,
            'account_not_signed_in', 'account path escapes home')
    fd = os.open('/', os.O_PATH | os.O_DIRECTORY)
    try:
        components = list(home.parts[1:]) + list(parts)
        for index, part in enumerate(components):
            child = os.open(part, os.O_PATH | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            mode = os.fstat(fd).st_mode
            expected = stat.S_ISDIR if index < len(components) - 1 or directory else stat.S_ISREG
            require(expected(mode), 'account_not_signed_in', 'account path contains a link or invalid component')
    finally:
        os.close(fd)


def account_check(req):
    home = Path.home()
    try:
        if req.get('config_dir'):
            metadata_path(home, req['config_dir'], directory=True)
        for path in req['sign_in']:
            metadata_path(home, path)
    except OSError:
        raise Refusal('account_not_signed_in', req['login_hint'])
    return home


def inspect_worktree(receipt, discard):
    worktree = receipt["worktree"]
    require(Path(worktree).is_dir(), "ownership_mismatch", "owned worktree is absent")
    require(git(worktree, "rev-parse", "--show-toplevel") == worktree,
            "ownership_mismatch", "worktree root changed")
    require(git(worktree, "symbolic-ref", "HEAD") == "refs/heads/" + receipt["branch"],
            "ownership_mismatch", "worktree branch changed")
    common = str(Path(git(worktree, "rev-parse", "--path-format=absolute", "--git-common-dir")).resolve())
    require(common == receipt["common_dir"], "ownership_mismatch", "repository identity changed")
    require(not git(worktree, "status", "--porcelain=v1", "--untracked-files=all", "--ignore-submodules=none"),
            "worktree_dirty", "dirty or untracked files must be preserved")
    head = git(worktree, "rev-parse", "HEAD")
    if head == receipt.get('base_commit'):
        return head
    upstream = run(["git", "-C", worktree, "rev-parse", "--verify", "@{upstream}"], False)
    if not discard:
        require(upstream.returncode == 0, "worktree_no_upstream", "cannot prove commits are pushed without upstream")
        remote = git(worktree, "config", "--get", "branch." + receipt["branch"] + ".remote")
        merge = git(worktree, "config", "--get", "branch." + receipt["branch"] + ".merge")
        require(remote != "." and not remote.startswith("-") and merge == "refs/heads/" + receipt["branch"],
                "worktree_unproved_push", "upstream must be the owned branch on a remote")
        advertised = git(worktree, "ls-remote", "--exit-code", remote, merge).split()
        require(len(advertised) == 2 and advertised[0] == upstream.stdout.decode().strip(),
                "worktree_unproved_push", "remote branch does not match recorded upstream")
        require(git(worktree, "rev-list", "--count", "@{upstream}..HEAD") == "0",
                "worktree_unpushed", "unpushed commits must be preserved")
    return head


def owned_pane(receipt):
    rows = panes(receipt.get("zellij_session"))
    require(len(rows) == 1 and rows[0]["id"] == receipt["pane_id"],
            "ownership_mismatch", "owned session pane changed")
    require(receipt["session"] in rows[0].get("terminal_command", "")
            and rows[0].get("terminal_command") == receipt["terminal_command"],
            "ownership_mismatch", "pane command identity changed")


def scope_status(receipt, absent=False):
    scope = receipt['scope']
    result = run(['systemctl', '--user', 'show', scope['unit'], '--property=InvocationID',
                  '--property=ControlGroup', '--property=LoadState'], False)
    props = dict(line.split('=', 1) for line in result.stdout.decode().splitlines() if '=' in line)
    if absent and props.get('LoadState') == 'not-found':
        return None
    require(props.get('InvocationID') == scope['invocation_id'] and
            props.get('ControlGroup') == scope['control_group'],
            'ownership_mismatch', 'scope invocation changed')
    group = Path('/sys/fs/cgroup') / scope['control_group'].lstrip('/')
    require('..' not in group.parts and scope['control_group'].startswith('/'),
            'ownership_mismatch', 'invalid scope cgroup')
    if absent and not group.exists():
        return None
    return group


def scope_events(group):
    return dict(line.split() for line in (group / 'cgroup.events').read_text().splitlines())


def process_fence(receipt):
    require(same_process(receipt['process']), 'ownership_mismatch', 'original process identity changed')
    group = scope_status(receipt)
    membership = Path('/proc', str(receipt['process']['pid']), 'cgroup').read_text().splitlines()
    require('0::' + receipt['scope']['control_group'] in membership,
            'ownership_mismatch', 'process left owned scope')
    require(same_process(receipt['process']), 'ownership_mismatch', 'process changed during fence')
    return group


def freeze_owned(receipt):
    owned_pane(receipt)
    process_fence(receipt)
    run(['systemctl', '--user', 'freeze', receipt['scope']['unit']])
    group = scope_status(receipt)
    require(scope_events(group).get('frozen') == '1', 'stop_unproved', 'scope did not freeze')
    process_fence(receipt)
    owned_pane(receipt)
    return group


def thaw_owned(receipt):
    scope_status(receipt)
    run(['systemctl', '--user', 'thaw', receipt['scope']['unit']])


def scope_gone(receipt):
    group = scope_status(receipt, absent=True)
    return group is None or scope_events(group).get('populated') == '0'


def stop_owned(directory, receipt, discard):
    if receipt['phase'] == 'running' and not same_process(receipt['process']):
        require(scope_gone(receipt) and not panes(receipt.get('zellij_session')),
                'ownership_mismatch', 'stale process identity with surviving resources')
        receipt['phase'] = 'pane_stopped'
        save(directory, receipt)
    if receipt['phase'] == 'running':
        try:
            freeze_owned(receipt)
            head = inspect_worktree(receipt, discard) if receipt['owns_worktree'] else None
            process_fence(receipt)
            owned_pane(receipt)
            if receipt['owns_worktree']:
                require(inspect_worktree(receipt, discard) == head,
                        'worktree_changed', 'HEAD changed while frozen')
            receipt['phase'] = 'stopping'
            save(directory, receipt)
        except Exception:
            thaw_owned(receipt)
            receipt['phase'] = 'running'
            save(directory, receipt)
            raise
    if receipt['phase'] == 'stopping':
        if not scope_gone(receipt):
            group = scope_status(receipt)
            require(scope_events(group).get('frozen') == '1', 'stop_unproved', 'scope thawed during stop')
            process_fence(receipt)
            owned_pane(receipt)
            if receipt['owns_worktree']:
                try:
                    inspect_worktree(receipt, discard)
                except Exception:
                    thaw_owned(receipt)
                    receipt['phase'] = 'running'
                    save(directory, receipt)
                    raise
            # Kill the frozen cgroup; its pane closes and so ends the session.
            (group / 'cgroup.kill').write_text('1')
            for _ in range(100):
                if scope_gone(receipt):
                    break
                time.sleep(0.05)
            require(scope_gone(receipt), 'stop_unproved', 'owned descendants survive')
        require(not same_process(receipt['process']), 'stop_unproved', 'original process survives')
        for _ in range(100):
            if not panes(receipt.get('zellij_session')):
                break
            time.sleep(0.05)
        require(not panes(receipt.get('zellij_session')), 'stop_unproved', 'owned session survives')
        receipt['phase'] = 'pane_stopped'
        save(directory, receipt)
    require(scope_gone(receipt), 'stop_unproved', 'scope still populated')
    if receipt['owns_worktree'] and Path(receipt['worktree']).exists():
        inspect_worktree(receipt, discard)
        run(['git', '-C', receipt['root'], 'worktree', 'remove', '--', receipt['worktree']])
    receipt['phase'] = 'stopped'
    save(directory, receipt)
    return receipt


def reconcile_launch(directory, receipt, req):
    worktree = receipt['worktree']
    if receipt['phase'] == 'creating_worktree':
        if not (Path(worktree) / '.git').exists():
            if req['op'] == 'stop':
                require(not Path(worktree).exists() or not any(Path(worktree).iterdir()),
                        'ownership_mismatch', 'partial worktree contains files')
                if Path(worktree).exists():
                    Path(worktree).rmdir()
                receipt['phase'] = 'stopped'
                save(directory, receipt)
                return receipt
            require(run(['git', '-C', receipt['root'], 'show-ref', '--verify',
                         'refs/heads/' + receipt['branch']], False).returncode != 0,
                    'ownership_mismatch', 'branch exists without owned worktree')
            run(['git', '-C', receipt['root'], 'worktree', 'add', '-b', receipt['branch'],
                 '--', worktree, receipt['base_commit']])
        # Private session directory was reserved before intent; branch and
        # repository identities must still match the creation intent.
        require(git(worktree, 'symbolic-ref', 'HEAD') == 'refs/heads/' + receipt['branch'] and
                str(Path(git(worktree, 'rev-parse', '--path-format=absolute', '--git-common-dir')).resolve()) == receipt['common_dir'],
                'ownership_mismatch', 'partial worktree identity changed')
        receipt['phase'] = 'creating_tab'
        save(directory, receipt)
    marker = str(directory / 'launch.py')
    rows = panes(receipt['zellij_session'])
    if not rows:
        require(not receipt.get('tab_create_intent') or (directory / 'process.json').exists(),
                'launch_in_doubt', 'terminal creation acknowledgement is unresolved; preserve resources')
        if (directory / 'process.json').exists():
            receipt['process'] = json.loads((directory / 'process.json').read_text())
            receipt['scope'] = receipt['process']['scope']
            require(scope_gone(receipt) and not same_process(receipt['process']),
                    'ownership_mismatch', 'owned process survives without pane')
        if req['op'] == 'stop' or (directory / 'process.json').exists():
            if receipt['owns_worktree'] and Path(worktree).exists():
                inspect_worktree(receipt, req.get('discard_unpushed', False))
                run(['git', '-C', receipt['root'], 'worktree', 'remove', '--', worktree])
            receipt['phase'] = 'stopped'
            save(directory, receipt)
            return receipt
        account_check(req)
        # A single command session lets a lost reply be recovered through the private launch path.
        receipt['tab_create_intent'] = True
        save(directory, receipt)
        start_session(receipt['zellij_session'], directory / 'layout.kdl')
        for _ in range(100):
            rows = panes(receipt['zellij_session'])
            if rows:
                break
            time.sleep(0.05)
    require(len(rows) == 1, 'launch_in_doubt', 'created session not yet visible')
    require(shlex.split(rows[0].get('terminal_command', '')) == ['python3', marker],
            'ownership_mismatch', 'partial session command changed')
    receipt['pane_id'] = rows[0]['id']
    receipt['terminal_command'] = rows[0]['terminal_command']
    save(directory, receipt)
    for _ in range(100):
        if (directory / 'process.json').exists():
            break
        time.sleep(0.05)
    require((directory / 'process.json').exists(), 'launch_in_doubt', 'process receipt not yet available')
    receipt['process'] = json.loads((directory / 'process.json').read_text())
    require(receipt['process']['session'] == receipt['session'], 'ownership_mismatch', 'process session changed')
    receipt['scope'] = receipt['process']['scope']
    process_fence(receipt)
    receipt['phase'] = 'running'
    save(directory, receipt)
    return receipt


def execute(req):
    require(re.fullmatch(r"[0-9a-f-]{36}", req["session"]), "invalid_session", "invalid session identity")
    home = account_check(req) if req["op"] not in ("stop", "read") else Path.home()
    root = Path(req.get('root') or home).expanduser().resolve(strict=True)
    owns_worktree = req.get('owns_worktree', True)
    require(root.is_dir(), "project_unavailable", "project root is absent")
    if req["op"] == "preflight":
        if owns_worktree:
            git(root, 'rev-parse', '--git-common-dir')
        import shutil
        for executable in ('claude', 'bwrap', 'zellij', 'systemctl', 'systemd-run'):
            require(shutil.which(executable) is not None, "target_prerequisite_missing", executable + " is not installed")
        for server in req["mcp"]["mcpServers"].values():
            require(shutil.which(server["command"]) is not None,
                    "mcp_prerequisite_missing", "declared MCP executable is not installed")
        require(Path('/sys/fs/cgroup/cgroup.controllers').is_file(),
                'target_prerequisite_missing', 'cgroup v2 is required')
        return {"ready": True}
    state = home / ".local/state/odin/claude-host"
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(not state.is_symlink() and state.stat().st_uid == os.getuid()
            and state.stat().st_mode & 0o077 == 0,
            "ownership_mismatch", "unsafe host journal root")
    directory = state / req["session"]
    directory.mkdir(mode=0o700, exist_ok=True)
    require(not directory.is_symlink() and directory.stat().st_uid == os.getuid()
            and directory.stat().st_mode & 0o077 == 0,
            "ownership_mismatch", "unsafe session journal")
    lock_fd = os.open(directory / "lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_fd, "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        path = directory / "receipt.json"
        require(not path.is_symlink(), "ownership_mismatch", "unsafe receipt")
        receipt = json.loads(path.read_text()) if path.exists() else None
        if receipt is None and req['op'] == 'stop':
            # Any residue beyond the lock may belong to an interrupted launch.
            require(all(entry.name == 'lock' for entry in directory.iterdir()),
                    'launch_in_doubt', 'journal absent with session artifacts; preserve resources')
            receipt = dict(session=req['session'], root=str(root), phase='stopped', no_effect=True,
                           owns_worktree=False)
            save(directory, receipt)
            return receipt
        if receipt:
            require(receipt["session"] == req["session"] and receipt["root"] == str(root),
                    "ownership_mismatch", "journal does not match request")
        if req["op"] == "read":
            require(receipt is not None, "ownership_mismatch", "no target ownership receipt")
            alive = (receipt["phase"] == "running" and same_process(receipt["process"])
                     and bool(panes(receipt.get("zellij_session"))))
            if alive:
                owned_pane(receipt)
                process_fence(receipt)
            result = dict(alive=alive, remote_control=remote_control(receipt) if alive else None)
            if alive and req.get("transcript"):
                result["transcript"] = transcript_page(
                    receipt, req.get("since", 0), req.get("claude_session_id"), req.get("transcript_source"))
            return result
        if req["op"] == "open":
            if receipt:
                if receipt['phase'].startswith('creating_'):
                    receipt = reconcile_launch(directory, receipt, req)
                require(receipt['phase'] == 'running', 'ownership_mismatch', 'session is not running')
                owned_pane(receipt)
                process_fence(receipt)
                return receipt
            branch = 'claude/' + req['name'] if owns_worktree else None
            worktree = str(directory / 'worktree') if owns_worktree else str(root)
            receipt = dict(session=req['session'], root=str(root), worktree=worktree,
                           branch=branch, account=req['account'], owns_worktree=owns_worktree,
                           unsandboxed=not owns_worktree, cwd=worktree,
                           phase='creating_worktree' if owns_worktree else 'creating_tab',
                           common_dir=None,
                           # every device's hub shows it; the bound keeps zellij's socket path short, and the
                           # session id's tail keeps two names with one 32-character start apart
                           zellij_session='hub.' + socket.gethostname() + '.claude-' + req['name'][:32] + '-' + req['session'][-6:],
                           claude_dir=str(home / (req.get('config_dir') or '.claude')))
            if owns_worktree:
                receipt['common_dir'] = str(Path(git(root, 'rev-parse', '--path-format=absolute', '--git-common-dir')).resolve())
                require(not Path(worktree).exists() and run(['git', '-C', str(root), 'show-ref', '--verify',
                        'refs/heads/' + branch], False).returncode != 0,
                        'ownership_mismatch', 'worktree or branch already exists')
                receipt['base_commit'] = git(root, 'rev-parse', 'HEAD')
            argv = ["env", "-u", "CLAUDE_CONFIG_DIR"]
            if req.get("config_dir"):
                argv.append("CLAUDE_CONFIG_DIR=" + str(home / req["config_dir"]))
            argv += ["claude"]
            argv += ["--remote-control", req["name"]]
            if req.get("model"):
                argv += ["--model", req["model"]]
            if req["skip_permissions"]:
                argv.append("--dangerously-skip-permissions")
            def expand(value):
                if isinstance(value, str):
                    return value.replace("/ODIN_OWNED_WORKTREE", worktree)
                if isinstance(value, list):
                    return [expand(v) for v in value]
                if isinstance(value, dict):
                    return {k: expand(v) for k, v in value.items()}
                return value
            # The MCP config (its declared env values included) never rides
            # argv: it lands in a 0600 file the journal root already owns.
            mcp_path = directory / 'mcp.json'
            mcp_fd = os.open(mcp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            with os.fdopen(mcp_fd, 'w') as out:
                json.dump(expand(req["mcp"]), out)
            argv += ["--strict-mcp-config", "--mcp-config", str(mcp_path)]
            receipt["remote_control"] = req["remote_control"]
            receipt["skip_permissions"] = req["skip_permissions"]
            unit = 'odin-claude-' + req['session'] + '.scope'
            # Record the exec identity inside bubblewrap, without a PID namespace:
            # Claude's sessions/<pid>.json must name the same host PID we fence.
            sandbox = ["bwrap", "--die-with-parent", "--unshare-user",
                       "--ro-bind", "/", "/", "--tmpfs", "/run/media",
                       "--dev-bind", "/dev", "/dev",
                       "--proc", "/proc", "--tmpfs", "/tmp",
                       "--bind", worktree, worktree,
                       "--bind", receipt["claude_dir"], receipt["claude_dir"],
                       "--bind", str(directory), str(directory)]
            account_record = (home / req["config_dir"] / ".claude.json"
                              if req.get("config_dir") else home / ".claude.json")
            if account_record.is_file():
                sandbox += ["--bind", str(account_record), str(account_record)]
            if receipt.get("common_dir"):
                sandbox += ["--bind", receipt["common_dir"], receipt["common_dir"]]
            sandbox += ["--chdir", worktree, "--", "python3", "-c", PROCESS_LAUNCH,
                        str(directory), req["session"], unit, *argv]
            command = ['python3', '-c', PROCESS_LAUNCH, str(directory), req['session'], unit,
                       'outer', PROCESS_LAUNCH, 'sandbox', *sandbox]
            launch = directory / 'launch.py'
            with launch.open('w') as out:
                account_paths = [(path, False) for path in req['sign_in']]
                if req.get('config_dir'):
                    account_paths.append((req['config_dir'], True))
                out.write('account_paths=' + repr(account_paths) + '\n' + LAUNCH_ACCOUNT +
                          '\nos.execvp(' + repr(command[0]) + ',' + repr(command) + ')\n')
                out.flush()
                os.fsync(out.fileno())
            layout = directory / 'layout.kdl'
            with layout.open('w') as out:
                out.write('layout { pane command="python3" cwd=' + json.dumps(worktree) +
                          ' close_on_exit=true { args ' + json.dumps(str(launch)) + '; }; }\n')
                out.flush()
                os.fsync(out.fileno())
            save(directory, receipt)
            return reconcile_launch(directory, receipt, req)
        require(receipt is not None, "ownership_mismatch", "no target ownership receipt")
        if receipt['phase'].startswith('creating_'):
            receipt = reconcile_launch(directory, receipt, req)
        if receipt["phase"] == "stopped":
            return receipt
        return stop_owned(directory, receipt, req.get('discard_unpushed', False))


def main():
    try:
        result = execute(json.loads(sys.stdin.read()))
        print(json.dumps({"ok": result}))
    except Refusal as e:
        print(json.dumps({"error": {"code": e.code, "message": e.message}}))
    except Exception:
        # No command stderr, environment or credential material leaves the target.
        print(json.dumps({"error": {"code": "target_failed", "message": "target operation failed; preserve journal for recovery"}}))


if __name__ == "__main__":
    main()
