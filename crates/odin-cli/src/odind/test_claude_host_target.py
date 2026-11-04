"""Offline safety regressions: temporary repositories only; never launches Claude."""
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

# Fixture commits never read the host's git config, so no signing key is involved.
os.environ.update(
    GIT_CONFIG_GLOBAL=os.devnull,
    GIT_CONFIG_SYSTEM=os.devnull,
    GIT_CONFIG_NOSYSTEM="1",
    GIT_AUTHOR_NAME="Fixture",
    GIT_AUTHOR_EMAIL="fixture@example.invalid",
    GIT_COMMITTER_NAME="Fixture",
    GIT_COMMITTER_EMAIL="fixture@example.invalid",
)

spec = importlib.util.spec_from_file_location("claude_host_target", Path(__file__).with_name("claude_host_target.py"))
backend = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backend)


class GitSafety(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "repo"
        self.root.mkdir()
        self.git("init")
        self.git("commit", "--allow-empty", "-m", "initial")
        self.worktree = Path(self.tmp.name) / "owned"
        self.git("worktree", "add", "-b", "claude/fixture", str(self.worktree))
        self.receipt = dict(root=str(self.root), worktree=str(self.worktree), branch="claude/fixture",
                            common_dir=str(self.root / ".git"))

    def tearDown(self):
        self.tmp.cleanup()

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.root), *args], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def refuses(self, code, discard=False):
        with self.assertRaises(backend.Refusal) as caught:
            backend.inspect_worktree(self.receipt, discard)
        self.assertEqual(caught.exception.code, code)

    def test_no_upstream_refuses_without_explicit_discard(self):
        self.refuses("worktree_no_upstream")
        self.assertTrue(backend.inspect_worktree(self.receipt, True))

    def test_untouched_persisted_base_needs_no_upstream(self):
        self.receipt['base_commit'] = backend.git(self.worktree, 'rev-parse', 'HEAD')
        self.assertEqual(backend.inspect_worktree(self.receipt, False), self.receipt['base_commit'])
        backend.git(self.worktree, 'commit', '--allow-empty', '-m', 'local work')
        self.refuses('worktree_no_upstream')

    def test_normal_stop_preserves_dirty_checkout_and_branch(self):
        tracked = self.root / 'tracked'
        tracked.write_text('committed')
        self.git('add', 'tracked')
        self.git('commit', '-m', 'tracked fixture')
        tracked.write_text('human changes')
        untracked = self.root / 'untracked'
        untracked.write_text('human untracked')
        before = self.git('status', '--porcelain=v1').stdout
        branch = self.git('symbolic-ref', 'HEAD').stdout
        receipt = dict(phase='running', owns_worktree=False, worktree=str(self.root), root=str(self.root),
                       process={}, pane_id=4)
        with patch.object(backend, 'same_process', return_value=False), \
                patch.object(backend, 'scope_gone', return_value=True), patch.object(backend, 'panes', return_value=[]):
            result = backend.stop_owned(Path(self.tmp.name), receipt, False)
        self.assertEqual(result['phase'], 'stopped')
        self.assertEqual(tracked.read_text(), 'human changes')
        self.assertEqual(untracked.read_text(), 'human untracked')
        self.assertEqual(self.git('status', '--porcelain=v1').stdout, before)
        self.assertEqual(self.git('symbolic-ref', 'HEAD').stdout, branch)

    def test_untracked_never_discarded(self):
        (self.worktree / "human-work").write_text("preserve")
        self.refuses("worktree_dirty", True)
        self.assertTrue((self.worktree / "human-work").exists())

    def test_branch_switch_refuses(self):
        backend.git(self.worktree, "checkout", "-b", "foreign")
        self.refuses("ownership_mismatch", True)

    def test_push_then_new_commit_refuses(self):
        remote = Path(self.tmp.name) / "remote.git"
        subprocess.run(["git", "init", "--bare", str(remote)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        backend.git(self.worktree, "remote", "add", "origin", str(remote))
        backend.git(self.worktree, "push", "-u", "origin", "claude/fixture")
        self.assertTrue(backend.inspect_worktree(self.receipt, False))
        backend.git(self.worktree, "commit", "--allow-empty", "-m", "unpushed")
        self.refuses("worktree_unpushed")

    def test_foreign_pane_refuses_before_action(self):
        receipt = dict(session="token", zellij_session="hub.pc.claude-token", pane_id=9, terminal_command="token")
        rows = [dict(id=9, terminal_command="token"), dict(id=10)]
        with patch.object(backend, "panes", return_value=rows):
            with self.assertRaises(backend.Refusal) as caught:
                backend.owned_pane(receipt)
            self.assertEqual(caught.exception.code, "ownership_mismatch")

    def test_account_check_does_not_read_credentials(self):
        with patch.object(backend.Path, "home", return_value=Path(self.tmp.name)):
            for name in ("credential", "record"):
                (Path(self.tmp.name) / name).touch()
            with patch.object(backend.Path, "read_text", side_effect=AssertionError("credential read")):
                backend.account_check(dict(sign_in=["credential", "record"], login_hint="login"))

    def test_reused_pid_is_not_owned_process(self):
        identity = dict(pid=42, start_time="100", boot_id="boot")
        stat = "42 (command with spaces) " + " ".join(["0"] * 19 + ["101"])
        with patch.object(backend.Path, "read_text", side_effect=["boot", stat]):
            self.assertFalse(backend.same_process(identity))

    def test_missing_account_record_refuses(self):
        with patch.object(backend.Path, "home", return_value=Path(self.tmp.name)):
            with self.assertRaises(backend.Refusal) as caught:
                backend.account_check(dict(sign_in=["missing"], login_hint="on target: claude, then /login"))
            self.assertEqual(caught.exception.code, "account_not_signed_in")
            self.assertIn("on target", caught.exception.message)


class LifecycleFaults(unittest.TestCase):
    def test_stop_before_backend_journal_returns_positive_no_effect(self):
        with tempfile.TemporaryDirectory() as tmp:
            req = dict(op='stop', session='00000000-0000-0000-0000-000000000001', root=tmp)
            with patch.object(backend.Path, 'home', return_value=Path(tmp)), \
                    patch.object(backend, 'run') as commands, patch.object(backend, 'zellij') as terminal:
                result = backend.execute(req)
                self.assertTrue(result['no_effect'])
                self.assertEqual(result['phase'], 'stopped')
                self.assertFalse(result['owns_worktree'])
                self.assertEqual(backend.execute(req), result)
                commands.assert_not_called()
                terminal.assert_not_called()

    def test_absent_journal_with_any_residue_is_not_no_effect(self):
        for artifact in ('launch.py', 'layout.kdl', 'mcp.json', 'process.pending', 'process.json', 'worktree', 'unexpected'):
            with self.subTest(artifact=artifact), tempfile.TemporaryDirectory() as tmp:
                session = '00000000-0000-0000-0000-000000000001'
                directory = Path(tmp) / '.local/state/odin/claude-host' / session
                directory.mkdir(mode=0o700, parents=True)
                directory.parent.chmod(0o700)
                residue = directory / artifact
                residue.write_text('preserve')
                req = dict(op='stop', session=session, root=tmp, owns_worktree=False)
                with patch.object(backend.Path, 'home', return_value=Path(tmp)), patch.object(backend, 'run') as commands:
                    with self.assertRaises(backend.Refusal) as caught:
                        backend.execute(req)
                    self.assertEqual(caught.exception.code, 'launch_in_doubt')
                    self.assertEqual(residue.read_text(), 'preserve')
                    self.assertFalse((directory / 'receipt.json').exists())
                    commands.assert_not_called()

    def test_process_receipt_read_failure_is_retryable(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            receipt = dict(phase='creating_tab', session='token', zellij_session='owned', worktree=tmp)
            (directory / 'process.json').write_text(backend.json.dumps(dict(session='token', scope={})))
            rows = [dict(id=4, terminal_command='python3 ' + str(directory / 'launch.py'))]
            with patch.object(backend, 'panes', return_value=rows), \
                    patch.object(backend.Path, 'read_text', side_effect=OSError('read fault')):
                with self.assertRaises(OSError):
                    backend.reconcile_launch(directory, receipt, {'op': 'open'})
            with patch.object(backend, 'panes', return_value=rows), \
                    patch.object(backend, 'process_fence'), patch.object(backend, 'zellij') as terminal:
                self.assertEqual(backend.reconcile_launch(directory, receipt, {'op': 'open'})['phase'], 'running')
                terminal.assert_not_called()

    def test_a_session_with_a_foreign_pane_is_not_adopted(self):
        with tempfile.TemporaryDirectory() as tmp:
            receipt = dict(phase='creating_tab', worktree=tmp, zellij_session='owned')
            with patch.object(backend, 'panes', return_value=[dict(id=0, terminal_command='python3 elsewhere')]), \
                    patch.object(backend, 'zellij') as terminal:
                with self.assertRaises(backend.Refusal):
                    backend.reconcile_launch(Path(tmp), receipt, {'op': 'open'})
                terminal.assert_not_called()

    def test_changed_boot_or_start_time_never_closes_same_pane(self):
        for boot, start in [('new-boot', '100'), ('boot', '101')]:
            identity = dict(pid=42, boot_id='boot', start_time='100')
            receipt = dict(phase='running', process=identity, owns_worktree=False)
            proc_stat = '42 (claude) ' + ' '.join(['0'] * 19 + [start])
            with self.subTest(boot=boot, start=start), patch.object(backend.Path, 'read_text', side_effect=[boot, proc_stat]), \
                    patch.object(backend, 'scope_gone', return_value=False), patch.object(backend, 'zellij') as terminal:
                with self.assertRaises(backend.Refusal):
                    backend.stop_owned(Path('/unused'), receipt, False)
                terminal.assert_not_called()

    def test_failed_worktree_command_can_be_stopped(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            receipt = dict(phase='creating_worktree', root=tmp, worktree=str(directory / 'worktree'),
                           branch='claude/test', base_commit='base', owns_worktree=True)
            commands = [subprocess.CompletedProcess([], 1, b''), backend.Refusal('target_command_failed', 'add failed')]
            with patch.object(backend, 'run', side_effect=commands):
                with self.assertRaises(backend.Refusal):
                    backend.reconcile_launch(directory, receipt, {'op': 'open'})
            self.assertEqual(backend.reconcile_launch(directory, receipt, {'op': 'stop'})['phase'], 'stopped')

    def test_delayed_session_acknowledgement_never_creates_a_second_session(self):
        with tempfile.TemporaryDirectory() as tmp:
            receipt = dict(phase='creating_tab', worktree=tmp, zellij_session='owned', owns_worktree=False)
            with patch.object(backend, 'panes', return_value=[]), patch.object(backend, 'account_check'), \
                    patch.object(backend, 'start_session', side_effect=backend.Refusal('target_command_failed', 'lost reply')):
                with self.assertRaises(backend.Refusal):
                    backend.reconcile_launch(Path(tmp), receipt, {'op': 'open'})
            self.assertEqual(receipt['phase'], 'creating_tab')
            self.assertTrue(receipt['tab_create_intent'])
            for operation in ('open', 'stop'):
                with self.subTest(operation=operation), patch.object(backend, 'panes', return_value=[]), \
                        patch.object(backend, 'start_session') as terminal, patch.object(backend, 'run') as commands:
                    with self.assertRaises(backend.Refusal) as caught:
                        backend.reconcile_launch(Path(tmp), receipt, {'op': operation})
                    self.assertEqual(caught.exception.code, 'launch_in_doubt')
                    terminal.assert_not_called()
                    commands.assert_not_called()

    def test_account_component_links_and_escape_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            (home / 'real').mkdir()
            (home / 'real' / 'record').touch()
            (home / 'linked').symlink_to(home / 'real', target_is_directory=True)
            (home / 'record').symlink_to(home / 'real' / 'record')
            for path in ('linked/record', 'record', '../outside', str(home / 'real' / 'record')):
                with self.subTest(path=path), patch.object(backend.Path, 'home', return_value=home):
                    with self.assertRaises(backend.Refusal):
                        backend.account_check(dict(sign_in=[path], login_hint='login'))

    def test_launch_revalidation_rejects_swapped_parent(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            (home / 'account').mkdir()
            (home / 'account' / 'record').touch()
            with patch.object(backend.Path, 'home', return_value=home):
                req = dict(sign_in=['account/record'], login_hint='login')
                backend.account_check(req)
                (home / 'account').rename(home / 'other')
                (home / 'account').symlink_to(home / 'other')
                with self.assertRaises(backend.Refusal):
                    backend.account_check(req)

    def test_stale_pid_fences_stop_before_any_destructive_action(self):
        receipt = dict(phase='running', process={}, owns_worktree=True)
        with patch.object(backend, 'scope_gone', return_value=False), patch.object(backend, 'owned_pane'), patch.object(backend, 'same_process', return_value=False), \
                patch.object(backend, 'thaw_owned'), patch.object(backend, 'zellij') as terminal, \
                patch.object(backend, 'save'), patch.object(backend, 'inspect_worktree') as inspect:
            with self.assertRaises(backend.Refusal):
                backend.stop_owned(Path('/unused'), receipt, False)
            terminal.assert_not_called()
            inspect.assert_not_called()

    def test_dirty_remote_failure_and_head_race_thaw_without_close(self):
        cases = [[backend.Refusal('worktree_dirty', 'dirty')],
                 [backend.Refusal('target_command_failed', 'remote unavailable')], ['before', 'after']]
        for results in cases:
            receipt = dict(phase='running', owns_worktree=True, process={})
            with self.subTest(results=results), patch.object(backend, 'same_process', return_value=True), patch.object(backend, 'freeze_owned') as freeze, \
                    patch.object(backend, 'process_fence'), patch.object(backend, 'owned_pane'), \
                    patch.object(backend, 'inspect_worktree', side_effect=results), \
                    patch.object(backend, 'save'), patch.object(backend, 'thaw_owned') as thaw, patch.object(backend, 'zellij') as terminal:
                with self.assertRaises(backend.Refusal):
                    backend.stop_owned(Path('/unused'), receipt, False)
                freeze.assert_called_once()
                thaw.assert_called_once()
                terminal.assert_not_called()

    def test_surviving_descendants_prevent_removal(self):
        with tempfile.TemporaryDirectory() as tmp:
            receipt = dict(phase='stopping', owns_worktree=True)
            with patch.object(backend, 'scope_gone', return_value=False), \
                    patch.object(backend, 'scope_status', return_value=Path(tmp)), \
                    patch.object(backend, 'scope_events', return_value={'frozen': '1', 'populated': '1'}), \
                    patch.object(backend, 'process_fence'), patch.object(backend, 'owned_pane'), \
                    patch.object(backend, 'inspect_worktree'), \
                    patch.object(backend.time, 'sleep'), patch.object(backend, 'run') as commands:
                with self.assertRaises(backend.Refusal):
                    backend.stop_owned(Path(tmp), receipt, True)
                commands.assert_not_called()

    def test_new_scope_invocation_cannot_be_adopted(self):
        receipt = dict(scope=dict(unit='owned.scope', invocation_id='original', control_group='/owned'))
        result = subprocess.CompletedProcess([], 0, b'InvocationID=replacement\nControlGroup=/owned\nLoadState=loaded\n')
        with patch.object(backend, 'run', return_value=result):
            with self.assertRaises(backend.Refusal):
                backend.scope_gone(receipt)

    def test_normal_stop_never_inspects_or_removes_checkout(self):
        receipt = dict(phase='running', owns_worktree=False, pane_id=4, process={})
        with tempfile.TemporaryDirectory() as tmp, patch.object(backend, 'freeze_owned'), \
                patch.object(backend, 'process_fence'), patch.object(backend, 'owned_pane'), \
                patch.object(backend, 'scope_gone', return_value=True), \
                patch.object(backend, 'same_process', return_value=False), patch.object(backend, 'panes', return_value=[]), \
                patch.object(backend, 'inspect_worktree') as inspect, patch.object(backend, 'run') as commands:
            self.assertEqual(backend.stop_owned(Path(tmp), receipt, False)['phase'], 'stopped')
            inspect.assert_not_called()
            commands.assert_not_called()

    def test_lost_launch_reply_reconciles_without_second_launch(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            receipt = dict(phase='creating_tab', session='token', zellij_session='hub.pc.claude-token', worktree=tmp)
            process = dict(session='token', scope={})
            (directory / 'process.json').write_text(backend.json.dumps(process))
            rows = [dict(id=4, terminal_command='python3 ' + str(directory / 'launch.py'))]
            with patch.object(backend, 'panes', return_value=rows), \
                    patch.object(backend, 'process_fence'), patch.object(backend, 'zellij') as terminal:
                self.assertEqual(backend.reconcile_launch(directory, receipt, {'op': 'open'})['phase'], 'running')
                terminal.assert_not_called()

    def test_failed_final_save_reconciles_process_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            receipt = dict(phase='creating_tab', session='token', zellij_session='hub.pc.claude-token', worktree=tmp)
            (directory / 'process.json').write_text(backend.json.dumps(dict(session='token', scope={})))
            rows = [dict(id=4, terminal_command='python3 ' + str(directory / 'launch.py'))]
            with patch.object(backend, 'panes', return_value=rows), \
                    patch.object(backend, 'process_fence'), patch.object(backend, 'save', side_effect=[None, OSError('disk')]):
                with self.assertRaises(OSError):
                    backend.reconcile_launch(directory, receipt, {'op': 'open'})
            receipt['phase'] = 'creating_tab'
            with patch.object(backend, 'panes', return_value=rows), \
                    patch.object(backend, 'process_fence'), patch.object(backend, 'zellij') as terminal:
                self.assertEqual(backend.reconcile_launch(directory, receipt, {'op': 'open'})['phase'], 'running')
                terminal.assert_not_called()


class Read(unittest.TestCase):
    """`read` reports whether the tab's Claude still runs, and its Remote Control session."""

    def test_a_live_tab_reports_its_remote_control_session(self):
        with tempfile.TemporaryDirectory() as tmp:
            sessions = Path(tmp) / 'sessions'
            sessions.mkdir()
            (sessions / '42.json').write_text(json.dumps(dict(pid=42, bridgeSessionId='session_01abc')))
            receipt = dict(phase='running', process=dict(pid=42), zellij_session='hub.pc.claude-x', claude_dir=tmp)
            self.assertEqual(backend.remote_control(receipt),
                             dict(session_url='https://claude.ai/code/session_01abc', bridge_session_id='session_01abc'))
            receipt['process']['pid'] = 43
            self.assertIsNone(backend.remote_control(receipt))

    def test_a_gone_tab_reads_as_not_alive(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = '00000000-0000-0000-0000-000000000007'
            directory = Path(tmp) / '.local/state/odin/claude-host' / session
            directory.mkdir(mode=0o700, parents=True)
            directory.parent.chmod(0o700)
            receipt = dict(session=session, root=tmp, phase='running', process=dict(pid=42),
                           zellij_session='hub.pc.claude-x')
            (directory / 'receipt.json').write_text(json.dumps(receipt))
            with patch.object(backend.Path, 'home', return_value=Path(tmp)), \
                    patch.object(backend, 'same_process', return_value=True), \
                    patch.object(backend, 'panes', return_value=[]):
                self.assertEqual(backend.execute(dict(op='read', session=session, root=tmp)),
                                 dict(alive=False, remote_control=None))


class TranscriptReads(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.session = "00000000-0000-0000-0000-000000000042"
        self.cwd = str(self.home / "checkout")
        claude = self.home / ".claude"
        (claude / "sessions").mkdir(parents=True)
        (claude / "sessions/42.json").write_text(json.dumps(
            dict(pid=42, sessionId=self.session, cwd=self.cwd)))
        project = "".join(c if c.isascii() and c.isalnum() else "-" for c in self.cwd)
        directory = claude / "projects" / project
        directory.mkdir(parents=True)
        self.path = directory / (self.session + ".jsonl")
        self.receipt = dict(process=dict(pid=42), claude_dir=str(claude), cwd=self.cwd)

    def tearDown(self):
        self.tmp.cleanup()

    def frame(self, text):
        return (json.dumps(dict(type="assistant", sessionId=self.session,
                               message=dict(role="assistant", content=text))) + "\n").encode()

    def test_pages_acknowledge_only_whole_frames_and_resume_without_duplicates(self):
        first, second = self.frame("first"), self.frame("second")
        self.path.write_bytes(first + second[:-1])
        page = backend.transcript_page(self.receipt, 0)
        self.assertEqual(page["cursor"], len(first))
        self.assertEqual(len(page["events"]), 1)
        self.assertFalse(page["has_more"])
        self.path.write_bytes(first + second)
        next_page = backend.transcript_page(self.receipt, page["cursor"], self.session, page["source"])
        self.assertEqual(next_page["cursor"], len(first + second))
        self.assertEqual([e["message"]["content"] for e in next_page["events"]], ["second"])

    def test_event_and_byte_bounds_offer_a_next_page(self):
        self.path.write_bytes(self.frame("bounded") * (backend.TRANSCRIPT_MAX_EVENTS + 1))
        page = backend.transcript_page(self.receipt, 0)
        self.assertEqual(len(page["events"]), backend.TRANSCRIPT_MAX_EVENTS)
        self.assertTrue(page["has_more"])
        self.assertLess(len(json.dumps(page)), backend.TRANSCRIPT_MAX_BYTES)

    def test_oversized_frame_is_not_truncated_or_acknowledged(self):
        self.path.write_bytes(b"x" * (backend.TRANSCRIPT_MAX_LINE + 10))
        with self.assertRaises(backend.Refusal) as caught:
            backend.transcript_page(self.receipt, 0)
        self.assertEqual(caught.exception.code, "transcript_frame_too_large")

    def test_session_cwd_source_and_boundary_are_verified(self):
        self.path.write_bytes(self.frame("owned"))
        for since, expected, source in [
            (0, "another-session", None),
            (1, self.session, None),
            (0, self.session, dict(device=-1, inode=-1)),
        ]:
            with self.subTest(since=since, expected=expected, source=source), self.assertRaises(backend.Refusal):
                backend.transcript_page(self.receipt, since, expected, source)
        self.receipt["cwd"] = "/another/checkout"
        with self.assertRaises(backend.Refusal):
            backend.transcript_page(self.receipt, 0)

    def test_symlink_transcript_cannot_read_another_file(self):
        private = self.home / "private"
        private.write_bytes(self.frame("secret"))
        self.path.symlink_to(private)
        with self.assertRaises(OSError):
            backend.transcript_page(self.receipt, 0)

    def test_liveness_read_does_not_read_transcripts(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = self.session
            directory = Path(tmp) / ".local/state/odin/claude-host" / session
            directory.mkdir(mode=0o700, parents=True)
            directory.parent.chmod(0o700)
            receipt = dict(session=session, root=tmp, phase="running", process=dict(pid=42),
                           zellij_session="hub.pc.claude-x")
            (directory / "receipt.json").write_text(json.dumps(receipt))
            with patch.object(backend.Path, "home", return_value=Path(tmp)), \
                    patch.object(backend, "same_process", return_value=True), \
                    patch.object(backend, "panes", return_value=[{}]), \
                    patch.object(backend, "owned_pane"), patch.object(backend, "process_fence"), \
                    patch.object(backend, "transcript_page") as transcript:
                backend.execute(dict(op="read", session=session, root=tmp))
                transcript.assert_not_called()


class ArgumentHygiene(unittest.TestCase):
    """The request and the MCP config must never ride argv (`ps` on either host)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.session = '00000000-0000-0000-0000-000000000042'
        self.directory = self.home / '.local/state/odin/claude-host' / self.session

    def tearDown(self):
        self.tmp.cleanup()

    def open_request(self):
        return dict(op='open', session=self.session, root=self.tmp.name, name='fixture',
                    account='default', sign_in=[], login_hint='on target',
                    remote_control=True, skip_permissions=False, owns_worktree=False,
                    discard_unpushed=False,
                    mcp={"mcpServers": {"fs": {"type": "stdio", "command": "/bin/mcp-server-filesystem",
                                                "args": ["/ODIN_OWNED_WORKTREE/data"],
                                                "env": {"MCP_TOKEN": "SECRET-VALUE-7f3a"}}}})

    def test_main_reads_the_request_from_stdin(self):
        seen = []
        with patch.object(backend, 'execute', side_effect=lambda req: seen.append(req) or {'ready': True}), \
                patch('sys.stdin', io.StringIO('{"op": "preflight"}')), \
                patch('sys.stdout', new_callable=io.StringIO) as out:
            backend.main()
        self.assertEqual(seen, [dict(op='preflight')])
        self.assertIn('"ready"', out.getvalue())

    def test_open_launch_argv_carries_no_mcp_config(self):
        with patch.object(backend.Path, 'home', return_value=self.home), \
                patch.object(backend, 'save'), \
                patch.object(backend, 'reconcile_launch',
                             side_effect=backend.Refusal('captured', 'stop after argv build')):
            with self.assertRaises(backend.Refusal) as caught:
                backend.execute(self.open_request())
        self.assertEqual(caught.exception.code, 'captured')
        launch = (self.directory / 'launch.py').read_text()
        self.assertIn("'--mcp-config', '" + str(self.directory / 'mcp.json') + "'", launch)
        self.assertNotIn('SECRET-VALUE-7f3a', launch)
        self.assertIn("'bwrap'", launch)
        self.assertIn("'--ro-bind', '/', '/', '--tmpfs', '/run/media'", launch)
        self.assertIn("'--remote-control', 'fixture'", launch)
        # An unpinned tab passes no model or effort; an explicit model
        # choice is the one override that reaches argv.
        self.assertNotIn("'--model'", launch)
        self.assertNotIn("'--effort'", launch)
        pinned = self.open_request()
        pinned['model'] = 'claude-opus-5-5'
        with patch.object(backend.Path, 'home', return_value=self.home), \
                patch.object(backend, 'save'), \
                patch.object(backend, 'reconcile_launch',
                             side_effect=backend.Refusal('captured', 'stop after argv build')):
            with self.assertRaises(backend.Refusal):
                backend.execute(pinned)
        pinned_launch = (self.directory / 'launch.py').read_text()
        self.assertIn("'--model', 'claude-opus-5-5'", pinned_launch)
        self.assertNotIn('mcpServers', launch)
        mcp = self.directory / 'mcp.json'
        self.assertEqual(mcp.stat().st_mode & 0o077, 0)
        written = json.loads(mcp.read_text())
        resolved = str(Path(self.tmp.name).resolve())
        self.assertEqual(written["mcpServers"]["fs"]["args"], [resolved + "/data"])
        self.assertEqual(written["mcpServers"]["fs"]["env"]["MCP_TOKEN"], "SECRET-VALUE-7f3a")


if __name__ == "__main__":
    unittest.main()
