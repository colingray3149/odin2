"""Runner checks use local fixtures and never contact Odin."""

import importlib.util
import io
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("scenarios", ROOT / "tools/scenarios/run.py")
RUN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUN)


class RunnerChecks(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.executescript(
            "CREATE TABLE live_events(session_id TEXT, sequence INTEGER, body_json TEXT);"
            "CREATE TABLE live_sessions(session_id TEXT, seat_id TEXT);"
            "CREATE TABLE operation_journal(capability TEXT, effect_state TEXT);"
        )
        self.addCleanup(self.db.close)
        self.query = patch.object(RUN, "ledger", self.ledger)
        self.query.start()
        self.addCleanup(self.query.stop)
        self.no_sleep = patch.object(RUN.time, "sleep", side_effect=AssertionError("unexpected sleep"))
        self.no_sleep.start()
        self.addCleanup(self.no_sleep.stop)
        self.zero_wait = patch.object(RUN, "WAIT", 0)
        self.zero_wait.start()
        self.addCleanup(self.zero_wait.stop)

    def ledger(self, sql):
        return "\n".join("|".join(str(value) for value in row) for row in self.db.execute(sql))

    def event(self, session, sequence, body):
        self.db.execute("INSERT INTO live_events VALUES (?, ?, ?)", (session, sequence, json.dumps(body)))

    def prompt(self, session, sequence, text):
        self.event(session, sequence, {"kind": "command_issued", "frame": {"type": "prompt", "message": text}})

    def reply(self, session, sequence, text, kind="text"):
        self.event(session, sequence, {"frame": {
            "type": "message_end", "message": {"role": "assistant", "content": [{"type": kind, "text": text}]},
        }})

    def created(self):
        return {"jobs": [], "routines": [], "refs": [], "started": datetime(2026, 1, 1, 12).timestamp()}

    def execute(self, row, reply="", created=None):
        with patch.object(RUN, "say", return_value=reply):
            return RUN.execute(row, RUN.RECIPES[row], "acc-fixture", "acc-routine", created or self.created())

    def test_cleanup_discovers_only_explicit_repository_effects(self):
        self.assertEqual(RUN.owned_projects(["say:read a repository", "routine:example", "expect:git:foreign"]), [])
        self.assertEqual(RUN.owned_projects(["git:one:tag", "gitfile:two:tag:text", "gitnonempty:four:tag", "gitkeep:one:tag", "merge:three:tag"]), ["one", "two", "four", "three"])

    def test_owner_reply_excludes_foreign_sessions_old_replies_thinking_and_later_prompts(self):
        self.db.executemany("INSERT INTO live_sessions VALUES (?, ?)", [("owner", "sinmara"), ("old-owner", "sinmara"), ("worker", "kubert")])
        self.reply("owner", 100, "PASSED earlier")
        self.prompt("owner", 101, "GPU job [acc-gpu]")
        self.prompt("worker", 1, "GPU job [acc-gpu]")
        self.reply("worker", 900, "PASSED")
        self.reply("old-owner", 900, "PASSED")
        self.reply("owner", 102, "PASSED", "thinking")
        self.assertEqual(RUN.owner_replies("acc-gpu"), [])
        self.reply("owner", 103, "The GPU job passed.\nResult complete.")
        self.prompt("owner", 104, "unrelated")
        self.reply("owner", 105, "unrelated result")
        self.assertEqual(RUN.owner_replies("acc-gpu"), ["The GPU job passed.\nResult complete."])

    def test_active_pending_pod_is_not_a_running_job(self):
        for state in ("pending", "scheduling", "suspended", "succeeded", "failed", ""):
            with self.subTest(state=state):
                self.assertFalse(RUN.job_in_phase({"state": state, "active": 1}, "running"))
        self.assertTrue(RUN.job_in_phase({"state": "running", "active": 1}, "running"))

    def test_casual_requires_greeting_word(self):
        self.execute("chat.casual", "Hi!")
        for reply in ("This is something.", "highway", "they arrived"):
            with self.subTest(reply=reply), self.assertRaisesRegex(RuntimeError, "reply missed"):
                self.execute("chat.casual", reply)

    def test_yesterday_requires_actual_local_date(self):
        for reply in ("2025-12-31", "December 31", "31 Dec", "Dec. 31"):
            with self.subTest(reply=reply):
                self.execute("memory.yesterday", reply)
        for reply in ("yesterday", "2026-01-01", "December 30", "December 310"):
            with self.subTest(reply=reply), self.assertRaisesRegex(RuntimeError, "local date"):
                self.execute("memory.yesterday", reply)

    def test_failed_web_load_requires_new_read_and_precise_failure(self):
        self.db.execute("INSERT INTO operation_journal VALUES ('web.read', 'committed')")
        with self.assertRaisesRegex(RuntimeError, "no new web.read"):
            self.execute("chat.web-failed-load", "could not load")
        def answer(*args):
            self.db.execute("INSERT INTO operation_journal VALUES ('web.read', 'aborted')")
            return "The page could not load."
        with patch.object(RUN, "say", side_effect=answer):
            RUN.execute("chat.web-failed-load", RUN.RECIPES["chat.web-failed-load"], "acc-fixture", "acc-routine", self.created())
        def vague(*args):
            answer()
            return "Something failed."
        with patch.object(RUN, "say", side_effect=vague), self.assertRaisesRegex(RuntimeError, "reply missed"):
            RUN.execute("chat.web-failed-load", RUN.RECIPES["chat.web-failed-load"], "acc-fixture", "acc-routine", self.created())

    def test_correction_waits_for_delayed_odin_readme_reply(self):
        self.db.execute("INSERT INTO live_sessions VALUES ('owner', 'sinmara')")
        self.prompt("owner", 1, "read README [acc-fixture]")
        with tempfile.TemporaryDirectory() as directory:
            checkout = Path(directory)
            (checkout / "README.md").write_text("# Actual Odin\nSecond line\n")
            def delayed(_seconds):
                self.reply("owner", 2, "The line is # Actual Odin")
            with patch.object(RUN, "require_checkout", return_value=checkout), patch.object(RUN, "WAIT", 10), patch.object(RUN.time, "sleep", side_effect=delayed) as sleeper:
                self.execute("chat.correction", "Delegated the read.")
                self.assertEqual(sleeper.call_count, 1)
            self.db.execute("DELETE FROM live_events WHERE sequence=2")
            with patch.object(RUN, "require_checkout", return_value=checkout), self.assertRaisesRegex(RuntimeError, "first line"):
                self.execute("chat.correction", "Second line")

    def test_research_requires_two_scores_and_nonempty_branch_diff(self):
        with self.assertRaisesRegex(RuntimeError, "fewer than 2"):
            self.execute("lifecycle.research-implementation", "random baseline 1")
        with patch.object(RUN, "wait_refs", return_value=["refs/heads/acc-routine"]), patch.object(RUN, "require_checkout", return_value=Path("/fixture")):
            for diff in ("", "   ", "+policy()"):
                def git(args, **kwargs):
                    return subprocess.CompletedProcess(args, 0, diff if "diff" in args else "", "")
                with self.subTest(diff=diff), patch.object(RUN, "run", side_effect=git):
                    if diff.strip():
                        self.execute("lifecycle.research-implementation", "policy 2.5, random baseline 1.2")
                    else:
                        with self.assertRaisesRegex(RuntimeError, "no changes"):
                            self.execute("lifecycle.research-implementation", "policy 2.5, random baseline 1.2")

    def test_job_attribution_uses_only_name_or_labels(self):
        items = [
            {"metadata": {"uid": "name", "name": "acc-fixture-job"}},
            {"metadata": {"uid": "label", "name": "job", "labels": {"scenario": "acc-fixture"}}},
            {"metadata": {"uid": "foreign", "name": "other", "annotations": {"scenario": "acc-fixture"}}, "spec": {"tag": "acc-fixture"}},
        ]
        result = subprocess.CompletedProcess([], 0, json.dumps({"items": items}), "")
        with patch.object(RUN, "ssh", return_value=result), patch.object(RUN, "huginn", return_value={}):
            created = self.created()
            RUN.note_jobs(created, "acc-fixture")
            RUN.note_jobs(created, "acc-fixture")
        self.assertEqual([job["uid"] for job in created["jobs"]], ["name", "label"])

    def test_repo_push_registers_cleanup_even_if_publication_check_fails(self):
        created = self.created()
        with patch.object(RUN, "odin_published", side_effect=RuntimeError("publication failed")), self.assertRaisesRegex(RuntimeError, "publication failed"):
            self.execute("routine.repo-push", "Created.", created)
        self.assertEqual(created["routines"], ["acc-routine"])
        missing = subprocess.CompletedProcess([], 128, "", "fatal: path does not exist")
        with patch.object(RUN, "say") as say, patch.object(RUN, "fetch_odin_main"), patch.object(RUN, "ssh", return_value=missing), patch.object(RUN, "schedule_rows", return_value=[]), patch.object(RUN, "memory_has", return_value=False):
            self.assertEqual(RUN.cleanup("acc-fixture", "acc-routine", created), [])
        say.assert_called_once_with("Remove routine acc-routine.", 0)

    def test_sessionseat_requires_fresh_live_session_and_new_ask(self):
        created = self.created()
        created["started"] = datetime(2026, 1, 1, 12, tzinfo=RUN.timezone.utc).timestamp()
        session = {"seatId": "kubert", "state": "running", "startedAt": [2026, 1, 12, 0, 1, 0, 0, 0, 0]}
        snapshot = {"value": {"objects": [session]}}
        self.db.execute("INSERT INTO operation_journal VALUES ('seat.ask.kubert', 'committed')")
        def ask(*args):
            self.db.execute("INSERT INTO operation_journal VALUES ('seat.ask.kubert', 'committed')")
            return "Kubert is checking."
        with patch.object(RUN, "huginn", return_value=snapshot):
            with self.assertRaisesRegex(RuntimeError, "no new committed"):
                self.execute("seat.ask-kubert", created=created)
            for started, state in (([2025, 365, 12, 0, 0, 0, 0, 0, 0], "running"), ([2026, 1, 12, 0, 1, 0, 0, 0, 0], "ended")):
                session.update(startedAt=started, state=state)
                with patch.object(RUN, "say", side_effect=ask), self.assertRaisesRegex(RuntimeError, "no fresh live"):
                    RUN.execute("seat.ask-kubert", RUN.RECIPES["seat.ask-kubert"], "acc-fixture", "acc-routine", created)
            session.update(startedAt=[2026, 1, 12, 0, 1, 0, 0, 0, 0], state="running")
            with patch.object(RUN, "say", side_effect=ask):
                RUN.execute("seat.ask-kubert", RUN.RECIPES["seat.ask-kubert"], "acc-fixture", "acc-routine", created)


    def test_every_row_of_the_committed_doc_has_a_recipe_or_a_manual_reason_and_its_own_area(self):
        inventory = dict(RUN.rows())
        self.assertEqual([row for row in inventory if row not in RUN.RECIPES and row not in RUN.MANUAL], [])
        self.assertEqual(inventory["§3 Brain cost while idle and per turn"], "unscripted")
        self.assertEqual(inventory["chat.clarify"], "chat")
        output = io.StringIO()
        with patch.object(sys, "argv", ["run.py", "--list"]), redirect_stdout(output):
            RUN.main()
        self.assertNotIn("UNMAPPED", output.getvalue())

    def test_list_preserves_spaced_manual_ids_as_tab_columns(self):
        row = "§3 Declared project roots may advance"
        output = io.StringIO()
        with patch.object(RUN, "rows", return_value=[(row, "unscripted")]), patch.object(sys, "argv", ["run.py", "--list"]), redirect_stdout(output):
            RUN.main()
        self.assertEqual(output.getvalue().strip().split("\t"), [row, "unscripted", "manual", "no checker"])


if __name__ == "__main__":
    unittest.main()
