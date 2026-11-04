#!/usr/bin/env python3
"""Record one gate run's step and test outcomes in ~/.local/state/odin/gate-pass/<sha>.json.

gate.sh calls this from its EXIT trap:
  gate-results.py <sha> <exit-code> <outcomes-path> "<steps>" <junit-path>
Each finished step appended "<step> <pass|fail> <milliseconds>" to the outcomes file.
It writes only while HEAD is still <sha> and the tree is clean; otherwise it exits 0 silently.

  gate-results.py capabilities <junit.xml | gate-pass.json> [<registry-dir>]
fails, naming each one, when a test an enabled capability's `tests` names did not pass in that run. Against a
JUnit report (the gate) it also fails on an enabled capability that names no test, outside UNTESTED.
gate.sh runs it after the test step; deploy runs it on the gate record against the registry it publishes.

  gate-results.py passed <sha>
exits 0 when the record for <sha> says the gate passed every step on that commit, else 1 with the reason.
deploy.sh and ship.sh ask it before they build or switch anything.
"""

import json
import os
import subprocess
import sys
import tomllib
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RECORDS = Path.home() / ".local/state/odin/gate-pass"
# The capabilities left untested on purpose; every other enabled capability names a passing test.
UNTESTED: set[str] = set()


def git(*args: str) -> str:
    result = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=True)
    return result.stdout


def step_outcomes(steps: list[str], outcomes_path: Path) -> tuple[dict[str, str], dict[str, float]]:
    """Each step's outcome and wall seconds; a step with no line never finished, so it did not run."""
    outcomes = {name: "not-run" for name in steps}
    seconds: dict[str, float] = {}
    for line in outcomes_path.read_text().splitlines():
        name, outcome, milliseconds = line.split()
        outcomes[name] = outcome
        seconds[name] = round(int(milliseconds) / 1000, 1)
    return outcomes, seconds


def test_outcomes(junit: Path) -> dict[str, str]:
    """Map '<classname> <name>' to pass, fail or skip from a nextest JUnit report."""
    if not junit.is_file():
        print(f"gate: no test report at {junit}; tests not recorded", file=sys.stderr)
        return {}
    try:
        cases = ET.parse(junit).iter("testcase")
        outcomes: dict[str, str] = {}
        for case in cases:
            key = f"{case.get('classname', '')} {case.get('name', '')}"
            tags = {child.tag for child in case}
            if tags & {"failure", "error"}:
                outcomes[key] = "fail"
            elif "skipped" in tags:
                outcomes[key] = "skip"
            else:
                outcomes[key] = "pass"
        return outcomes
    except ET.ParseError as err:
        print(f"gate: unreadable test report {junit} ({err}); tests not recorded", file=sys.stderr)
        return {}


def declared_tests(registry: Path) -> dict[str, list[str]]:
    """Each enabled capability's named tests, `<binary-id> <test-name>` as the JUnit report keys them."""
    declared = {}
    for path in sorted(registry.glob("capabilities/*/capability.toml")):
        capability = tomllib.loads(path.read_text())
        if capability.get("enabled") and capability.get("tests"):
            declared[path.parent.name] = capability["tests"]
    return declared


def unproven_tests(tests: dict[str, str], registry: Path) -> list[str]:
    """One line per named test the run did not record as passed."""
    problems = []
    for capability, names in declared_tests(registry).items():
        for name in names:
            outcome = tests.get(name)
            if outcome != "pass":
                why = "is absent from this run" if outcome is None else f"did not pass ({outcome})"
                problems.append(f"capability {capability}: test {name} {why}")
    return problems


def untested_capabilities(registry: Path) -> list[str]:
    """One line per enabled capability outside UNTESTED that names no test."""
    problems = []
    for path in sorted(registry.glob("capabilities/*/capability.toml")):
        capability = tomllib.loads(path.read_text())
        if capability.get("enabled") and not capability.get("tests") and path.parent.name not in UNTESTED:
            problems.append(f"capability {path.parent.name}: names no test")
    return problems


def check_capabilities(source: Path, registry: Path) -> int:
    """0 when every named test passed in the JUnit report or gate record at `source`, else 1. A JUnit report (the
    gate's own run) also needs every enabled capability outside UNTESTED to name a test; deploy reads the record and
    the registry Sinmara may have extended since, so it checks only the tests that are named."""
    gate_run = source.suffix != ".json"
    tests = test_outcomes(source) if gate_run else json.loads(source.read_text())["tests"]
    problems = unproven_tests(tests, registry) + (untested_capabilities(registry) if gate_run else [])
    for problem in problems:
        print(f"gate: {problem}", file=sys.stderr)
    return 1 if problems else 0


def gate_failure(sha: str, records: Path = RECORDS) -> str | None:
    """Why the gate record for `sha` does not prove a pass, or None when it does."""
    path = records / f"{sha}.json"
    if not path.is_file():
        return f"{sha} has no gate record; run tools/gate.sh on a clean tree at {sha} (it writes {path})"
    record = json.loads(path.read_text())
    if record.get("sha") != sha:
        return f"{path} records {record.get('sha')}, not {sha}"
    if record.get("result") != "pass":
        return f"the gate did not pass on {sha}"
    unfinished = sorted(name for name, outcome in record.get("steps", {}).items() if outcome != "pass")
    if unfinished:
        return f"the gate record for {sha} has no pass for {', '.join(unfinished)}"
    return None


def main() -> int:
    if sys.argv[1:2] == ["passed"] and len(sys.argv) == 3:
        failure = gate_failure(sys.argv[2])
        if failure:
            print(f"gate: {failure}", file=sys.stderr)
        return 1 if failure else 0
    if sys.argv[1:2] == ["capabilities"] and len(sys.argv) in (3, 4):
        return check_capabilities(Path(sys.argv[2]), Path(sys.argv[3]) if len(sys.argv) == 4 else ROOT / "registry")
    if len(sys.argv) != 6:
        sys.exit(
            "usage: gate-results.py <sha> <exit-code> <outcomes-path> <steps> <junit-path>\n"
            "       gate-results.py capabilities <junit.xml | gate-pass.json> [<registry-dir>]\n"
            "       gate-results.py passed <sha>"
        )
    sha, code_text, outcomes_text, steps_text, junit_text = sys.argv[1:]
    code = int(code_text)
    # Only a clean run of the commit it started on is recorded; a moved HEAD or a dirty tree is not.
    if git("rev-parse", "HEAD").strip() != sha or git("status", "--porcelain").strip():
        return 0
    tests = test_outcomes(Path(junit_text))
    outcomes, seconds = step_outcomes(steps_text.split(), Path(outcomes_text))
    record = {
        "sha": sha,
        "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "result": "pass" if code == 0 else "fail",
        "steps": outcomes,
        "seconds": seconds,
        "tests": tests,
    }
    RECORDS.mkdir(parents=True, exist_ok=True)
    tmp = RECORDS / f"{sha}.json.tmp"
    tmp.write_text(json.dumps(record, indent=2) + "\n")
    os.replace(tmp, RECORDS / f"{sha}.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
