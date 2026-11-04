"""gate-results.py: a named test that is absent or red fails the capabilities check, and only a record of a
clean gate run on the exact commit lets deploy build."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("gate_results", Path(__file__).with_name("gate-results.py"))
gate_results = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate_results)

JUNIT = """<testsuites><testsuite name="odin">
  <testcase classname="odin-cli::bin/odind" name="coding_route::tests::passes"/>
  <testcase classname="odin-omp" name="host_tools::tests::fails"><failure message="x"/></testcase>
</testsuite></testsuites>"""


def capability(registry: Path, name: str, enabled: bool, tests: list[str]) -> None:
    folder = registry / "capabilities" / name
    folder.mkdir(parents=True)
    listed = ", ".join(f'"{test}"' for test in tests)
    (folder / "capability.toml").write_text(f"enabled = {str(enabled).lower()}\ntests = [{listed}]\n")


class CapabilityTests(unittest.TestCase):
    def test_a_named_test_that_is_absent_or_red_names_its_capability(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            registry = root / "registry"
            capability(registry, "code.ok", True, ["odin-cli::bin/odind coding_route::tests::passes"])
            capability(registry, "code.red", True, ["odin-omp host_tools::tests::fails"])
            capability(registry, "code.gone", True, ["odin-omp host_tools::tests::renamed"])
            capability(registry, "code.off", False, ["odin-omp host_tools::tests::never_ran"])
            junit = root / "junit.xml"
            junit.write_text(JUNIT)
            problems = gate_results.unproven_tests(gate_results.test_outcomes(junit), registry)
            self.assertEqual(
                problems,
                [
                    "capability code.gone: test odin-omp host_tools::tests::renamed is absent from this run",
                    "capability code.red: test odin-omp host_tools::tests::fails did not pass (fail)",
                ],
            )
            self.assertEqual(gate_results.check_capabilities(junit, registry), 1)

    def test_the_gate_fails_on_an_untested_capability_but_deploy_reads_only_named_tests(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            registry = root / "registry"
            capability(registry, "code.ok", True, ["odin-cli::bin/odind coding_route::tests::passes"])
            capability(registry, "code.exempt", True, [])
            gate_results.UNTESTED = {"code.exempt"}
            junit = root / "junit.xml"
            junit.write_text(JUNIT)
            record = root / "record.json"
            record.write_text(json.dumps({"tests": gate_results.test_outcomes(junit)}))
            self.assertEqual(gate_results.check_capabilities(junit, registry), 0)
            capability(registry, "code.new", True, [])
            self.assertEqual(gate_results.untested_capabilities(registry), ["capability code.new: names no test"])
            self.assertEqual(gate_results.check_capabilities(junit, registry), 1)
            self.assertEqual(gate_results.check_capabilities(record, registry), 0)


class GateRecordTests(unittest.TestCase):
    def record(self, records: Path, name: str, **fields) -> None:
        body = {"sha": name, "result": "pass", "steps": {"fmt": "pass", "test": "pass"}, **fields}
        (records / f"{name}.json").write_text(json.dumps(body))

    def test_only_a_passing_record_of_that_commit_lets_deploy_build(self):
        with tempfile.TemporaryDirectory() as scratch:
            records = Path(scratch)
            self.record(records, "good")
            self.record(records, "red", result="fail")
            self.record(records, "skipped", steps={"fmt": "pass", "test": "not-run"})
            self.record(records, "moved", sha="other")
            (records / "stamp").write_text("2026-11-02T00:00:00Z")  # the bare timestamp the old gate wrote
            self.assertIsNone(gate_results.gate_failure("good", records))
            self.assertIn("did not pass", gate_results.gate_failure("red", records))
            self.assertIn("test", gate_results.gate_failure("skipped", records))
            self.assertIn("records other", gate_results.gate_failure("moved", records))
            self.assertIn("no gate record", gate_results.gate_failure("stamp", records))

    def test_a_report_reads_as_pass_fail_and_skip_with_its_class_and_name(self):
        with tempfile.TemporaryDirectory() as scratch:
            junit = Path(scratch) / "junit.xml"
            junit.write_text(JUNIT.replace("</testsuite>", '<testcase classname="odin-kube" name="k"><skipped/></testcase></testsuite>'))
            self.assertEqual(
                gate_results.test_outcomes(junit),
                {
                    "odin-cli::bin/odind coding_route::tests::passes": "pass",
                    "odin-omp host_tools::tests::fails": "fail",
                    "odin-kube k": "skip",
                },
            )


if __name__ == "__main__":
    unittest.main()
