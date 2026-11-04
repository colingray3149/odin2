"""design-check.py's ratchet and tsc parsing: a new group, a count off its ceiling and a gone group all fail."""

import importlib.util
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("design_check", Path(__file__).with_name("design-check.py"))
design = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(design)


class RatchetChecks(unittest.TestCase):
    def report(self, found, ceiling):
        grouped = design.groups([("duration-literal-rust", "a.rs", line, text) for line, text in found])
        key = ("duration-literal-rust", "a.rs", design.fingerprint("Duration::from_secs(5)"))
        return design.report(grouped, {} if ceiling is None else {key: ceiling}, "baseline.txt")

    def test_a_group_at_its_ceiling_passes_and_every_other_count_fails(self):
        five = [(1, "Duration::from_secs(5)"), (9, "Duration::from_secs(5)")]
        self.assertEqual(self.report(five, 2), ([], 1))
        new, _ = self.report(five, None)
        self.assertEqual(len(new), 2)
        grown, _ = self.report(five, 1)
        self.assertIn("baseline 1", grown[0])
        shrunk, _ = self.report(five[:1], 2)
        self.assertIn("lower its count", shrunk[0])
        gone, _ = self.report([], 2)
        self.assertIn("delete its line", gone[0])

    def test_a_tsc_error_keeps_its_continuation_lines_and_unknown_output_is_reported(self):
        findings, unknown = design.parse_tsc("view/a.ts(3,4): error TS2322: Type 'x'\n  is not 'y'.\nnoise\n")
        self.assertEqual(findings, [("view/a.ts", "3", "TS2322 Type 'x' is not 'y'.")])
        self.assertEqual(unknown, ["noise"])


if __name__ == "__main__":
    unittest.main()
