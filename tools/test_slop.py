"""slop.py's test mask: what is test code is not counted or checked as production."""

import importlib.util
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("slop", Path(__file__).with_name("slop.py"))
slop = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(slop)

SOURCE = '''fn production() { let brace = "}"; }

#[cfg(test)]
mod tests {
    #[test]
    fn a() { let open = "{"; }
}

#[tokio::test]
async fn at_file_scope() -> Result<(), String> {
    Ok(())
}

#[test]
fn another() {}

fn production_again() {}
'''


class MaskChecks(unittest.TestCase):
    def test_test_modules_and_file_scope_test_functions_are_masked_and_production_is_not(self):
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch, "x.rs")
            path.write_text(SOURCE)
            kept = [line for line in slop.non_test_lines(path) if line is not None and line.strip()]
        self.assertEqual(kept, ['fn production() { let brace = "}"; }', "fn production_again() {}"])

    def test_an_unterminated_test_module_is_an_error_not_silently_production(self):
        with self.assertRaisesRegex(ValueError, "unterminated"):
            slop.test_module_spans("#[cfg(test)]\nmod tests {\n", "x.rs")


if __name__ == "__main__":
    unittest.main()
