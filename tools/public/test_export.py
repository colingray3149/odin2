"""Wiring tests for export.py on tiny trees; the tag is spelled through export's constants."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import export  # noqa: E402

TAG, BEGIN, END = export.TOKEN, export.BEGIN, export.END


class Export(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.scratch.name)

    def tearDown(self):
        self.scratch.cleanup()

    def tree(self, files, conf=None):
        for path, body in files.items():
            (self.tmp_path / path).parent.mkdir(parents=True, exist_ok=True)
            (self.tmp_path / path).write_text(body)
        return export.export(self.tmp_path, sorted(files), conf or {})

    def capability(self, name, schema, header=""):
        return (f"{header}schema = \"odin.registry.v1\"\nkind = \"capability\"\n"
                f"toolset = \"{name.split('.')[0]}\"\nhandler = {{ id = \"{name}_handler\" }}\n"
                f"input_schema = \"{schema}\"\noutput_schema = \"{schema}\"\n")

    def test_file_rule_reads_three_lines(self):
        texts, _, gone, _ = self.tree({
            "a.sh": f"#!/bin/sh\n# about\n# {TAG}\necho a\n",
            "b.sh": f"#!/bin/sh\n# about\n# more\n# {TAG}\necho b\n",
        })
        self.assertNotIn("a.sh", texts)
        self.assertIn("a.sh", gone.paths)
        self.assertEqual(texts["b.sh"], "#!/bin/sh\n# about\n# more\necho b\n")

    def test_capability_takes_its_schemas(self):
        texts, _, gone, _ = self.tree({
            "registry/capabilities/secret.read/capability.toml":
                self.capability("secret.read", "schemas/secret.json", f"# {TAG}\n"),
            "schemas/secret.json": "{}\n",
        })
        self.assertEqual(texts, {})
        self.assertIn("registry/capabilities/secret.read/capability.toml", gone.paths)
        self.assertIn("schemas/secret.json", gone.paths)

    def test_shared_schema_survives(self):
        texts, _, gone, _ = self.tree({
            "registry/capabilities/secret.read/capability.toml":
                self.capability("secret.read", "schemas/shared.json", f"# {TAG}\n"),
            "registry/capabilities/plain.read/capability.toml":
                self.capability("plain.read", "schemas/shared.json"),
            "schemas/shared.json": "{}\n",
        })
        self.assertIn("schemas/shared.json", texts)
        self.assertNotIn("schemas/shared.json", gone.paths)

    def test_generic_workflow_markers_survive_private_members(self):
        texts, _, gone, _ = self.tree({
            "registry/capabilities/private.run/capability.toml":
                f'# {TAG}\nkind = "capability"\nimplementation = "workflow"\n'
                'handler = { id = "odin_workflow.run" }\n'
                'evidence_extractor = { id = "odin_workflow.receipt" }\n',
            "registry/capabilities/secret.read/capability.toml":
                self.capability("secret.read", "schemas/secret.json", f"# {TAG}\n"),
            "schemas/secret.json": "{}\n",
            "kernel.rs": 'const RUN: &str = "odin_workflow.run";\n'
                         'const RECEIPT: &str = "odin_workflow.receipt";\n'
                         'const PRIVATE: &str = "secret.read_handler";\n',
        })
        found = list(export.dangling(texts, gone, ()))
        self.assertEqual([(path, hit) for _, path, _, hit, _ in found],
                         [("kernel.rs", "secret.read_handler")])

    def test_line_and_block_rules(self):
        texts, _, _, findings = self.tree({
            "list.toml": f'a = 1\nb = 2\nids = [\n  "kept",\n  "gone",  # {TAG}\n]\n'
                         f'# {BEGIN}\nx = 1\n# {END}\ny = 2\n',
        })
        self.assertEqual(texts["list.toml"], 'a = 1\nb = 2\nids = [\n  "kept",\n]\ny = 2\n')
        self.assertEqual(findings, [])

    def test_json_remove_drops_enum_values(self):
        schema = {"properties": {"event": {"enum": ["kept", "gone"]}}}
        conf = {"json_remove": [{"file": "s.json", "pointer": "/properties/event/enum",
                                 "values": ["gone", "absent"]}]}
        texts, _, _, findings = self.tree({"s.json": json.dumps(schema)}, conf)
        self.assertEqual(json.loads(texts["s.json"])["properties"]["event"]["enum"], ["kept"])
        self.assertEqual(findings, [])

    def test_dangling_capability_quote_is_found(self):
        texts, _, gone, _ = self.tree({
            "registry/capabilities/secret.read/capability.toml":
                self.capability("secret.read", "schemas/secret.json", f"# {TAG}\n"),
            "registry/seats/one/seat.toml": 'tool_refs = [\n  "plain.read",\n  "secret.read",\n]\n',
        })
        found = list(export.dangling(texts, gone, ()))
        self.assertEqual([(kind, path, line, hit) for kind, path, line, hit, _ in found],
                         [("dangling", "registry/seats/one/seat.toml", 3, "secret.read")])

    def test_prompt_marker_is_refused(self):
        body = f'guidance = """\nYou help.\nSecret part {TAG}\n"""\n'
        (self.tmp_path / "seat.toml").write_text(body)
        found = list(export.prompt_markers(self.tmp_path, ["seat.toml"]))
        self.assertEqual([(kind, line, key) for kind, _, line, key, _ in found],
                         [("prompt-marker", 3, "guidance")])

    def test_replace_overrides_after_strip(self):
        texts, _, gone, _ = self.tree({
            "README.md": f"<!-- {TAG} -->\nprivate\n",
            "tools/public/replace/README.md": "public\n",
        })
        self.assertEqual(texts["README.md"], "public\n")
        self.assertNotIn("tools/public/replace/README.md", texts)
        self.assertNotIn("README.md", gone.paths)

    def test_rust_syntax_parses_each_file_alone(self):
        texts = {
            "parent.rs": "mod missing;\nfn ok(){let x=1;}\n",
            "child.rs": "fn bad( {\n",
        }
        found = [(path, hit) for kind, path, _line, hit, _text in export.syntax(self.tmp_path, texts)]
        self.assertEqual(found, [("child.rs", "unparseable")])

    def test_non_utf8_rust_is_not_silently_copied_as_a_binary(self):
        (self.tmp_path / "invalid.rs").write_bytes(b"\xfffn bad() {}")
        texts, raw, _gone, _findings = export.export(self.tmp_path, ["invalid.rs"], {})
        found = [(kind, path) for kind, path, *_ in export.syntax(self.tmp_path, texts, raw)]
        self.assertEqual(found, [("syntax", "invalid.rs")])


class Checks(unittest.TestCase):
    def test_residue_finds_a_whole_word_in_any_case_and_skips_vendored_trees(self):
        texts = {"a.md": "Ships with ALPHA today\nalphabet is fine\n", "vendor/b.md": "alpha\n"}
        found = [(path, line, word) for _, path, line, word, _ in export.residue(texts, ["alpha"], ("vendor/",))]
        self.assertEqual(found, [("a.md", 1, "alpha")])

    def test_the_ratchet_fails_a_new_group_a_count_off_its_ceiling_and_a_gone_group(self):
        def group(path, count):
            return {("residue", path, "h"): [(n, "word", "text") for n in range(count)]}
        self.assertEqual(export.report(group("a", 2), {("residue", "a", "h"): 2}, "residue.txt"), ([], 1))
        failures, _ = export.report(group("a", 3), {("residue", "a", "h"): 2}, "residue.txt")
        self.assertEqual(len(failures), 3)
        failures, _ = export.report(group("a", 1), {("residue", "a", "h"): 2}, "residue.txt")
        self.assertTrue(failures[0].startswith("stale-baseline") and "lower its count" in failures[0])
        failures, _ = export.report({}, {("residue", "gone", "h"): 1}, "residue.txt")
        self.assertIn("delete its line", failures[0])
        failures, _ = export.report({("syntax", "a", "h"): [(1, "k", "t")]}, {}, "residue.txt")
        self.assertTrue(failures[0].startswith("syntax a:1"), "only dangling and residue groups may be baselined")

    def test_a_stripped_rust_module_is_refused_where_its_parent_still_declares_it(self):
        gone = export.Gone()
        export.refuse_module("crates/odin-x/src/secret.rs", gone)
        texts = {"crates/odin-x/src/lib.rs": "mod secret;\nmod kept;\n"}
        found = [hit for _, _, _, hit, _ in export.dangling(texts, gone, ())]
        self.assertEqual(found, ["mod secret"])

    def test_a_stripped_crate_leaves_neither_its_lock_block_nor_a_dependency_on_it(self):
        lock = ('[[package]]\nname = "kept"\ndependencies = [\n "odin-gone",\n "serde",\n]\n\n'
                '[[package]]\nname = "odin-gone"\nversion = "0.0.0"\n')
        texts = {"Cargo.lock": lock}
        export.cargo_lock(texts, {"odin-gone"})
        self.assertEqual(texts["Cargo.lock"], '[[package]]\nname = "kept"\ndependencies = [\n "serde",\n]\n')

    def test_check_never_writes_and_an_out_folder_must_be_empty_or_a_checkout(self):
        with tempfile.TemporaryDirectory() as scratch:
            out = Path(scratch)
            (out / "precious.txt").write_text("keep")
            with self.assertRaises(SystemExit):
                export.write_tree(out, out, {"a.txt": "x"}, set())
            self.assertTrue((out / "precious.txt").exists())
            (out / ".git").mkdir()
            export.write_tree(out, out, {"a.txt": "x"}, set())
            self.assertEqual(sorted(path.name for path in out.iterdir()), [".git", "a.txt"])
            with self.assertRaises(SystemExit):
                export.main(["--check", "--out", str(out)])


if __name__ == "__main__":
    unittest.main()
