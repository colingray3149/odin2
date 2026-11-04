#!/usr/bin/env python3
"""design-check.py — design rules and view type errors against shrink-only baselines.

Rules live in tools/ast-grep/. Design findings are grouped by rule, path, and a
hash of the normalized match text. tools/design-baseline.txt records
`rule path hash count` for violations already in the tree; a trailing `# ...`
comment on a line is ignored. A new group fails. A
count above or below its recorded ceiling fails until that ceiling is edited in
a reviewed commit — a partial shrink cannot be left in place, or the count
could grow back. A group that is gone fails until its line is deleted.

Prints `<rule> <path>:<line> <detail>` per failing finding. Quiet on a clean
tree except one `ok:` line. Vendored trees come from slop.VENDORED. The scan
is production code only: tests/, test modules, #[cfg(test)] modules, fixtures,
and benches are out of scope. Pass `--write-baseline` to replace the design
baseline with the current scan; the gate does not pass that flag.

ast-grep has no TOML grammar, so `[quiet]` in tracked TOML is scanned as text
and reported as quiet-token-toml. The one allowed `[quiet]` is the QUIET_REPLY
initializer in crates/odin-hermes/src/conversation/prompt.rs. Another const of
that name, in that file or any other, fails.

View type errors use the same ceiling: tools/tsc-baseline.txt records
`tsc path hash count` for `tsc --pretty false` diagnostics already in the
vendored view. A finding is the error header plus continuation lines, so a
related-information line is part of the identity and a moved line is not a new
finding. A nonzero tsc exit with no parsed error, or any line that is not an
error header or its continuation, fails closed. stderr is read even when
stdout is nonempty. `--write-tsc-baseline` rewrites that baseline; the gate
never passes it.
"""
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from slop import VENDORED, test_module_spans  # noqa: E402

DESIGN_BASELINE = pathlib.Path(__file__).with_name("design-baseline.txt")
TSC_BASELINE = pathlib.Path(__file__).with_name("tsc-baseline.txt")
CONFIG = pathlib.Path(__file__).with_name("ast-grep") / "sgconfig.yml"
TSC_RULE = "tsc"
TSC_COMMAND = ["tsc", "--noEmit", "-p", "view/tsconfig.json", "--pretty", "false"]
def vendored_globs():
    """ast-grep exclusions for the same trees slop.VENDORED names."""
    globs = []
    for prefix in VENDORED:
        root = prefix.rstrip("/")
        globs.append(f"!{root}/**")
        globs.append(f"!{pathlib.PurePosixPath(root).name}/**")
    return globs


GLOBS = [
    "*.rs", "*.ts", "*.tsx", "*.sh",
    *vendored_globs(),
    "!**/node_modules/**", "!target/**",
]
QUIET_TOML = re.compile(r"\[quiet\]")
QUIET_DEFINITION = "crates/odin-hermes/src/conversation/prompt.rs"
QUIET_DEF_LINE = re.compile(r"""\bconst\s+QUIET_REPLY\s*:\s*&str\s*=\s*"\[quiet\]"\s*;""")
IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
FLEET_HOST = re.compile(r"fd7a:115c:a1e0|\.ts\.net|\b(?:mini|pc|laptop|workspace)\b")
TSC_HEADER = re.compile(
    r"^(?P<path>.+?)\((?P<line>\d+),(?P<col>\d+)\): error (?P<code>TS\d+): (?P<detail>.*)$")
TEST_PARTS = {"tests", "test", "fixtures", "fixture", "benches"}
TEST_NAMES = re.compile(r"(?:_tests|_test|tests)\.rs$|^(?:test_\w+|fixtures?)\.rs$|[._]test\.tsx?$")


def repo_root():
    return subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip()


def ast_grep():
    for name in ("ast-grep", "sg"):
        found = shutil.which(name)
        if found:
            return found
    sys.exit("design-check: ast-grep is not on PATH")


def tracked_toml():
    out = subprocess.check_output(["git", "ls-files", "-z", "*.toml"], text=True)
    return [path for path in out.split("\0") if path and not path.startswith(VENDORED)]


def production_path(path):
    """Tests, fixtures, benches, and vendored trees are not design-rule scope."""
    if path.startswith(VENDORED) or "/node_modules/" in path:
        return False
    parts = pathlib.PurePosixPath(path).parts
    if any(part in TEST_PARTS for part in parts):
        return False
    return TEST_NAMES.search(pathlib.PurePosixPath(path).name) is None


def canonical_quiet(root, path, line, text):
    """The one allowed token: the single QUIET_REPLY initializer in prompt.rs."""
    if path != QUIET_DEFINITION or text != '"[quiet]"':
        return False
    source = pathlib.Path(root, path).read_text(errors="replace").splitlines()
    definitions = [number for number, row in enumerate(source, 1) if QUIET_DEF_LINE.search(row)]
    return definitions == [line]


def loopback_literal(text):
    """A literal whose only address is 127.0.0.1 and that names no fleet host is loopback."""
    addresses = set(IPV4.findall(text))
    return addresses == {"127.0.0.1"} and not FLEET_HOST.search(text)


def test_spans(root, path):
    """Byte spans (ast-grep's offsets) of inline #[cfg(test)] modules, from the shared slop mask."""
    source_path = pathlib.Path(root, path)
    try:
        source = source_path.read_text()
        spans = test_module_spans(source, source_path)
    except (OSError, UnicodeError, ValueError) as error:
        sys.exit(f"design-check: cannot mask test modules in {path}: {error}")
    return [(len(source[:start].encode()), len(source[:end].encode())) for start, end in spans]


def scan(root):
    command = [ast_grep(), "scan", "-c", str(CONFIG), "--json=stream",
               *sum([["--globs", glob] for glob in GLOBS], []), root]
    result = subprocess.run(command, cwd=root, capture_output=True, text=True)
    if result.returncode not in (0, 1):
        sys.stderr.write(result.stderr)
        sys.exit(result.returncode or 1)
    findings, seen = [], set()
    spans = {}
    for raw in result.stdout.splitlines():
        if not raw.strip():
            continue
        item = json.loads(raw)
        path = os.path.relpath(item["file"], root)
        if not production_path(path):
            continue
        start = item["range"]["byteOffset"]["start"]
        end = item["range"]["byteOffset"]["end"]
        if path.endswith(".rs"):
            if path not in spans:
                spans[path] = test_spans(root, path)
            if any(span_start <= start and end <= span_end for span_start, span_end in spans[path]):
                continue
        text = " ".join(item["text"].split())
        if item["ruleId"].startswith("no-host-literal-") and loopback_literal(item["text"]):
            continue
        line = item["range"]["start"]["line"] + 1
        key = (item["ruleId"], path, start)
        if key in seen:
            continue
        seen.add(key)
        findings.append((item["ruleId"], path, line, text))
    for path in tracked_toml():
        if not production_path(path):
            continue
        for number, line in enumerate(pathlib.Path(root, path).read_text(errors="replace").splitlines(), 1):
            if QUIET_TOML.search(line):
                findings.append(("quiet-token-toml", path, number, " ".join(line.split())))
    return [item for item in findings if not canonical_quiet(root, item[1], item[2], item[3])]


def fingerprint(text):
    return hashlib.sha256(text.encode()).hexdigest()[:12]


def groups(findings):
    grouped = {}
    for rule, path, line, text in findings:
        grouped.setdefault((rule, path, fingerprint(text)), []).append((line, text))
    return grouped


def load_baseline(path):
    ceilings = {}
    if not path.exists():
        return ceilings
    for entry in path.read_text().splitlines():
        if not entry.strip() or entry.startswith("#"):
            continue
        rule, file_path, digest, count = entry.split("#", 1)[0].split()
        key = (rule, file_path, digest)
        if key in ceilings or int(count) < 1:
            raise ValueError(f"invalid baseline entry: {entry}")
        ceilings[key] = int(count)
    return ceilings


def write_baseline(path, grouped):
    lines = [f"{rule} {file_path} {digest} {len(items)}"
             for (rule, file_path, digest), items in sorted(grouped.items())]
    path.write_text("".join(f"{line}\n" for line in lines))


def report(grouped, ceilings, baseline_name):
    """Compare one scan with its ceiling. Returns (failures, matched groups)."""
    failures = []
    matched = 0
    for key, items in sorted(grouped.items()):
        rule, path, digest = key
        recorded = ceilings.pop(key, None)
        count = len(items)
        if recorded is None:
            for line, text in items:
                failures.append(f"{rule} {path}:{line} {text[:160]}")
        elif count > recorded:
            failures.append(
                f"{rule} {path}:0 {count} findings (baseline {recorded}); split or name the new literal")
            for line, text in items:
                failures.append(f"{rule} {path}:{line} {text[:160]}")
        elif count < recorded:
            failures.append(
                f"stale-baseline {path}:0 {rule} {digest} count {count} baseline {recorded}; "
                f"lower its count in {baseline_name}")
        else:
            matched += 1
    for rule, path, digest in sorted(ceilings):
        failures.append(f"stale-baseline {path}:0 {rule} {digest}; delete its line from {baseline_name}")
    return failures, matched


def combined(stdout, stderr):
    """Keep stderr lines that stdout did not already carry."""
    seen = set(stdout.splitlines())
    extra = [line for line in stderr.splitlines() if line not in seen]
    if not extra:
        return stdout
    return stdout + ("" if stdout.endswith("\n") or not stdout else "\n") + "\n".join(extra) + "\n"


def parse_tsc(text):
    """Return (findings, unknown). Continuations attach to the open error."""
    findings = []
    unknown = []
    current = None

    def close():
        nonlocal current
        if current is not None:
            findings.append(current)
            current = None

    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        match = TSC_HEADER.match(line.strip())
        if match:
            close()
            detail = f"{match['code']} {match['detail']}"
            current = (match["path"], match["line"], detail)
            continue
        if current is not None and (raw.startswith(" ") or raw.startswith("\t")):
            path, line_no, detail = current
            current = (path, line_no, detail + " " + line.strip())
            continue
        close()
        unknown.append(line.strip())
    close()
    return findings, unknown


def tsc_groups(findings):
    grouped = {}
    for path, line, detail in findings:
        grouped.setdefault((TSC_RULE, path, fingerprint(detail)), []).append((int(line), detail))
    return grouped


def scan_tsc():
    proc = subprocess.run(TSC_COMMAND, text=True, capture_output=True)
    text = combined(proc.stdout, proc.stderr)
    findings, unknown = parse_tsc(text)
    if proc.returncode not in (0, 1, 2):
        print(f"design-check: tsc exited {proc.returncode}")
        if proc.stderr.strip():
            sys.stderr.write(proc.stderr if proc.stderr.endswith("\n") else proc.stderr + "\n")
        return None
    if unknown or (proc.returncode != 0 and not findings):
        if unknown:
            print("design-check: unparsed tsc output")
            for line in unknown:
                print(line)
        else:
            print(f"design-check: tsc exited {proc.returncode} with no diagnostics")
        shown = "\n".join(unknown)
        if proc.stderr.strip() and proc.stderr.strip() not in shown:
            sys.stderr.write(proc.stderr if proc.stderr.endswith("\n") else proc.stderr + "\n")
        return None
    return tsc_groups(findings)


def main():
    root = repo_root()
    os.chdir(root)
    write_design = "--write-baseline" in sys.argv
    write_tsc = "--write-tsc-baseline" in sys.argv
    design = groups(scan(root))
    tsc = scan_tsc()
    if tsc is None:
        return 1
    if write_design:
        write_baseline(DESIGN_BASELINE, design)
        print(f"wrote {DESIGN_BASELINE.name}: {len(design)} group(s)")
    if write_tsc:
        write_baseline(TSC_BASELINE, tsc)
        print(f"wrote {TSC_BASELINE.name}: {len(tsc)} group(s)")
    if write_design or write_tsc:
        return 0
    failures, design_matched = report(design, load_baseline(DESIGN_BASELINE), DESIGN_BASELINE.name)
    tsc_failures, tsc_matched = report(tsc, load_baseline(TSC_BASELINE), TSC_BASELINE.name)
    failures.extend(tsc_failures)
    for failure in failures:
        print(failure)
    if not failures:
        print(f"ok: no design findings; {design_matched} baselined; {tsc_matched} tsc baselined")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
