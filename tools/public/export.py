#!/usr/bin/env python3
"""export.py — the public tree of a repo: everything tagged personal stripped, then checked.

The tag is the token TOKEN below. A tracked file carrying it in its first 3 lines is
personal; a registry object (registry/<kind>/<id>/<kind>.toml) tagged that way takes its
folder and the schemas no kept capability names. A line holding the token goes, as does
every line from BEGIN through END. tools/public/replace/<path> then replaces <path>,
scrub.toml's [[json_remove]] drops array values and its [[replace]] literals are applied in
order. The stripped tree is checked:
  dangling       a quote of a stripped id, handler, module, crate, Nix module or file path
  residue        a words.txt word (case-insensitive, word boundaries)
  prompt-marker  the token inside a TOML string value in the private tree (it reaches a model)
  syntax         a TOML, JSON or Rust file that parsed before stripping and no longer does

  --check            only check: print `<kind> <path>:<line> <detail>` per finding, exit 1 on any
  --out DIR          also write the stripped tree to DIR, a git checkout or an empty folder
                     (everything but DIR/.git is replaced)
  --repo PATH        the repo to export (default: this one)
  --write-baseline   record today's dangling and residue groups in residue.txt

residue.txt holds `<kind> <path> <hash12> <count>` with design-check.py's shrink-only
semantics: a new group fails, a count off its ceiling fails until the line is edited, a
gone group fails until its line is deleted. The gate never passes --write-baseline.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path, PurePosixPath

TAG = "personal"
TOKEN, BEGIN, END = f"[{TAG}]", f"[{TAG}:begin]", f"[{TAG}:end]"
PUBLIC = "tools/public/"
REPLACE = PUBLIC + "replace/"
HERE = Path(__file__).resolve().parent
OBJECT = re.compile(r"registry/([^/]+)/([^/]+)/[^/]+\.toml")
NIX_ATTR = re.compile(r"flake\.modules\.(?:nixos|homeManager)\.([\w-]+)")
RUST_PATH = re.compile(r'#\[path\s*=\s*"([^"]+)"\]')
QUOTED = re.compile(r"""["']([^"'\s]{1,200})["']""")
TOOLSET = re.compile(r"""toolset(?::|\s*=\s*["'])([\w.-]+)""")
WORD = re.compile(r"[\w./-]+")
PATH_NAME = re.compile(r"\b(?=(\w+)::(\w+)\b)")
MOD = re.compile(r"\bmod\s+(\w+)")
NIX_USE = re.compile(r"modules\.(?:nixos|homeManager)\.([\w-]+)")
BASELINED = ("dangling", "residue")
RUST_EDITION = "2021"
WORKFLOW_MARKERS = {"odin_workflow.run", "odin_workflow.receipt"}


class Gone:
    """What stripping removed, as the names a kept file must not use.

    `quoted` ids and handlers match a quoted string, `toolsets` a toolset grant, `words` (crates
    and paths) a whole token, `nix` a Nix module attribute. A Rust module `x` is refused as
    `mod x` in its parent file (`mods`) and as `parent::x`, `crate::x` or `super::x` in the files
    under a path prefix (`qualified`).
    """

    def __init__(self):
        self.paths, self.quoted, self.toolsets, self.words, self.nix, self.crates = (set() for _ in range(6))
        self.mods, self.qualified = {}, {}


def tagged(body):
    return TOKEN in "\n".join(body.split("\n", 3)[:3])


def read(path):
    try:
        with open(path, encoding="utf-8", newline="") as handle:
            return handle.read()
    except (UnicodeDecodeError, OSError):
        return None


def tracked(repo):
    out = subprocess.run(["git", "-C", str(repo), "ls-files", "-z"], check=True,
                         capture_output=True).stdout.decode()
    return [path for path in out.split("\0") if path]


def load(repo, paths):
    """Text files by path; everything else (binaries, symlinks) is copied untouched."""
    texts, raw = {}, set()
    for path in paths:
        source = repo / path
        if path.startswith(REPLACE) or not (source.is_file() or source.is_symlink()):
            continue
        body = None if source.is_symlink() else read(source)
        if body is None:
            raw.add(path)
        else:
            texts[path] = body
    return texts, raw


def walk_strings(node, key=""):
    if isinstance(node, str):
        yield key, node
    elif isinstance(node, dict):
        for name, value in node.items():
            yield from walk_strings(value, f"{key}.{name}" if key else name)
    elif isinstance(node, list):
        for value in node:
            yield from walk_strings(value, key)


def registry_facts(body):
    try:
        data = tomllib.loads(body)
    except tomllib.TOMLDecodeError:
        return {}, set(), set()
    handlers = {data[key]["id"] for key in ("handler", "evidence_extractor")
                if isinstance(data.get(key), dict) and "id" in data[key]}
    schemas = {data[key] for key in ("input_schema", "output_schema") if key in data}
    return data, handlers, schemas


def registry_pass(texts, raw, gone):
    folders, schemas, ids, toolsets, handlers = set(), set(), set(), set(), set()
    for path, body in texts.items():
        match = OBJECT.fullmatch(path)
        if match and tagged(body):
            data, owned, named = registry_facts(body)
            folders.add(path.rsplit("/", 1)[0] + "/")
            # A toolset object's id is a category name ("mail"): only its grants dangle, not every quote.
            (toolsets if match[1] == "toolsets" else ids).add(match[2])
            toolsets.add(data.get("toolset", ""))
            handlers |= owned
            schemas |= named
    for path in [path for path in [*texts, *raw] if path.startswith(tuple(folders))]:
        texts.pop(path, None)
        raw.discard(path)
        gone.paths.add(path)
    kept_names, kept_handlers, kept_schemas = set(), set(), set()
    for path, body in texts.items():
        if match := OBJECT.fullmatch(path):
            data, owned, named = registry_facts(body)
            kept_names |= {match[2], data.get("toolset", "")}
            kept_handlers |= owned
            kept_schemas |= named
    for path in schemas - kept_schemas:
        if texts.pop(path, None) is not None:
            gone.paths.add(path)
    gone.quoted |= (ids - kept_names) | (handlers - kept_handlers - WORKFLOW_MARKERS)
    gone.toolsets |= toolsets - kept_names - {""}


def refuse_module(path, gone):
    """A stripped Rust module file: its `mod` line, `super::`, `parent::` and `crate::` paths."""
    pure = PurePosixPath(path)
    name = pure.parent.name if pure.name == "mod.rs" else pure.stem
    parent = pure.parent.parent if pure.name == "mod.rs" else pure.parent
    if name in ("lib", "main", "build") or parent.name == "tests" and pure.name != "mod.rs":
        return
    crate = "/".join(pure.parts[:2]) + "/"
    if parent.name in ("src", "tests"):
        parents, qualifier = (f"{parent}/lib.rs", f"{parent}/main.rs"), "crate"
        gone.qualified.setdefault("", set()).add(f"{pure.parts[1].replace('-', '_')}::{name}")
    else:
        parents, qualifier = (f"{parent}.rs", f"{parent}/mod.rs"), parent.name
    for parent_file in parents:
        gone.mods.setdefault(parent_file, set()).add(name)
    gone.qualified.setdefault(crate, set()).add(f"{qualifier}::{name}")
    gone.qualified.setdefault(f"{pure.parent}/", set()).add(f"super::{name}")


def file_pass(texts, gone):
    for path in [path for path, body in texts.items() if tagged(body)]:
        body = texts.pop(path)
        gone.paths.add(path)
        if crate := re.fullmatch(r"crates/([^/]+)/Cargo\.toml", path):
            gone.words |= {crate[1], crate[1].replace("-", "_")}
            gone.crates.add(crate[1])
        if path.endswith(".rs"):
            refuse_module(path, gone)
        gone.nix |= set(NIX_ATTR.findall(body))


def cargo_lock(texts, crates):
    """Drop a stripped crate's [[package]] block and its entries in other packages' dependencies."""
    if "Cargo.lock" not in texts or not crates:
        return
    blocks = texts["Cargo.lock"].split("\n[[package]]\n")
    kept = [block for block in blocks if not any(block.startswith(f'name = "{c}"\n') for c in crates)]
    body = "\n[[package]]\n".join(kept)
    texts["Cargo.lock"] = "".join(line for line in body.splitlines(keepends=True)
                                  if line.strip() not in {f'"{c}",' for c in crates})


def strip_lines(path, body, findings):
    kept, skipping = [], 0
    for number, line in enumerate(body.splitlines(keepends=True), 1):
        if BEGIN in line:
            skipping = skipping or number
        elif END in line:
            if not skipping:
                findings.append(("syntax", path, number, END, f"{END} without {BEGIN}"))
            skipping = 0
        elif not skipping and TOKEN not in line:
            kept.append(line)
    if skipping:
        findings.append(("syntax", path, skipping, BEGIN, f"{BEGIN} is never closed"))
    return "".join(kept)


def json_remove(texts, entries, findings):
    for entry in entries:
        path = entry["file"]
        if path not in texts:
            findings.append(("syntax", path, 0, "json_remove", "json_remove names a file the tree lacks"))
            continue
        try:
            data = json.loads(texts[path])
            node = data
            for part in entry["pointer"].split("/")[1:]:
                part = part.replace("~1", "/").replace("~0", "~")
                node = node[int(part)] if isinstance(node, list) else node[part]
            node[:] = [value for value in node if value not in entry["values"]]
        except (KeyError, IndexError, ValueError, TypeError) as error:
            findings.append(("syntax", path, 0, "json_remove",
                             f"json_remove {entry['pointer']} fails: {error!r}"))
            continue
        texts[path] = json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def export(repo, paths, conf):
    """Strip one repo's tracked paths. Returns (texts, raw, gone, findings)."""
    findings, gone = [], Gone()
    texts, raw = load(repo, paths)
    registry_pass(texts, raw, gone)
    file_pass(texts, gone)
    cargo_lock(texts, gone.crates)
    for path, body in texts.items():
        if f"[{TAG}" in body:
            texts[path] = strip_lines(path, body, findings)
    json_remove(texts, conf.get("json_remove", []), findings)
    for path in paths:
        if path.startswith(REPLACE):
            target = path[len(REPLACE):]
            body = read(repo / path)
            texts.pop(target, None)
            raw.discard(target)
            if body is None:
                raw.add(path)
            else:
                texts[target] = body
                raw.discard(path)
            gone.paths.discard(target)
    pairs = [(item["from"], item["to"]) for item in conf.get("replace", [])]
    vendored = tuple(conf.get("vendored", ()))
    for path, body in texts.items():
        if not path.startswith(vendored):
            for old, new in pairs:
                body = body.replace(old, new)
            texts[path] = body
    return texts, raw, gone, findings


def hits(path, text, gone, qualified):
    """The stripped names one text (a file, then each of its lines) still uses."""
    found = set(QUOTED.findall(text)) & gone.quoted
    found |= {f"toolset:{name}" for name in set(TOOLSET.findall(text)) & gone.toolsets}
    found |= set(NIX_USE.findall(text)) & gone.nix
    tokens = {word.strip("./") for word in set(WORD.findall(text))}
    found |= tokens & gone.paths
    if any(word in text for word in gone.words):
        found |= {token for token in tokens if gone.words & set(token.split("/"))}
    found |= {f"{a}::{b}" for a, b in PATH_NAME.findall(text)} & qualified
    found |= {f"mod {name}" for name in set(MOD.findall(text)) & gone.mods.get(path, set())}
    for target in RUST_PATH.findall(text):
        if os.path.normpath(PurePosixPath(path).parent / target) in gone.paths:
            found.add(target)
    return found


def dangling(texts, gone, vendored):
    for path, body in texts.items():
        if path.startswith(vendored):
            continue
        qualified = set().union(*(names for scope, names in gone.qualified.items()
                                  if path.startswith(scope)))
        if not hits(path, body, gone, qualified):
            continue
        for number, line in enumerate(body.splitlines(), 1):
            for hit in sorted(hits(path, line, gone, qualified)):
                yield ("dangling", path, number, hit, line.strip())


def residue(texts, words, vendored):
    if not words:
        return
    pattern = re.compile(r"\b(" + "|".join(re.escape(word.lower()).replace(r"\ ", r"[\s_-]+")
                                           for word in words) + r")\b")
    for path, body in texts.items():
        if path.startswith(vendored):
            continue
        lines, lowered, seen = body.split("\n"), body.lower(), set()
        for match in pattern.finditer(lowered):
            number = lowered.count("\n", 0, match.start()) + 1
            if (number, match[1]) not in seen:
                seen.add((number, match[1]))
                yield ("residue", path, number, match[1], lines[number - 1].strip())


def prompt_markers(repo, paths):
    for path in paths:
        if not path.endswith(".toml") or (body := read(repo / path)) is None or f"[{TAG}" not in body:
            continue
        try:
            data = tomllib.loads(body)
        except tomllib.TOMLDecodeError:
            continue
        for key, value in walk_strings(data):
            if f"[{TAG}" in value:
                line = next((n for n, row in enumerate(body.splitlines(), 1)
                             if f"[{TAG}" in row and "#" not in row.split(f"[{TAG}")[0]), 0)
                yield ("prompt-marker", path, line, key, f"{key} holds the tag; use a replace file")


def parses(path, body):
    try:
        (tomllib.loads if path.endswith(".toml") else json.loads)(body)
        return True
    except ValueError:
        return False


def rust_parses(bodies):
    """Parse each exported Rust file on its own, with no module resolution.

    rustfmt with no file argument reads stdin. `--emit stdout` exits 0 for
    unformatted-but-valid input, including `mod missing;`, and 1 when the
    parser rejects the file. `--check` is not used: it also fails a tree that
    is merely unformatted. A path argument would follow `mod` declarations
    into files that are not this file.
    """
    if not bodies:
        return []
    if shutil.which("rustfmt") is None:
        return [("*", "rustfmt is not on PATH")]
    failed = []
    for path, body in bodies:
        result = subprocess.run(
            ["rustfmt", "--edition", RUST_EDITION, "--emit", "stdout"],
            input=body if isinstance(body, bytes) else body.encode(),
            capture_output=True,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).decode(errors="replace").strip()
            failed.append((path, detail.splitlines()[0] if detail else "unparseable"))
    return failed


def syntax(repo, texts, raw=()):
    for path, body in texts.items():
        if path.endswith((".toml", ".json")) and not parses(path, body):
            source = repo / REPLACE / path if (repo / REPLACE / path).is_file() else repo / path
            before = read(source)
            if before is None or parses(path, before):
                yield ("syntax", path, 0, "unparseable", "no longer parses after stripping")
    rust = [(path, body) for path, body in texts.items() if path.endswith(".rs")]
    for source in sorted(raw):
        if not source.endswith(".rs"):
            continue
        target = source[len(REPLACE):] if source.startswith(REPLACE) else source
        try:
            rust.append((target, (repo / source).read_bytes()))
        except OSError as error:
            yield ("syntax", target, 0, "unparseable", str(error)[:160])
    for path, detail in rust_parses(rust):
        yield ("syntax", path, 0, "unparseable", detail[:160])


def groups(findings):
    grouped = {}
    for kind, path, line, key, text in findings:
        digest = hashlib.sha256(key.encode()).hexdigest()[:12]
        grouped.setdefault((kind, path, digest), []).append((line, key, text))
    return grouped


def load_baseline(path):
    ceilings = {}
    for entry in (path.read_text().splitlines() if path.exists() else []):
        if entry.strip() and not entry.startswith("#"):
            kind, file_path, digest, count = entry.split()
            ceilings[(kind, file_path, digest)] = int(count)
    return ceilings


def report(grouped, ceilings, name):
    failures, matched = [], 0
    for key, items in sorted(grouped.items()):
        kind, path, _ = key
        recorded = ceilings.pop(key, None) if kind in BASELINED else None
        if recorded is None or len(items) > recorded:
            failures += [f"{kind} {path}:{line} {hit} — {text[:160]}" for line, hit, text in items]
        elif len(items) < recorded:
            failures.append(f"stale-baseline {path}:0 {kind} {key[2]} count {len(items)} "
                            f"baseline {recorded}; lower its count in {name}")
        else:
            matched += 1
    failures += [f"stale-baseline {path}:0 {kind} {digest}; delete its line from {name}"
                 for kind, path, digest in sorted(ceilings)]
    return failures, matched


def write_tree(out, repo, texts, raw):
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()) and not (out / ".git").exists():
        sys.exit(f"export: {out} is neither empty nor a git checkout; refusing to replace its contents")
    for entry in out.iterdir():
        if entry.name != ".git":
            shutil.rmtree(entry) if entry.is_dir() and not entry.is_symlink() else entry.unlink()
    for path, body in texts.items():
        (out / path).parent.mkdir(parents=True, exist_ok=True)
        with open(out / path, "w", encoding="utf-8", newline="") as handle:
            handle.write(body)
    for path in raw:
        source = repo / path
        target = out / (path[len(REPLACE):] if path.startswith(REPLACE) else path)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target, follow_symlinks=False)


def config(repo):
    public = repo / PUBLIC if (repo / PUBLIC / "scrub.toml").is_file() else HERE
    conf = tomllib.loads(read(public / "scrub.toml") or "")
    words_file = read(public / "words.txt") or ""
    words = [line.strip() for line in words_file.splitlines() if line.strip() and line[0] != "#"]
    return conf, words, repo / PUBLIC / "residue.txt"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--repo", type=Path, default=HERE.parents[1])
    parser.add_argument("--write-baseline", action="store_true")
    args = parser.parse_args(argv)
    if args.check and (args.out or args.write_baseline):
        parser.error("--check only checks; drop --out and --write-baseline")
    repo = args.repo.resolve()
    conf, words, baseline = config(repo)
    paths = tracked(repo)
    texts, raw, gone, findings = export(repo, paths, conf)
    vendored = tuple(conf.get("vendored", ()))
    findings += dangling(texts, gone, vendored)
    findings += residue(texts, words, vendored)
    findings += prompt_markers(repo, paths)
    findings += syntax(repo, texts, raw)
    grouped = groups(findings)
    if args.write_baseline:
        kept = {key: items for key, items in grouped.items() if key[0] in BASELINED}
        lines = [f"# {TOKEN}\n"] + [f"{kind} {path} {digest} {len(items)}\n"
                                    for (kind, path, digest), items in sorted(kept.items())]
        baseline.write_text("".join(lines))
        print(f"wrote {baseline.name}: {len(kept)} group(s)")
    if args.out:
        write_tree(args.out, repo, texts, raw)
    failures, matched = report(grouped, load_baseline(baseline), baseline.name)
    print("\n".join(failures) if failures else f"ok: export clean; {matched} group(s) baselined")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
