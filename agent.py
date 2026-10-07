#!/usr/bin/env python3
"""Kacknex SWE Agent - a sandboxed, proof-gated AI software engineer.

What makes it different from a plain "LLM + tools" loop
  1. SANDBOX    The agent works in a throw-away `git worktree`, never in your checkout.
                Your uncommitted work is snapshotted into it; rollback = delete the worktree.
  2. RED->GREEN finish() is rejected by the harness (not by the prompt) unless a test that
                FAILED on the original code now PASSES. New tests are re-run against the
                pristine base to prove they really fail without the fix.
  3. ANTI-CHEAT Existing tests are append-only, diff size is budgeted, regressions are blocked.
  4. SECRET GUARD  .env / keys are unreadable, child processes get a scrubbed environment,
                tool output is redacted and the final diff is scanned for credentials.
  5. SELF-HEAL  Malformed tool-call JSON (Groq `tool_use_failed`), wrong argument names,
                truncated output and syntax-breaking edits are repaired or bounced automatically.
  6. TOURNAMENT --candidates N runs N independent agents in parallel worktrees and keeps the
                smallest patch that passes every gate.

Usage
  python agent.py --repo ./test-repo --task "Fix the add function so it adds instead of subtracts"
  python agent.py --repo . --task "..." --candidates 3 --apply
  python agent.py --selftest          # offline demo of the harness, no API key needed

.env (next to agent.py)
  OPENAI_API_KEY=...                       # your Groq key
  OPENAI_BASE_URL=https://api.groq.com/openai/v1
  AGENT_MODEL=openai/gpt-oss-120b
"""
from __future__ import annotations

import argparse
import ast
import concurrent.futures as cf
import contextlib
import difflib
import inspect
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

OUT_LIMIT = 8000
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "env", "dist", "build",
             ".pytest_cache", ".mypy_cache", ".ruff_cache", ".idea", ".vscode"}
GIT_READONLY = {"diff", "status", "log", "show", "blame", "ls-files", "grep"}
PY_MODULES_OK = {"pytest", "unittest", "doctest", "pyflakes", "flake8", "mypy", "ruff", "black",
                 "isort", "compileall", "py_compile"}
GIT_LOCK = threading.Lock()
PRINT_LOCK = threading.Lock()
GIT_ID = ["-c", "user.name=kacknex-agent", "-c", "user.email=agent@kacknex.local",
          "-c", "commit.gpgsign=false", "-c", "core.quotepath=false"]

# --------------------------------------------------------------------------- secret guard
SECRET_FILE = re.compile(
    r"(^|/)(\.env(?!\.(example|sample|template)$)(\..*)?|[^/]*\.(pem|key|p12|pfx|jks)"
    r"|id_(rsa|dsa|ecdsa|ed25519)(\.pub)?|\.netrc|\.npmrc|\.pypirc|credentials(\.json)?"
    r"|secrets?\.(json|ya?ml|toml))$", re.I)
SECRET_PATTERNS = [re.compile(p) for p in (
    r"\bgsk_[A-Za-z0-9]{20,}", r"\bsk-[A-Za-z0-9_\-]{20,}", r"\bAKIA[0-9A-Z]{16}",
    r"\bgh[pousr]_[A-Za-z0-9]{30,}", r"\bxox[abprs]-[A-Za-z0-9\-]{10,}", r"\bAIza[0-9A-Za-z_\-]{30,}",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----")]
ASSIGN_SECRET = re.compile(
    r"""(?ix)\b(?:api[_-]?key|secret|token|passw(?:or)?d)\w*\s*[=:]\s*['"]([^'"\s]{16,})['"]""")
_SENSITIVE_ENV = re.compile(r"(KEY|TOKEN|SECRET|PASSW|CREDENTIAL|AUTH|COOKIE|SESSION|PRIVATE)", re.I)


def redact(s: str) -> str:
    for rx in SECRET_PATTERNS:
        s = rx.sub("[REDACTED]", s)
    return s


def has_secret(line: str) -> bool:
    if any(rx.search(line) for rx in SECRET_PATTERNS):
        return True
    m = ASSIGN_SECRET.search(line)
    return bool(m and re.search(r"\d", m.group(1)) and re.search(r"[A-Za-z]", m.group(1)))


def scrubbed_env() -> dict:
    """Environment for every child process: no API keys, no bytecode litter, UTF-8 everywhere."""
    env = {k: v for k, v in os.environ.items() if not _SENSITIVE_ENV.search(k)}
    env.update(PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="utf-8", PYTHONUTF8="1",
               GIT_TERMINAL_PROMPT="0", NO_COLOR="1")
    return env


# --------------------------------------------------------------------------- small utilities
def clip(s: str, n: int = OUT_LIMIT) -> str:
    return s if len(s) <= n else s[: n // 2] + "\n...[truncated]...\n" + s[-n // 2:]


def split_cmd(cmd: str) -> list[str]:
    return [t.strip('"') for t in shlex.split(cmd, posix=(os.name != "nt"))]


def run_proc(argv, cwd, timeout=300, input=None, raw=False):
    try:
        r = subprocess.run([str(a) for a in argv], cwd=str(cwd), capture_output=True,
                           env=scrubbed_env(), timeout=timeout, input=input)
    except subprocess.TimeoutExpired:
        return 124, (b"" if raw else f"TIMEOUT after {timeout}s")
    except FileNotFoundError:
        return 127, (b"" if raw else f"command not found: {argv[0]}")
    if raw:
        return r.returncode, r.stdout
    return r.returncode, (r.stdout + r.stderr).decode("utf-8", "replace").strip()


def rmtree(path) -> None:
    def fix(func, p, *_):
        with contextlib.suppress(OSError):
            os.chmod(p, stat.S_IWRITE)
            func(p)
    shutil.rmtree(path, **({"onexc": fix} if sys.version_info >= (3, 12) else {"onerror": fix}))


def is_test_path(rel: str) -> bool:
    p = PurePosixPath(rel)
    n = p.name
    return (n.startswith("test_") or n.endswith(("_test.py", ".test.js", ".spec.js", ".test.ts", ".spec.ts"))
            or any(x in ("tests", "test", "__tests__") for x in p.parts[:-1]))


def syntax_error(text: str):
    try:
        ast.parse(text)
    except (SyntaxError, ValueError) as e:
        return f"{getattr(e, 'msg', e)} (line {getattr(e, 'lineno', '?')})"
    return None


TOOL_ALIASES = {"open_file": "read_file", "cat": "read_file", "print_tree": "list_files", "ls": "list_files",
                "search": "grep", "find": "grep", "apply_patch": "str_replace", "run": "run_command",
                "exec": "run_command", "shell": "run_command", "bash": "run_command", "done": "finish"}


def norm_tool(name: str) -> str:
    """gpt-oss sometimes calls tools as `repo_browser.list_files` / `functions.grep`; map them to real names."""
    n = (name or "").strip().split(".")[-1].split(":")[-1]
    return TOOL_ALIASES.get(n, n)


def parse_args(raw: str):
    """Tolerant JSON parsing for tool-call arguments. Returns (dict, error|None)."""
    if not raw or not raw.strip():
        return {}, None
    cleaned = raw.replace("\x00", "")
    for cand in (raw, cleaned, re.sub(r",\s*([}\]])", r"\1", cleaned)):
        try:
            v = json.loads(cand, strict=False)
            if isinstance(v, dict):
                return v, None
        except json.JSONDecodeError:
            pass
    return {}, "tool arguments were not valid JSON"


class UI:
    on = sys.stdout.isatty() and not os.getenv("NO_COLOR")
    multi = False

    @staticmethod
    def paint(s: str, code: str) -> str:
        return f"\033[{code}m{s}\033[0m" if UI.on else s


def say(tag: str, text: str) -> None:
    prefix = UI.paint(f"[{tag}] ", "36") if UI.multi else ""
    with PRINT_LOCK:
        print(prefix + text, flush=True)


# --------------------------------------------------------------------------- test runner
@dataclass
class RunResult:
    code: int
    out: str
    cases: dict = field(default_factory=dict)  # id -> (status, message)
    structured: bool = False

    @property
    def passed(self) -> set:
        return {k for k, (s, _) in self.cases.items() if s == "passed"}

    @property
    def failed(self) -> set:
        return {k for k, (s, _) in self.cases.items() if s == "failed"}

    def summary(self, max_fail: int = 6) -> str:
        if not self.structured:
            return f"exit code {self.code}\n" + clip(self.out, 3000)
        skipped = sum(1 for s, _ in self.cases.values() if s == "skipped")
        lines = [f"exit={self.code} passed={len(self.passed)} failed={len(self.failed)} skipped={skipped}"]
        for i, tid in enumerate(sorted(self.failed)):
            if i >= max_fail:
                lines.append(f"... and {len(self.failed) - max_fail} more failing tests")
                break
            lines.append(f"FAILED {tid}\n{clip(self.cases[tid][1], 900)}")
        if not self.cases:
            lines.append(clip(self.out, 1500))
        return "\n".join(lines)


def parse_junit(path: str):
    try:
        if os.path.getsize(path) == 0:
            return None
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return None
    cases = {}
    for tc in root.iter("testcase"):
        tid = f'{tc.get("classname", "")}::{tc.get("name", "")}'.lstrip(":")
        fail = next((c for c in tc if c.tag in ("failure", "error")), None)
        if fail is not None:
            cases[tid] = ("failed", (fail.text or fail.get("message") or "").strip())
        elif tc.find("skipped") is not None:
            cases[tid] = ("skipped", "")
        else:
            cases[tid] = ("passed", "")
    return cases


class TestRunner:
    __test__ = False  # not a pytest class

    def __init__(self, argv: list[str], timeout: int = 600):
        self.argv, self.timeout = argv, timeout
        self.is_pytest = "pytest" in " ".join(argv)

    @staticmethod
    def from_string(cmd: str | None) -> "TestRunner":
        if not cmd:
            return TestRunner([sys.executable, "-m", "pytest", "-q", "--tb=short"])
        argv = split_cmd(cmd)
        if argv and argv[0] == "pytest":
            argv = [sys.executable, "-m", "pytest"] + argv[1:]
        elif argv and argv[0] in ("python", "python3"):
            argv[0] = sys.executable
        return TestRunner(argv)

    def run(self, cwd, extra=()) -> RunResult:
        argv = self.argv + list(extra)
        xml_path = ""
        if self.is_pytest:
            fd, xml_path = tempfile.mkstemp(suffix=".xml")
            os.close(fd)
            argv += [f"--junitxml={xml_path}", f"--rootdir={cwd}", "-p", "no:cacheprovider"]
        code, out = run_proc(argv, cwd, timeout=self.timeout)
        cases = parse_junit(xml_path) if xml_path else None
        if xml_path:
            with contextlib.suppress(OSError):
                os.unlink(xml_path)
        return RunResult(code, out, cases or {}, structured=cases is not None)


# --------------------------------------------------------------------------- git sandbox
class Sandbox:
    """A disposable `git worktree` holding a snapshot of the user's working tree."""

    def __init__(self, repo: Path, run_id: str, tag: str):
        self.repo = repo.resolve()
        code, top = run_proc(["git", "rev-parse", "--show-toplevel"], self.repo)
        if code:
            raise SystemExit(f"Error: {repo} is not inside a git repository ({top})")
        self.top = Path(top).resolve()
        self.rel = Path(os.path.relpath(self.repo, self.top))
        self.branch = f"agent/{run_id}-{tag}"
        self.tmp = Path(tempfile.mkdtemp(prefix="kacknex-"))
        self.wt = self.tmp / "wt"
        self.base = ""
        self.excl = self.tmp / "excludes"
        self.excl.write_text("__pycache__/\n*.pyc\n.pytest_cache/\n.mypy_cache/\n.ruff_cache/\n.coverage\n"
                             "node_modules/\n.env\n.env.*\n!.env.example\n", encoding="utf-8")
        self.root = self.wt / self.rel
        self.snapshot_note = ""

    def git(self, *args, cwd=None, raw=False, input=None, timeout=120):
        cfg = ["-c", f"core.excludesFile={self.excl.as_posix()}"]
        return run_proc(["git", *GIT_ID, *cfg, *args], cwd or self.wt, timeout=timeout, raw=raw, input=input)

    def create(self) -> None:
        with GIT_LOCK:
            code, out = self.git("worktree", "add", "-q", "-b", self.branch, str(self.wt), "HEAD", cwd=self.top)
        if code:
            raise SystemExit(f"Error: could not create worktree: {out}\n(does the repo have at least one commit?)")
        notes = []
        _, patch = self.git("diff", "HEAD", "--binary", cwd=self.top, raw=True)
        if patch.strip():
            code, out = self.git("apply", "--index", "--whitespace=nowarn", "-", input=patch)
            notes.append("tracked changes snapshotted" if not code else f"WARNING: could not snapshot tracked changes: {out[:120]}")
        _, listing = self.git("ls-files", "--others", "--exclude-standard", "-z", cwd=self.top, raw=True)
        names = [n for n in listing.decode("utf-8", "replace").split("\0") if n and not SECRET_FILE.search(n)]
        copied = 0
        for n in names[:2000]:
            src = self.top / n
            if src.is_file() and src.stat().st_size < 5_000_000:
                dst = self.wt / n
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)
                copied += 1
        if copied:
            notes.append(f"{copied} untracked file(s) copied")
        self.git("add", "-A")
        if self.git("diff", "--cached", "--quiet")[0]:
            self.git("commit", "-q", "-m", "kacknex: snapshot of working tree")
        self.base = self.git("rev-parse", "HEAD")[1].strip()
        self.root.mkdir(parents=True, exist_ok=True)
        self.snapshot_note = "; ".join(notes)

    # -- queries used by the gate
    def stage(self) -> None:
        self.git("add", "-A")

    def numstat(self) -> list[tuple[int, int, str]]:
        _, out = self.git("diff", "--cached", "--numstat", "--no-renames", self.base)
        rows = []
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) == 3:
                a, d, path = parts
                rows.append((int(a) if a.isdigit() else 1, int(d) if d.isdigit() else 1, path))
        return rows

    def name_status(self) -> dict:
        _, out = self.git("diff", "--cached", "--name-status", "--no-renames", self.base)
        return {l.split("\t", 1)[1]: l.split("\t", 1)[0] for l in out.splitlines() if "\t" in l}

    def added_lines(self) -> list[str]:
        _, out = self.git("diff", "--cached", "-U0", "--no-renames", self.base)
        return [l[1:] for l in out.splitlines() if l.startswith("+") and not l.startswith("+++")]

    def patch(self) -> bytes:
        return self.git("diff", "--cached", "--binary", "--no-renames", self.base, raw=True)[1]

    def diffstat(self) -> str:
        return self.git("diff", "--cached", "--stat", "--no-renames", self.base)[1]

    def commit(self, msg: str) -> None:
        self.stage()
        self.git("commit", "-q", "-m", msg[:200])

    @contextlib.contextmanager
    def pristine(self):
        """A second, untouched checkout of the base commit (used to prove tests fail without the fix)."""
        tmp = Path(tempfile.mkdtemp(prefix="kacknex-red-"))
        with GIT_LOCK:
            self.git("worktree", "add", "-q", "--detach", str(tmp / "wt"), self.base, cwd=self.top)
        try:
            yield tmp / "wt"
        finally:
            with GIT_LOCK:
                self.git("worktree", "remove", "--force", str(tmp / "wt"), cwd=self.top)
                self.git("worktree", "prune", cwd=self.top)
            rmtree(tmp)

    def remove(self, delete_branch: bool) -> None:
        with GIT_LOCK:
            self.git("worktree", "remove", "--force", str(self.wt), cwd=self.top)
            if delete_branch:
                self.git("branch", "-D", self.branch, cwd=self.top)
            self.git("worktree", "prune", cwd=self.top)
        rmtree(self.tmp)


# --------------------------------------------------------------------------- workspace tools
ALIASES = {
    "line_start": ("start",), "start_line": ("start",), "line_end": ("end",), "end_line": ("end",),
    "file": ("path",), "filepath": ("path",), "file_path": ("path",), "filename": ("path",),
    "path": ("subdir",), "dir": ("subdir",), "directory": ("subdir",), "folder": ("subdir",),
    "new_str": ("new",), "old_str": ("old",), "new_string": ("new",), "old_string": ("old",),
    "regex": ("pattern", "name"), "query": ("pattern", "name"), "pattern": ("name",),
    "symbol": ("name",), "identifier": ("name",), "new_text": ("text",), "content": ("text",),
    "text": ("content",), "cmd": ("command",), "extra_args": ("args",), "test_path": ("args",),
}
BLOCKED_PYTEST_ARGS = re.compile(r"^(--junitxml|--rootdir|--confcutdir|--basetemp|-p$|-c$|-o$|--override-ini)")


class Workspace:
    TOOLS = ("list_files", "read_file", "grep", "symbols", "find_references",
             "str_replace", "edit_lines", "write_file", "run_tests", "run_command")

    def __init__(self, root: Path, runner: TestRunner):
        self.root, self.runner, self.edits = root.resolve(), runner, 0

    # ---- plumbing
    def rel(self, p: Path) -> str:
        return p.relative_to(self.root).as_posix()

    def safe(self, rel: str) -> Path:
        rel = str(rel or ".").replace("\\", "/")
        p = (self.root / rel).resolve()
        if p != self.root and self.root not in p.parents:
            raise ValueError(f"path escapes the repo: {rel}")
        r = self.rel(p)
        if r == ".git" or r.startswith(".git/") or SECRET_FILE.search(r):
            raise ValueError(f"access to '{r}' is blocked by the secret guard")
        return p

    def files(self, subdir: str = ""):
        for dp, dns, fns in os.walk(self.safe(subdir or ".")):
            dns[:] = sorted(d for d in dns if d not in SKIP_DIRS)
            for f in sorted(fns):
                rel = Path(dp, f).relative_to(self.root).as_posix()
                if not SECRET_FILE.search(rel):
                    yield rel

    @staticmethod
    def _load(p: Path):
        raw = p.read_bytes()
        if b"\x00" in raw[:8192]:
            raise ValueError("binary file")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("file is not valid UTF-8")
        return text.replace("\r\n", "\n"), ("\r\n" if "\r\n" in text else "\n")

    def call(self, name: str, args: dict) -> str:
        """Whitelisted dispatcher with alias repair, int coercion and helpful errors."""
        if name not in self.TOOLS:
            return f"ERROR: unknown tool '{name}'. Available: {', '.join(self.TOOLS + ('finish',))}"
        fn = getattr(self, name)
        sig = inspect.signature(fn)
        params, clean = sig.parameters, {}
        for k, v in args.items():
            key = k if k in params else next((a for a in ALIASES.get(k, ()) if a in params), None)
            if key is None:
                return f"ERROR: unknown argument '{k}'. Signature: {name}{sig}"
            if v is None:
                continue
            if "int" in str(params[key].annotation) and not isinstance(v, int):
                try:
                    v = int(v)
                except (TypeError, ValueError):
                    return f"ERROR: argument '{k}' must be an integer"
            clean[key] = v
        missing = [n for n, pr in params.items() if pr.default is inspect.Parameter.empty and n not in clean]
        if missing:
            return f"ERROR: missing argument(s) {missing}. Signature: {name}{sig}"
        try:
            out = fn(**clean)
        except Exception as e:  # noqa: BLE001 - tool errors go back to the model
            out = f"ERROR: {type(e).__name__}: {e}"
        return redact(clip(str(out)))

    # ---- read-only tools
    def list_files(self, subdir: str = "") -> str:
        names = list(self.files(subdir))
        more = f"\n... {len(names) - 400} more" if len(names) > 400 else ""
        return "\n".join(names[:400]) + more if names else "(empty)"

    def read_file(self, path: str, start: int = 1, end: int = 0) -> str:
        p = self.safe(path)
        if not p.is_file():
            return f"ERROR: {path} is not a file"
        lines = self._load(p)[0].split("\n")
        if lines and lines[-1] == "":
            lines.pop()
        n = len(lines)
        s = max(start or 1, 1)
        e = min(end or n, n, s + 399)
        if e < s:
            return f"ERROR: empty range (file has {n} lines)"
        head = f"# {path} ({n} lines) showing {s}-{e}" + (f"; continue with start={e + 1}" if e < n else "")
        return head + "\n" + "\n".join(f"{i}: {l}" for i, l in enumerate(lines[s - 1:e], s))

    def _scan(self, rx, subdir="", limit=150):
        hits = []
        for rel in self.files(subdir):
            p = self.root / rel
            try:
                if p.stat().st_size > 1_000_000:
                    continue
                for i, line in enumerate(self._load(p)[0].split("\n"), 1):
                    if rx.search(line):
                        hits.append((rel, i, line))
                        if len(hits) >= limit:
                            return hits
            except (ValueError, OSError):
                continue
        return hits

    def grep(self, pattern: str, subdir: str = "") -> str:
        hits = self._scan(re.compile(pattern), subdir)
        return "\n".join(f"{r}:{i}:{l.strip()[:200]}" for r, i, l in hits) or "no matches"

    def find_references(self, name: str) -> str:
        defrx = re.compile(rf"^\s*(async\s+def|def|class)\s+{re.escape(name)}\b")
        hits = self._scan(re.compile(rf"\b{re.escape(name)}\b"), "")
        return "\n".join(f"{'DEF ' if defrx.search(l) else 'use '}{r}:{i}:{l.strip()[:160]}" for r, i, l in hits) or "no references"

    def symbols(self, path: str) -> str:
        """Outline of a Python file: classes, functions, signatures and line ranges."""
        p = self.safe(path)
        if p.suffix != ".py":
            return "ERROR: symbols works on .py files only; use read_file or grep."
        try:
            tree = ast.parse(self._load(p)[0])
        except SyntaxError as e:
            return f"ERROR: cannot parse {path}: {e}"
        out: list[str] = []

        def walk(body, depth):
            pad = "  " * depth
            for n in body:
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    kind = "async def" if isinstance(n, ast.AsyncFunctionDef) else "def"
                    ret = f" -> {ast.unparse(n.returns)}" if n.returns else ""
                    out.append(f"{pad}L{n.lineno}-{n.end_lineno} {kind} {n.name}({ast.unparse(n.args)}){ret}")
                    doc = ast.get_docstring(n)
                    if doc:
                        out.append(f'{pad}    "{doc.splitlines()[0][:80]}"')
                elif isinstance(n, ast.ClassDef):
                    out.append(f"{pad}L{n.lineno}-{n.end_lineno} class {n.name}({', '.join(ast.unparse(b) for b in n.bases)})")
                    walk(n.body, depth + 1)
                elif isinstance(n, ast.Assign) and depth == 0:
                    names = [t.id for t in n.targets if isinstance(t, ast.Name) and t.id.isupper()]
                    if names:
                        out.append(f"L{n.lineno} const {', '.join(names)}")

        walk(tree.body, 0)
        return "\n".join(out) or "(no top-level symbols)"

    # ---- editing tools (atomic, syntax-checked, newline-preserving)
    def _apply(self, p: Path, old: str, new: str, nl: str) -> str:
        if p.suffix == ".py":
            err = syntax_error(new)
            if err and not syntax_error(old):
                return f"ERROR: edit rejected - it would leave a syntax error: {err}. File unchanged."
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(new.replace("\n", nl).encode("utf-8"))
        self.edits += 1
        diff = "".join(list(difflib.unified_diff(old.splitlines(True), new.splitlines(True), "before", "after", n=2))[:60])
        return "OK" + self._import_warnings(new, p) + (f"\n{diff}" if diff else "")

    def _import_warnings(self, text: str, p: Path) -> str:
        if p.suffix != ".py":
            return ""
        import importlib.util
        try:
            tree = ast.parse(text)
        except SyntaxError:
            return ""
        bad = set()
        for n in ast.walk(tree):
            mods = ([a.name for a in n.names] if isinstance(n, ast.Import) else
                    [n.module] if isinstance(n, ast.ImportFrom) and n.level == 0 and n.module else [])
            for m in mods:
                top = m.split(".")[0]
                local = any((self.root / x).exists() for x in (top, f"{top}.py", f"src/{top}", f"src/{top}.py"))
                if not local:
                    try:
                        found = importlib.util.find_spec(top) is not None
                    except (ImportError, ValueError):
                        found = False
                    if not found:
                        bad.add(m)
        return f"\nWARNING: unresolved imports (do they exist?): {sorted(bad)}" if bad else ""

    def str_replace(self, path: str, old: str, new: str) -> str:
        """Replace one exact, unique occurrence of `old` with `new`."""
        p = self.safe(path)
        if not p.is_file():
            return f"ERROR: {path} does not exist (use write_file to create it)"
        text, nl = self._load(p)
        old, new = old.replace("\r\n", "\n"), new.replace("\r\n", "\n")
        if not old:
            return "ERROR: 'old' must not be empty"
        if old == new:
            return "ERROR: 'old' and 'new' are identical"
        n = text.count(old)
        if n == 1:
            return self._apply(p, text, text.replace(old, new, 1), nl)
        if n > 1:
            where = [text.count("\n", 0, m.start()) + 1 for m in re.finditer(re.escape(old), text)]
            return f"ERROR: 'old' matches {n} places (lines {where[:8]}); include more surrounding lines."
        tl, ol = text.split("\n"), old.strip("\n").split("\n")
        k, norm = len(ol), [x.rstrip() for x in ol]
        hits = [i for i in range(len(tl) - k + 1) if [x.rstrip() for x in tl[i:i + k]] == norm]
        if len(hits) == 1:  # whitespace-tolerant match
            body = new.strip("\n")
            tl[hits[0]:hits[0] + k] = body.split("\n") if body else []
            return self._apply(p, text, "\n".join(tl), nl)
        best, best_i = 0.0, -1
        target = "\n".join(norm)
        for i in range(min(len(tl) - k + 1, 4000)):
            r = difflib.SequenceMatcher(None, target, "\n".join(x.rstrip() for x in tl[i:i + k])).quick_ratio()
            if r > best:
                best, best_i = r, i
        if best >= 0.6:
            block = "\n".join(f"{j + 1}: {tl[j]}" for j in range(best_i, best_i + k))
            return f"ERROR: 'old' not found. Closest match (~{int(best * 100)}% similar), lines {best_i + 1}-{best_i + k}:\n{block}"
        return "ERROR: 'old' not found. Re-read the section with read_file and copy the text exactly."

    def edit_lines(self, path: str, start: int, end: int, text: str) -> str:
        """Replace lines start..end (inclusive, 1-based) with `text`. end=start-1 inserts before `start`; text="" deletes."""
        p = self.safe(path)
        if not p.is_file():
            return f"ERROR: {path} does not exist (use write_file to create it)"
        old, nl = self._load(p)
        had_nl = old.endswith("\n")
        lines = old.split("\n")
        if had_nl:
            lines.pop()
        n = len(lines)
        if not (1 <= start <= n + 1) or end < start - 1 or end > n:
            return f"ERROR: invalid range; file has {n} lines (start 1..{n + 1}, end start-1..{n})"
        new_lines = text.replace("\r\n", "\n").split("\n") if text else []
        if text.endswith("\n") and new_lines and new_lines[-1] == "":
            new_lines.pop()
        lines[start - 1:end] = new_lines
        return self._apply(p, old, "\n".join(lines) + ("\n" if had_nl and lines else ""), nl)

    def write_file(self, path: str, content: str) -> str:
        """Create a file or overwrite it completely."""
        p = self.safe(path)
        if p.is_dir():
            return f"ERROR: {path} is a directory"
        if len(content) > 300_000:
            return "ERROR: content too large"
        old, nl = self._load(p) if p.exists() else ("", "\n")
        return self._apply(p, old, content.replace("\r\n", "\n"), nl)

    # ---- execution tools
    def run_tests(self, args: str = "") -> str:
        extra = []
        for a in split_cmd(args):
            if BLOCKED_PYTEST_ARGS.match(a):
                return f"ERROR: argument '{a}' is not allowed"
            base = a.split("::")[0]
            if not a.startswith("-") and ("/" in base or base.endswith(".py")):
                self.safe(base)
            extra.append(a)
        return self.runner.run(self.root, extra).summary()

    def run_command(self, command: str) -> str:
        argv = split_cmd(command)
        if not argv:
            return "ERROR: empty command"
        exe = argv[0].lower().removesuffix(".exe")
        if exe in ("python", "python3", "py"):
            rest = argv[1:]
            if not rest or (rest[0].startswith("-") and rest[0] != "-m"):
                return "ERROR: only `python script.py` and `python -m <tool>` are allowed (no -c / stdin)"
            if rest[0] == "-m":
                if len(rest) < 2 or rest[1].split(".")[0] not in PY_MODULES_OK:
                    return f"ERROR: python -m is limited to {sorted(PY_MODULES_OK)}"
            else:
                self.safe(rest[0])
            argv = [sys.executable] + rest
        elif exe == "pytest":
            argv = [sys.executable, "-m", "pytest"] + argv[1:]
        elif exe == "git":
            sub = argv[1] if len(argv) > 1 else ""
            if sub not in GIT_READONLY or any(a.startswith(("--output", "--ext-diff", "--textconv", "-o")) for a in argv[2:]):
                return f"ERROR: git is limited to read-only: {sorted(GIT_READONLY)}"
            argv = [shutil.which("git") or "git", "--no-pager"] + argv[1:]
        elif exe == "node":
            if any(a in ("-e", "--eval", "-p", "--print") for a in argv[1:]):
                return "ERROR: inline node code is blocked"
            argv[0] = shutil.which("node") or "node"
        elif exe == "npm":
            if len(argv) < 2 or argv[1] not in ("test", "run", "ls"):
                return "ERROR: npm is limited to: test, run, ls"
            argv[0] = shutil.which("npm") or "npm"
        else:
            return "ERROR: allowed commands: python, pytest, git (read-only), node, npm"
        code, out = run_proc(argv, self.root, timeout=180)
        return f"exit={code}\n{out}"


# --------------------------------------------------------------------------- tool schemas
def _tool(name, desc, props, req=()):
    return {"type": "function", "function": {"name": name, "description": desc,
            "parameters": {"type": "object", "properties": props, "required": list(req)}}}


_S, _I = {"type": "string"}, {"type": "integer"}
TOOLS = [
    _tool("list_files", "List repo files (relative paths); optional subdir.", {"subdir": _S}),
    _tool("read_file", "Read a file with line numbers (max 400 lines per call).",
          {"path": _S, "start": {**_I, "description": "1-based first line"}, "end": {**_I, "description": "last line"}}, ["path"]),
    _tool("grep", "Regex search across the repo. Returns file:line:text.", {"pattern": _S, "subdir": _S}, ["pattern"]),
    _tool("symbols", "Outline of a .py file: classes/functions with signatures and line ranges. Cheaper than read_file.", {"path": _S}, ["path"]),
    _tool("find_references", "Find every definition/use of an identifier.", {"name": _S}, ["name"]),
    _tool("str_replace", "Replace ONE exact, unique occurrence of old with new in an existing file.",
          {"path": _S, "old": _S, "new": _S}, ["path", "old", "new"]),
    _tool("edit_lines", "Replace lines start..end (inclusive) with text. end=start-1 inserts; text='' deletes. Use after read_file.",
          {"path": _S, "start": _I, "end": _I, "text": _S}, ["path", "start", "end", "text"]),
    _tool("write_file", "Create a new file or fully overwrite one. Best for new tests and small files.",
          {"path": _S, "content": _S}, ["path", "content"]),
    _tool("run_tests", "Run the project's tests; returns pass/fail counts and failure details.",
          {"args": {**_S, "description": "extra pytest args, e.g. tests/test_x.py::test_y"}}),
    _tool("run_command", "Run an allowlisted command: python script.py, python -m <tool>, pytest, read-only git, node, npm test.",
          {"command": _S}, ["command"]),
    _tool("finish", "Declare the task complete. The harness verifies tests, regressions, red->green proof and diff safety.",
          {"root_cause": _S, "summary": _S, "files_changed": {"type": "array", "items": _S}}, ["root_cause", "summary"]),
]

SYSTEM = """You are Kacknex, an autonomous software engineer working in an ISOLATED git worktree of the user's repository.

Process: (1) explore with symbols / find_references / grep / read_file (small ranges), (2) form a root-cause hypothesis,
(3) make the SMALLEST change that solves the task, (4) prove it with a test, (5) run_tests, (6) call finish.

The harness enforces these rules in code - finish() is REJECTED until they hold:
- RED->GREEN: at least one test that FAILED before your change must PASS now. If no failing test reproduces the
  problem, first ADD one (new test function or new test file) that fails on the original code.
- Existing tests are append-only: never edit or delete existing assertions to get green.
- No regressions: every test that passed at baseline must still pass.
- Small diff: source changes must stay under {max_diff} changed lines; no unrelated refactors.
- Secrets: never read, print or write credentials, .env files or keys.

Tool tips:
- Never invent functions, modules or APIs; verify each via grep/symbols/find_references first.
- Use ONLY the tool names in the tool list (no repo_browser.*). run_command cannot run `python -`, heredocs or -c;
  never create helper scripts. Be decisive: usually 5-10 tool calls are enough.
- Prefer edit_lines (after read_file) or str_replace; use write_file for new files.
- If a tool call fails with malformed JSON, retry with smaller arguments, or reply with a plain-text edit block:
<<<<<<< SEARCH path/to/file.py
exact old lines (empty to create a new file)
=======
new lines
>>>>>>> REPLACE
- finish() needs root_cause (why the bug happens) and summary (what you changed and why)."""

EDIT_BLOCK = re.compile(r"<<<<<<< SEARCH[ \t]+(\S+)[ \t]*\n(.*?)=======[ \t]*\n(.*?)>>>>>>> REPLACE", re.S)


# --------------------------------------------------------------------------- agent
@dataclass
class Config:
    model: str
    max_turns: int = 25
    max_diff_lines: int = 150
    max_tokens: int = 8192
    temperature: float = 0.2
    allow_test_edits: bool = False
    require_proof: bool = True
    reasoning_effort: str | None = None
    max_rejections: int = 6


@dataclass
class Outcome:
    tag: str
    ok: bool = False
    error: str = ""
    root_cause: str = ""
    summary: str = ""
    files: list = field(default_factory=list)
    diff_lines: int = 0
    diffstat: str = ""
    patch: bytes = b""
    green: list = field(default_factory=list)
    red: list = field(default_factory=list)
    turns: int = 0
    tokens: int = 0
    secs: float = 0.0
    rejections: int = 0


class Tracer:
    def __init__(self, path: Path):
        self.path, self.lock = path, threading.Lock()

    def log(self, tag: str, event: str, **data) -> None:
        rec = {"t": round(time.time(), 2), "tag": tag, "event": event, **data}
        with self.lock, self.path.open("a", encoding="utf-8") as f:
            f.write(redact(json.dumps(rec, default=str)) + "\n")


def compact(msgs: list, budget: int = 90_000, keep_last: int = 10) -> None:
    """Shrink old tool outputs when the transcript gets large (keeps message structure intact)."""
    size = sum(len(m.get("content") or "") + len(json.dumps(m.get("tool_calls", ""))) for m in msgs)
    if size <= budget:
        return
    for m in msgs[:-keep_last]:
        c = m.get("content") or ""
        if m["role"] == "tool" and len(c) > 300 and not c.startswith("[elided"):
            m["content"] = f"[elided {len(c)} chars of older output; re-run the tool if you need it]"


class Agent:
    def __init__(self, client, cfg: Config, sb: Sandbox, runner: TestRunner, baseline: RunResult,
                 task: str, tracer: Tracer, tag: str, temperature: float):
        from openai import BadRequestError  # noqa: F401 - imported lazily so --selftest can stub it
        self.client, self.cfg, self.sb, self.runner = client, cfg, sb, runner
        self.baseline, self.task, self.tracer, self.tag, self.temp = baseline, task, tracer, tag, temperature
        self.ws = Workspace(sb.root, runner)
        self.tokens = self.rejections = 0
        self.done: dict | None = None
        self.info: dict = {}
        self.seen: dict[str, int] = {}
        self.seen_edits = 0

    def log(self, text: str) -> None:
        say(self.tag, text)

    # ---- LLM access with self-healing
    def _llm(self, msgs: list):
        from openai import (APIConnectionError, APITimeoutError, BadRequestError, InternalServerError,
                            RateLimitError)
        nudges, repairs, net = [], 0, 0
        while True:
            kw = dict(model=self.cfg.model, messages=msgs, tools=TOOLS, max_tokens=self.cfg.max_tokens,
                      temperature=min(self.temp + 0.2 * repairs, 1.0))
            if self.cfg.reasoning_effort:
                kw["extra_body"] = {"reasoning_effort": self.cfg.reasoning_effort}
            reason = ""
            try:
                resp = self.client.chat.completions.create(**kw)
                ch = resp.choices[0]
                if ch.finish_reason == "length" and ch.message.tool_calls:
                    reason = "Your last output was cut off mid tool call. Use much smaller arguments (edit_lines on a small range)."
            except (APIConnectionError, APITimeoutError, RateLimitError, InternalServerError) as e:
                net += 1
                if net > 8:
                    raise
                wait = min(2 ** net, 30)
                self.log(UI.paint(f"! network/API hiccup ({type(e).__name__}); retry {net}/8 in {wait}s", "33"))
                time.sleep(wait)
                continue
            except BadRequestError as e:
                msg_e = str(e)
                if not any(k in msg_e for k in ("tool_use_failed", "output_parse_failed", "failed_generation", "Parsing failed")):
                    raise
                reason = ("Your last reply could not be parsed (you wrote plain text or broken JSON instead of a tool call). "
                          "Do NOT explain or think out loud. Reply ONLY with a proper tool call now; if the work is done and "
                          "tests pass, call the finish tool with root_cause and summary.")
            if not reason:
                break
            repairs += 1
            if repairs > 6:
                raise RuntimeError("model kept producing unusable tool calls")
            self.log(UI.paint(f"! self-heal #{repairs}: {reason[:60]}...", "33"))
            self.tracer.log(self.tag, "self_heal", reason=reason)
            nudge = {"role": "user", "content": reason}
            msgs.append(nudge)
            nudges.append(nudge)
        msgs[:] = [m for m in msgs if not any(m is n for n in nudges)]
        u = getattr(resp, "usage", None)
        if u:
            self.tokens += (getattr(u, "prompt_tokens", 0) or 0) + (getattr(u, "completion_tokens", 0) or 0)
        return resp

    # ---- harness gate behind finish()
    def gate(self) -> list[str]:
        sb, cfg = self.sb, self.cfg
        sb.stage()
        stat_rows, status = sb.numstat(), sb.name_status()
        if not stat_rows:
            return ["no files were changed"]
        problems: list[str] = []
        src_lines = sum(a + d for a, d, p in stat_rows if not is_test_path(p))
        if src_lines > cfg.max_diff_lines:
            problems.append(f"diff too large: {src_lines} changed source lines (budget {cfg.max_diff_lines}); make a smaller, targeted fix")
        if not cfg.allow_test_edits:
            bad = [p for a, d, p in stat_rows if is_test_path(p) and (status.get(p) == "D" or (status.get(p) == "M" and d > 0))]
            if bad:
                problems.append(f"existing tests were modified/deleted: {bad}. Tests are append-only; revert those edits and fix the source instead")
        leaks = [l.strip()[:40] for l in sb.added_lines() if has_secret(l)]
        if leaks:
            problems.append("the diff contains what looks like a credential - remove it")
        now = self.runner.run(self.ws.root)
        green, red = [], set()
        if now.structured:
            regress = sorted(self.baseline.passed - now.passed)
            if regress:
                problems.append(f"regressions - these passed before and no longer do: {regress[:10]}")
            newfail = sorted(now.failed - self.baseline.failed)
            if newfail:
                problems.append(f"new failing tests (fix or remove them): {newfail[:10]}")
            if cfg.require_proof:
                newly_green = now.passed - self.baseline.passed
                if not newly_green:
                    problems.append("no red->green proof: no test that failed before now passes. Add a test that fails on the original code, then make it pass")
                else:
                    red = newly_green & self.baseline.failed
                    fresh = newly_green - set(self.baseline.cases)
                    if fresh:
                        paths = [p for _, _, p in stat_rows if is_test_path(p) and p.endswith(".py") and status.get(p) in ("A", "M")]
                        red |= self._red_check(fresh, paths)
                    if not red:
                        problems.append("your new tests also pass on the ORIGINAL code, so they do not prove the fix; write a test that fails without it")
                    green = sorted(newly_green)
        elif now.code != 0:
            problems.append(f"the test command exits with code {now.code}:\n{clip(now.out, 1500)}")
        if not problems:
            self.info = dict(green=green, red=sorted(red), diff_lines=src_lines, files=[p for _, _, p in stat_rows],
                             patch=sb.patch(), diffstat=sb.diffstat())
        return problems

    def _red_check(self, fresh: set, test_paths: list[str]) -> set:
        """Run the agent's new tests against the untouched base commit; return the ids that do NOT pass there."""
        if not test_paths:
            return set()
        with self.sb.pristine() as pw:
            for rel in test_paths:
                dst = pw / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(self.sb.wt / rel, dst)
            proot = pw / self.sb.rel
            extra = [os.path.relpath(pw / rel, proot).replace("\\", "/") for rel in test_paths]
            res = self.runner.run(proot, extra)
        return {t for t in fresh if t not in res.passed}

    def _finish(self, args: dict) -> str:
        problems = self.gate()
        self.tracer.log(self.tag, "gate", problems=problems)
        if problems:
            self.rejections += 1
            self.log(UI.paint("gate: finish rejected - " + problems[0][:90], "31"))
            return "FINISH REJECTED. Fix these, then call finish again:\n- " + "\n- ".join(problems)
        self.log(UI.paint("gate: all checks passed (red->green proven, no regressions)", "32"))
        self.done = {"root_cause": str(args.get("root_cause", "")), "summary": str(args.get("summary", ""))}
        return "Accepted."

    # ---- plain-text edit blocks (fallback when JSON tool calls keep failing)
    def _text_edits(self, content: str):
        blocks = EDIT_BLOCK.findall(content or "")
        if not blocks:
            return None
        results = []
        for path, old, new in blocks:
            old, new = old[:-1] if old.endswith("\n") else old, new[:-1] if new.endswith("\n") else new
            try:
                p = self.ws.safe(path)
                r = self.ws.write_file(path, new) if (not old and not p.exists()) else self.ws.str_replace(path, old, new)
            except Exception as e:  # noqa: BLE001
                r = f"ERROR: {e}"
            results.append(f"{path}: {r.splitlines()[0]}")
            self.log(f"  edit-block {path}: {r.splitlines()[0][:80]}")
        return "Edit blocks applied:\n" + "\n".join(results) + "\nContinue: run_tests, then finish."

    def _exec(self, name: str, args: dict, err: str | None) -> str:
        if self.done:
            return "skipped: the task is already finished"
        if err:
            return f"ERROR: {err}. Resend the call with valid JSON and smaller arguments."
        if name == "finish":
            return self._finish(args)
        if self.ws.edits != self.seen_edits:
            self.seen, self.seen_edits = {}, self.ws.edits
        sig = name + json.dumps(args, sort_keys=True, default=str)
        self.seen[sig] = self.seen.get(sig, 0) + 1
        out = self.ws.call(name, args)
        if self.seen[sig] >= 3:
            out += "\n[harness] you have repeated this exact call 3+ times without editing anything; change your approach."
        return out

    def _preload(self) -> str:
        try:
            return self._preload_unsafe()
        except Exception:  # noqa: BLE001 - a convenience feature must never crash the run
            return ""

    def _preload_unsafe(self) -> str:
        """Source files mentioned in baseline failures, so the model needs no exploration turns."""
        seen, parts = set(), []
        texts = [m for _, m in self.baseline.cases.values()] + [self.baseline.out]
        for rel in re.findall(r"([\w./\\-]+\.(?:py|js|ts))", "\n".join(t or "" for t in texts)):
            segs, p = rel.replace("\\", "/").lstrip("./").split("/"), None
            for i in range(len(segs)):  # absolute/traceback paths: drop leading parts until it resolves in the repo
                cand = "/".join(segs[i:])
                try:
                    q = self.ws.safe(cand)
                except Exception:  # noqa: BLE001
                    continue
                if q.is_file():
                    rel, p = cand, q
                    break
            if p is None or rel in seen or SECRET_FILE.search(rel):
                continue
            seen.add(rel)
            lines = self.ws._load(p)[0].split("\n")[:150]
            parts.append(f"--- {rel} ---\n" + "\n".join(f"{i}: {l}" for i, l in enumerate(lines, 1)))
            if len(parts) >= 4:
                break
        return "\n\n".join(parts)

    def _initial(self) -> list:
        listing = "\n".join(self.ws.list_files().splitlines()[:80])
        user = (f"Task: {self.task}\n\nRepository files:\n{listing}\n\nBaseline test status:\n{self.baseline.summary(max_fail=3)}\n\n"
                f"{len(self.baseline.passed)} tests pass and MUST keep passing.")
        pre = self._preload()
        if pre:
            user += f"\n\nFiles referenced by the failing tests (already loaded, no need to re-read):\n{pre}"
        return [{"role": "system", "content": SYSTEM.format(max_diff=self.cfg.max_diff_lines)},
                {"role": "user", "content": user}]

    def run(self) -> Outcome:
        t0, idle, turn = time.time(), 0, 0
        msgs: list = []
        err = "turn budget exhausted without an accepted finish()"
        try:
            msgs = self._initial()
            for turn in range(1, self.cfg.max_turns + 1):
                compact(msgs)
                resp = self._llm(msgs)
                msg = resp.choices[0].message
                calls = msg.tool_calls or []
                if not calls:
                    handled = self._text_edits(msg.content or "")
                    msgs.append({"role": "assistant", "content": msg.content or ""})
                    if handled is None:
                        idle += 1
                        if idle >= 3:
                            err = "the model stopped calling tools"
                            break
                        msgs.append({"role": "user", "content": "Continue by calling a tool. When the work is complete, call finish()."})
                    else:
                        msgs.append({"role": "user", "content": handled})
                    continue
                idle = 0
                parsed = [parse_args(tc.function.arguments) for tc in calls]
                msgs.append({"role": "assistant", "content": msg.content or "", "tool_calls": [
                    {"id": tc.id, "type": "function",
                     "function": {"name": norm_tool(tc.function.name), "arguments": json.dumps(a if not e else {})}}
                    for tc, (a, e) in zip(calls, parsed)]})
                for tc, (args, aerr) in zip(calls, parsed):
                    name = norm_tool(tc.function.name)
                    out = self._exec(name, args, aerr)
                    left = self.cfg.max_turns - turn
                    if left == 3 and not self.done:
                        out += "\n[harness] only 3 turns left - wrap up and call finish()."
                    ok = not out.startswith(("ERROR", "FINISH REJECTED"))
                    short = ", ".join(f"{k}={str(v)[:50]!r}" for k, v in args.items())[:110]
                    self.log(f"{UI.paint('✓' if ok else '✗', '32' if ok else '31')} {turn:>2}/{self.cfg.max_turns} {name}({short})" + ("" if ok else "\n      -> " + (out.splitlines() or [""])[0][:140]))
                    self.tracer.log(self.tag, "tool", turn=turn, name=name, args=args, out=out[:600])
                    msgs.append({"role": "tool", "tool_call_id": tc.id, "content": out})
                if self.done:
                    break
                if self.rejections >= self.cfg.max_rejections:
                    err = f"finish() rejected {self.rejections} times"
                    break
        except Exception as e:  # noqa: BLE001
            err = f"{type(e).__name__}: {str(e)[:300]}"
            self.tracer.log(self.tag, "fatal", error=err)
        o = Outcome(self.tag, turns=turn, tokens=self.tokens, secs=time.time() - t0, rejections=self.rejections)
        if self.done:
            i = self.info
            o.ok, o.root_cause, o.summary = True, self.done["root_cause"], self.done["summary"]
            o.files, o.diff_lines, o.diffstat, o.patch = i["files"], i["diff_lines"], i["diffstat"], i["patch"]
            o.green, o.red = i["green"], i["red"]
        else:
            o.error = err
        return o


# --------------------------------------------------------------------------- report
_HTML_CSS = """
:root{--bg:#f5f7fb;--fg:#1c2433;--card:#fff;--mut:#667085;--ok:#12805c;--okbg:#e3f6ee;--bad:#b42318;--badbg:#fdecea;--bd:#e4e7ec}
@media(prefers-color-scheme:dark){:root{--bg:#0f1420;--fg:#e8ecf4;--card:#171e2e;--mut:#9aa6bd;--ok:#4ade9b;--okbg:#10291f;--bad:#ff8a80;--badbg:#32171a;--bd:#2a3347}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.55 system-ui,Segoe UI,Arial,sans-serif}
.wrap{max-width:900px;margin:0 auto;padding:28px 18px 60px}h1{font-size:26px;margin:0 0 4px}.sub{color:var(--mut);margin-bottom:20px}
.banner{padding:18px 20px;border-radius:14px;font-size:22px;font-weight:700;margin:16px 0}.banner.ok{background:var(--okbg);color:var(--ok)}.banner.bad{background:var(--badbg);color:var(--bad)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:14px 0}.card{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:14px}
.card b{display:block;font-size:26px}.card span{color:var(--mut);font-size:13px}
section{background:var(--card);border:1px solid var(--bd);border-radius:14px;padding:18px 20px;margin:14px 0}h2{font-size:18px;margin:0 0 8px}
pre{background:#0d1117;color:#e6edf3;padding:14px;border-radius:10px;overflow:auto;font:13px/1.5 Consolas,monospace;margin:8px 0 0}
.add{color:#4ade80}.del{color:#ff7b72}.hunk{color:#79c0ff}ul{padding-left:20px;margin:6px 0}li{margin:4px 0}
.pill{display:inline-block;padding:2px 10px;border-radius:99px;font-size:13px;font-weight:600}.pill.f{background:var(--badbg);color:var(--bad)}.pill.p{background:var(--okbg);color:var(--ok)}
table{border-collapse:collapse;width:100%}td,th{text-align:left;padding:8px 6px;border-bottom:1px solid var(--bd)}small{color:var(--mut)}
"""


def write_html_report(out_dir: Path, task: str, outcomes: list, best, baseline, cfg, branch) -> None:
    """A friendly, non-technical report (open report.html in any browser)."""
    import html as H
    e = lambda x: H.escape(str(x if x is not None else ""))  # noqa: E731
    card = lambda n, label: f'<div class="card"><b>{e(n)}</b><span>{e(label)}</span></div>'  # noqa: E731
    p = [f'<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
         f'<title>Kacknex Report</title><style>{_HTML_CSS}</style></head><body><div class="wrap">',
         '<h1>Kacknex Agent Report</h1>', f'<div class="sub">Task: {e(task)}<br>Model: {e(cfg.model)}</div>']
    if best:
        p.append('<div class="banner ok">✅ Bug fixed and verified</div>')
        fixed = len(best.red) or len(best.green)
        p.append('<div class="cards">' + card(fixed, "failing test(s) now pass") + card(best.diff_lines, "lines changed")
                 + card(len(best.files), "file(s) changed") + card(f"{best.secs:.0f}s", f"{best.turns} steps taken") + '</div>')
        p.append(f'<section><h2>🔎 What was wrong</h2><p>{e(best.root_cause)}</p></section>')
        p.append(f'<section><h2>🛠️ What we changed, and why</h2><p>{e(best.summary)}</p>'
                 f'<ul>{"".join(f"<li><code>{e(f)}</code></li>" for f in best.files)}</ul></section>')
        p.append('<section><h2>🧪 What was failing before</h2><pre>' + e(clip(baseline.summary(max_fail=3), 1500)) + '</pre></section>')
        diff = []
        for ln in best.patch.decode("utf-8", "replace").splitlines():
            cls = "hunk" if ln.startswith("@@") else "add" if ln.startswith("+") and not ln.startswith("+++") \
                else "del" if ln.startswith("-") and not ln.startswith("---") else ""
            diff.append(f'<span class="{cls}">{e(ln)}</span>')
        p.append('<section><h2>📝 The exact change</h2><small>Red = removed, green = added</small><pre>' + "\n".join(diff) + '</pre></section>')
        if best.green:
            rows = "".join(f'<tr><td><code>{e(t)}</code></td><td><span class="pill f">{"FAIL" if t in best.red else "n/a"}</span></td>'
                           f'<td><span class="pill p">PASS</span></td></tr>' for t in best.green)
            p.append(f'<section><h2>✅ Proof it works</h2><table><tr><th>Test</th><th>Before</th><th>After</th></tr>{rows}</table></section>')
        checks = [f"Nothing that worked before is broken ({len(baseline.passed)} earlier tests still pass)",
                  f"Change is small ({best.diff_lines} lines, limit {cfg.max_diff_lines})",
                  "Existing tests were not edited to fake a pass" if not cfg.allow_test_edits else "Test edits were allowed for this run",
                  "No passwords or keys in the change", "Worked in a private copy, so your files were safe until the fix was proven"]
        p.append('<section><h2>🛡️ Safety checks passed</h2><ul>' + "".join(f"<li>✅ {e(c)}</li>" for c in checks) + '</ul></section>')
        if branch:
            p.append(f'<section><h2>Where is the fix?</h2><p>Saved as <code>patch.diff</code> in this folder and on git branch <code>{e(branch)}</code>. '
                     f'If you did not choose "apply", your own files are unchanged.</p></section>')
    else:
        p.append('<div class="banner bad">❌ No safe fix was found</div>')
        p.append('<section><h2>What happened</h2><p>The agent could not produce a fix that passed every safety check, '
                 '<b>so it changed nothing in your files</b>.</p><ul>'
                 + "".join(f"<li>{e(o.error)}</li>" for o in outcomes) + '</ul>'
                 '<p><small>Tip: just run it again (AI output varies between runs), check your internet connection, or describe the problem more precisely.</small></p></section>')
        p.append('<section><h2>What was failing</h2><pre>' + e(clip(baseline.summary(max_fail=3), 1500)) + '</pre></section>')
    p.append('</div></body></html>')
    (out_dir / "report.html").write_text("".join(p), encoding="utf-8")



def write_report(out_dir: Path, task: str, outcomes: list[Outcome], best: Outcome | None,
                 baseline: RunResult, cfg: Config, branch: str | None) -> str:
    L = ["# Kacknex Agent Report", "", f"**Task:** {task}", f"**Model:** `{cfg.model}`", ""]
    if best:
        L += [f"**Result:** ✅ success ({best.tag}, {best.turns} turns, {best.secs:.0f}s, ~{best.tokens} tokens)", ""]
        if branch:
            L += [f"**Branch:** `{branch}` (review with `git diff HEAD...{branch}`) · patch: `patch.diff`", ""]
        L += ["## What was failing before the fix", "```", clip(baseline.summary(max_fail=3), 1500), "```", "", "## Root cause", best.root_cause, "", "## Summary", best.summary, "", "## Proof of fix (red → green)"]
        if best.green:
            L += ["| test | before | after |", "|---|---|---|"]
            L += [f"| `{t}` | {'FAIL' if t in best.red else 'n/a'} | PASS |" for t in best.green]
        else:
            L += ["_proof gate disabled or non-pytest runner_"]
        L += ["", "## Gates passed",
              f"- ✅ no regressions ({len(baseline.passed)} baseline tests still pass)",
              f"- ✅ source diff {best.diff_lines} ≤ {cfg.max_diff_lines} changed lines",
              "- ✅ existing tests untouched (append-only)" if not cfg.allow_test_edits else "- ⚠️ test edits were allowed",
              "- ✅ no credentials in diff · env scrubbed · secret files unreadable",
              "- ✅ every edit syntax-checked · worked in an isolated git worktree", "",
              "## Files changed", *[f"- `{f}`" for f in best.files], "", "## Diff stat", "```", best.diffstat, "```"]
    else:
        L += ["**Result:** ❌ no candidate passed the gates; nothing was applied.", ""]
        L += [f"- {o.tag}: {o.error}" for o in outcomes]
    if len(outcomes) > 1:
        L += ["", "## Candidates", "| candidate | result | diff lines | turns | tokens | rejections |", "|---|---|---|---|---|---|"]
        L += [f"| {o.tag} | {'✅' if o.ok else '❌ ' + o.error[:40]} | {o.diff_lines} | {o.turns} | {o.tokens} | {o.rejections} |" for o in outcomes]
    text = "\n".join(L) + "\n"
    (out_dir / "report.md").write_text(text, encoding="utf-8")
    try:
        write_html_report(out_dir, task, outcomes, best, baseline, cfg, branch)
    except Exception:  # noqa: BLE001 - the pretty report must never break a run
        pass
    return text


# --------------------------------------------------------------------------- main
def run_session(client, repo: Path, task: str, cfg: Config, runner: TestRunner, n: int, out_dir: Path,
                apply: bool, run_id: str):
    """Returns (best_outcome|None, outcomes, baseline, branch|None)."""
    UI.multi = n > 1
    tracer = Tracer(out_dir / "trace.jsonl")
    sandboxes = [Sandbox(repo, run_id, f"c{i + 1}") for i in range(n)]
    best, outcomes, baseline, winner = None, [], RunResult(0, ""), None
    try:
        for sb in sandboxes:
            sb.create()
        if sandboxes[0].snapshot_note:
            say("setup", f"snapshot of your working tree: {sandboxes[0].snapshot_note}")
        baseline = runner.run(sandboxes[0].root)
        say("setup", f"baseline: {len(baseline.passed)} passing, {len(baseline.failed)} failing"
            + ("" if baseline.structured else " (non-pytest runner: exit-code gating only)"))
        if baseline.structured and not baseline.cases:
            say("setup", UI.paint("warning: no tests collected - the agent must add a test to prove its fix", "33"))
        agents = [Agent(client, cfg, sb, runner, baseline, task, tracer, sb.branch.rsplit("-", 1)[-1],
                        min(cfg.temperature + 0.15 * i, 0.9)) for i, sb in enumerate(sandboxes)]
        with cf.ThreadPoolExecutor(max_workers=n) as ex:
            outcomes = list(ex.map(lambda a: a.run(), agents))
        winners = [(o, sb) for o, sb in zip(outcomes, sandboxes) if o.ok]
        if winners:
            best, winner = min(winners, key=lambda t: (t[0].diff_lines, t[0].turns))
            (out_dir / "patch.diff").write_bytes(best.patch)
            winner.commit(f"kacknex: {task}"[:100])
            if apply:
                code, msg = run_proc(["git", "apply", "--whitespace=nowarn", "--ignore-whitespace", str((out_dir / "patch.diff").resolve())], winner.top)
                say("apply", "patch applied to your working tree" if not code else f"could not apply patch: {msg[:200]}")
    finally:
        for sb in sandboxes:
            sb.remove(delete_branch=(sb is not winner))
    return best, outcomes, baseline, (winner.branch if winner else None)


def build_parser():
    ap = argparse.ArgumentParser(description="Kacknex SWE Agent - sandboxed, proof-gated AI software engineer")
    ap.add_argument("--repo", help="path to a git repository (or a folder inside one)")
    ap.add_argument("--task", help="what the agent should do")
    ap.add_argument("--test-cmd", help="test command (default: python -m pytest -q)")
    ap.add_argument("--model", help="override AGENT_MODEL")
    ap.add_argument("--candidates", type=int, default=1, help="parallel independent attempts; smallest passing patch wins")
    ap.add_argument("--max-turns", type=int, default=25)
    ap.add_argument("--max-diff-lines", type=int, default=150)
    ap.add_argument("--temperature", type=float, default=0.2)
    ap.add_argument("--reasoning-effort", choices=["low", "medium", "high"])
    ap.add_argument("--allow-test-edits", action="store_true", help="let the agent modify existing tests")
    ap.add_argument("--no-proof", action="store_true", help="skip the red->green proof (refactors, docs)")
    ap.add_argument("--apply", action="store_true", help="apply the winning patch to your working tree")
    ap.add_argument("--out", default="agent_runs", help="folder for report/patch/trace")
    ap.add_argument("--no-open", action="store_true", help="do not open the HTML report in the browser when done")
    ap.add_argument("--selftest", action="store_true", help="offline demo of the harness (no API key)")
    return ap


def main() -> None:
    for s in (sys.stdout, sys.stderr):
        if hasattr(s, "reconfigure"):
            s.reconfigure(encoding="utf-8", errors="replace")
    if os.name == "nt":
        os.system("")  # enable ANSI colours in Windows terminals
    a = build_parser().parse_args()
    if a.selftest:
        sys.exit(selftest())
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass
    if not (a.repo and a.task):
        sys.exit("Error: --repo and --task are required (or use --selftest)")
    if not Path(a.repo).is_dir():
        sys.exit(f"Error: the folder '{a.repo}' does not exist. Check the path (run `dir` to see what is in the current folder).")
    key = os.getenv("OPENAI_API_KEY")
    if not key:
        sys.exit("Error: OPENAI_API_KEY is not set (put it in .env next to agent.py)")
    from openai import OpenAI
    cfg = Config(model=a.model or os.getenv("AGENT_MODEL", "openai/gpt-oss-120b"), max_turns=a.max_turns,
                 max_diff_lines=a.max_diff_lines, temperature=a.temperature, allow_test_edits=a.allow_test_edits,
                 require_proof=not a.no_proof, reasoning_effort=a.reasoning_effort or "low")
    client = OpenAI(base_url=os.getenv("OPENAI_BASE_URL", "https://api.groq.com/openai/v1"), api_key=key,
                    max_retries=3, timeout=60)
    run_id = time.strftime("%Y%m%d-%H%M%S")
    out_dir = Path(a.out) / run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    print(UI.paint(f"Kacknex SWE Agent · model={cfg.model} · candidates={a.candidates} · out={out_dir}", "1"))
    try:
        best, outcomes, baseline, branch = run_session(client, Path(a.repo), a.task, cfg, TestRunner.from_string(a.test_cmd),
                                                      max(1, a.candidates), out_dir, a.apply, run_id)
    except KeyboardInterrupt:
        sys.exit("\nInterrupted - worktrees cleaned up.")
    print("\n" + write_report(out_dir, a.task, outcomes, best, baseline, cfg, branch))
    html_report = out_dir / "report.html"
    if html_report.exists() and not a.no_open:
        try:
            import webbrowser
            webbrowser.open(html_report.resolve().as_uri())
            print(f"Opened the report in your browser: {html_report}")
        except Exception:  # noqa: BLE001
            print(f"Open this report in your browser: {html_report}")
    sys.exit(0 if best else 1)


# --------------------------------------------------------------------------- offline self-test
def selftest() -> int:
    """Scripted fake LLM + throw-away repo: exercises self-heal, aliases, anti-cheat gate and red->green."""
    from types import SimpleNamespace as NS
    from openai import APIConnectionError, BadRequestError

    class NetDrop(APIConnectionError):
        def __init__(self):
            Exception.__init__(self, "Connection error.")

    class ToolUseFailed(BadRequestError):
        def __init__(self):
            Exception.__init__(self, "400 tool_use_failed: Failed to parse tool call arguments as JSON")

    def call(i, name, args):
        raw = args if isinstance(args, str) else json.dumps(args)
        return NS(id=f"c{i}", function=NS(name=name, arguments=raw))

    script = [
        [call(1, "repo_browser.read_file", {"file": "math_utils.py", "line_start": "1"})],            # tool-name + arg aliases + coercion
        NetDrop(),                                                                                    # network drop -> auto retry
        ToolUseFailed(),                                                                              # Groq-style failure
        [call(2, "str_replace", '{"path": "math_utils.py", "old": "return a - b"')],                # truncated JSON
        [call(3, "str_replace", {"path": "test_math.py", "old": "== 5", "new": "== -1"})],         # cheating attempt
        [call(4, "finish", {"root_cause": "cheat", "summary": "cheat"})],                            # -> rejected
        [call(5, "str_replace", {"path": "test_math.py", "old": "== -1", "new": "== 5"})],          # revert the test
        [call(6, "edit_lines", {"path": "math_utils.py", "start": 2, "end": 2, "text": "    return a + b"})],
        [call(7, "finish", {"root_cause": "add() subtracted instead of adding", "summary": "return a + b"})],
    ]

    def create(**kw):
        step = script.pop(0)
        if isinstance(step, Exception):
            raise step
        return NS(choices=[NS(finish_reason="tool_calls", message=NS(content="", tool_calls=step))],
                  usage=NS(prompt_tokens=10, completion_tokens=5))

    client = NS(chat=NS(completions=NS(create=create)))
    work = Path(tempfile.mkdtemp(prefix="kacknex-selftest-"))
    try:
        (work / "math_utils.py").write_text("def add(a, b):\n    return a - b\n", encoding="utf-8")
        (work / "test_math.py").write_text("from math_utils import add\n\n\ndef test_add():\n    assert add(2, 3) == 5\n", encoding="utf-8")
        for cmd in (["init", "-q"], ["add", "-A"], ["commit", "-q", "-m", "init"]):
            run_proc(["git", *GIT_ID, *cmd], work)
        out_dir = work / "_out"
        out_dir.mkdir()
        cfg = Config(model="fake", max_turns=12)
        best, outs, baseline, branch = run_session(client, work, "Fix add()", cfg, TestRunner.from_string(None), 1, out_dir, False, "selftest")
        checks = [("agent finished successfully", bool(best)),
                  ("anti-cheat gate bounced the test edit", outs[0].rejections == 1),
                  ("red->green proof recorded", bool(best and best.red)),
                  ("patch contains the fix", bool(best and b"return a + b" in best.patch)),
                  ("survived a network drop", not any(isinstance(x, Exception) for x in script) and bool(best)),
                  ("your working tree was never touched", "a - b" in (work / "math_utils.py").read_text(encoding="utf-8")),
                  ("winning branch kept", bool(branch and run_proc(["git", "rev-parse", "--verify", branch], work)[0] == 0))]
        for name, ok in checks:
            print(f"  {'PASS' if ok else 'FAIL'}  {name}")
        return 0 if all(ok for _, ok in checks) else 1
    finally:
        rmtree(work)


if __name__ == "__main__":
    main()