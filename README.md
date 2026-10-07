# Kacknex SWE Agent

**An AI software engineer that must prove its fix before it is allowed to change your code.**

Submission for hackathon **HNX26PSI09: AI Software Engineering Agent** (Generative AI, Coding Agents, Software Engineering).

---

## Table of contents

1. [What the project does](#1-what-the-project-does)
2. [Technologies, libraries and models used](#2-technologies-libraries-and-models-used)
3. [How to install dependencies](#3-how-to-install-dependencies)
4. [How to configure and run the system](#4-how-to-configure-and-run-the-system)
5. [How to reproduce the demonstrated results](#5-how-to-reproduce-the-demonstrated-results)
6. [How it works](#6-how-it-works)
7. [Safety rules enforced by the code](#7-safety-rules-enforced-by-the-code)
8. [All command-line options](#8-all-command-line-options)
9. [Troubleshooting](#9-troubleshooting)
10. [Limitations](#10-limitations)
11. [Project files](#11-project-files)

---

## 1. What the project does

Real codebases are large. Kacknex is an agent that takes an existing project and a task written in plain English (for example *"Customers say discounted totals in the cart are wrong. Find out why and fix it"*) and then:

1. **Reads** the codebase (search, file outlines, reference lookup, small file reads).
2. **Understands** how it works well enough to state a root cause.
3. **Makes the requested change or fixes the bug** with the smallest possible edit, across multiple files if needed.
4. **Proves it did not break anything.** A test that failed before must now pass, and every test that passed before must still pass.
5. **Explains itself** in a report: what was wrong, what changed and why, and the proof.

What makes it different from a plain "LLM plus tools" loop is that the safety rules are enforced **by the program, not just requested in the prompt**. The AI is not allowed to finish until the checks pass. If it cannot pass them, it changes nothing.

Everything happens in a private temporary copy (a git worktree) of your project. Your real files are only modified if you pass `--apply` (or tick the box in the window app), and only after the fix is proven.

**Two ways to use it:** a point-and-click window (no command line needed) and a command line.

---

## 2. Technologies, libraries and models used

| Category | Details |
|---|---|
| Language | Python 3.10 or newer |
| AI model | `openai/gpt-oss-120b` (open-weight model) served through the **Groq** API |
| API client | `openai` Python SDK, pointed at Groq's OpenAI-compatible endpoint (`https://api.groq.com/openai/v1`) |
| Configuration | `python-dotenv` (reads the `.env` file) |
| Testing | `pytest` (used to measure pass/fail before and after a fix, and to run the target project's tests) |
| Version control | `git` (private worktrees for sandboxing, patch creation and application) |
| Window app | `tkinter` (ships with Python) |
| Standard library | `subprocess`, `ast`, `difflib`, `concurrent.futures`, `json`, `re`, `pathlib`, `webbrowser` and others |

Any other OpenAI-compatible service and model can be used by changing `OPENAI_BASE_URL` and `AGENT_MODEL` in `.env`.

---

## 3. How to install dependencies

**Requirements:** Python 3.10+, Git, and an internet connection.

```bash
git clone <this-repository-url>
cd <repository-folder>
pip install -r requirements.txt
```

`requirements.txt` contains:

```
openai>=1.40
python-dotenv>=1.0
pytest>=8.0
```

Check your tools:

```bash
python --version
git --version
```

---

## 4. How to configure and run the system

### 4.1 Configure

You need an API key from [Groq](https://console.groq.com) (or another OpenAI-compatible provider).

1. Copy the example settings file to `.env`:
   - Windows PowerShell: `Copy-Item .env.example .env`
   - macOS / Linux: `cp .env.example .env`
2. Open `.env` and paste your key:

```
OPENAI_API_KEY=your_api_key_here
OPENAI_BASE_URL=https://api.groq.com/openai/v1
AGENT_MODEL=openai/gpt-oss-120b
```

`.env` is listed in `.gitignore`. **Never commit your key.**

### 4.2 Check the install (no API key needed)

```bash
python agent.py --selftest
```

This runs an offline demo of the safety harness with a scripted fake model and prints a list of `PASS` lines.

### 4.3 Run it: the window app (no commands)

- Windows: double-click **`Start Kacknex.bat`**
- Any system: `python app.py`

Then: **Browse** to the project folder, describe the problem in plain English, leave "Apply the fix" ticked, and click **Fix it**. The report opens in your browser when it finishes.

### 4.4 Run it: the command line

```bash
python agent.py --repo <project folder> --task "<what to fix or change>"
```

Examples:

```bash
# Preview a fix (your files stay unchanged)
python agent.py --repo ./demo-repo --task "Customers say discounted totals in the cart are wrong. Find out why and fix it"

# Fix it and write the change into your files
python agent.py --repo ./demo-repo --task "Customers say discounted totals in the cart are wrong. Find out why and fix it" --apply

# Most reliable: three independent attempts, keep the smallest one that passes every check
python agent.py --repo ./demo-repo --task "Customers say discounted totals in the cart are wrong. Find out why and fix it" --apply --candidates 3

# Add a feature (allow a larger change)
python agent.py --repo ./demo-repo --task "Add a remove(name) method to the Cart class that deletes all items with that name, keeping everything else working" --apply --max-diff-lines 300

# A project that does not use pytest
python agent.py --repo ./myproject --task "..." --test-cmd "npm test"
```

The target folder must be a git repository (the agent uses git worktrees). The demo project below is created as one automatically.

### 4.5 Where the results go

Every run creates `agent_runs/<date-time>/` containing:

| File | Contents |
|---|---|
| `report.html` | Friendly report (opens in your browser automatically; use `--no-open` to disable) |
| `report.md` | The same report as plain text |
| `patch.diff` | The exact change (removed lines and added lines) |
| `trace.jsonl` | Log of every step the agent took |

---

## 5. How to reproduce the demonstrated results

The demo is a small shopping-cart project with a bug that appears in two places: the discount function subtracts the percent as if it were a price (a 10% discount on 200 gives 190 instead of 180), and the cart total uses that function, so cart totals are wrong too.

### Step 1: Create the demo project

```bash
python make_demo.py
```

This creates `demo-repo/` as a git repository with 7 tests. Run it again at any time to reset the bug.

### Step 2: Confirm the bug

```bash
python -m pytest demo-repo -q
```

**Expected:** `2 failed, 5 passed`. The two failures are `test_ten_percent_discount` (`assert 190 == 180`) and `test_total_with_discount` (`assert 60 == 80`). The five passing tests must keep passing.

### Step 3: Run the agent

```bash
python agent.py --repo ./demo-repo --task "Customers say discounted totals in the cart are wrong. Find out why and fix it" --apply
```

The task describes only the symptom; it does not name the function or file.

**Expected:**

- Live step-by-step output in the terminal, ending with a line like `gate: all checks passed (red->green proven, no regressions)`.
- The report opens in your browser: **Bug fixed and verified**, a root cause (the discount subtracts a number instead of applying a percentage), the exact change in `cart/pricing.py`, and a before/after table showing both failing tests going from FAIL to PASS.
- Only the source file is changed. The test files are untouched.

### Step 4: Verify the result

```bash
python -m pytest demo-repo -q
```

**Expected:** `7 passed`.

### Notes on reproducibility

- AI output varies between runs. If a run ends with "No safe fix was found", **nothing was changed**; simply run it again, or use `--candidates 3` for three independent attempts.
- A failed run is the safety design working: the agent refuses to apply a fix it cannot prove.
- Results depend on a working internet connection and a valid API key.

### Optional: the feature-addition task

Reset with `python make_demo.py`, then run the "Add a `remove(name)` method" command from section 4.4. The agent must write its own new test (none exists yet), and the harness re-runs that test on the original code to prove it really fails without the feature.

---

## 6. How it works

1. **Snapshot.** The project, including uncommitted changes, is copied into a private git worktree.
2. **Baseline.** The tests run once to record what passes and what fails today.
3. **Explore.** The model uses search, file outlines, reference lookup and small file reads. Files named in the failing test errors are shown to it up front, so it can start fixing immediately.
4. **Fix.** It makes the smallest edit it can. Every edit is syntax-checked before it is saved.
5. **Prove.** When the model asks to finish, the **gate** checks everything (section 7). If anything fails, the model is told exactly why and must try again.
6. **Report.** Root cause, summary, patch, proof and files changed.

**Built-in self-repair:** network drops, timeouts and rate limits are retried automatically with increasing waits; broken model output (bad JSON or plain text instead of a tool call) is detected and retried; wrong tool names such as `repo_browser.list_files` are mapped to real tools; wrong argument names and types are corrected.

**Tournament mode:** `--candidates N` runs N independent agents in parallel worktrees and keeps the smallest patch that passes every gate.

---

## 7. Safety rules enforced by the code

| Rule | Meaning |
|---|---|
| **Red to green proof** | A test that failed before must pass now. If none exists, the model must add one, and the program re-runs it on the original code to prove it fails without the fix. |
| **No regressions** | Every test that passed before must still pass. |
| **Existing tests are append-only** | The model cannot edit or delete existing tests to fake a pass. |
| **Small change budget** | 150 changed lines of real code by default (`--max-diff-lines`). |
| **No invented code** | The model must verify functions and imports before using them; the harness warns about imports that cannot be resolved. |
| **Secret guard** | `.env` and key files are unreadable, API keys are removed from child-process environments and outputs, and the final change is scanned for credentials. |
| **Sandbox** | All work happens in a throw-away copy; rollback is deleting it. |
| **Limited commands** | Only `python`, `pytest`, read-only `git`, `node` and `npm test` may run. |

---

## 8. All command-line options

| Option | What it does | Default |
|---|---|---|
| `--repo PATH` | Project folder to work on (required) | none |
| `--task "TEXT"` | What to fix or change in plain English (required) | none |
| `--apply` | Write the proven fix into your real files | off (preview only) |
| `--candidates N` | Parallel independent attempts; smallest passing fix wins | 1 |
| `--test-cmd "CMD"` | Command that runs the project's tests | `python -m pytest -q` |
| `--model NAME` | Use a different model than `AGENT_MODEL` | from `.env` |
| `--max-turns N` | Maximum steps the agent may take | 25 |
| `--max-diff-lines N` | Maximum changed lines of real code | 150 |
| `--temperature X` | Model randomness | 0.2 |
| `--reasoning-effort low/medium/high` | How hard the model thinks | low |
| `--allow-test-edits` | Let the agent edit existing tests | off |
| `--no-proof` | Skip the red-to-green proof (refactors, docs) | off |
| `--no-open` | Do not open the HTML report in the browser | off |
| `--out FOLDER` | Where reports are saved | `agent_runs` |
| `--selftest` | Offline demo of the safety harness (no key needed) | off |

---

## 9. Troubleshooting

| What you see | What to do |
|---|---|
| `OPENAI_API_KEY is not set` | Create `.env` next to `agent.py` (section 4.1). |
| `No module named 'openai'` or `'pytest'` | `pip install -r requirements.txt` |
| `Connection error` | The agent retries by itself; if it still fails, check your internet and run again. |
| `No safe fix was found` | Nothing was changed. Run again, use `--candidates 3`, or describe the problem more precisely. |
| `the folder './xyz' does not exist` | Check the path. `make_demo.py` must be next to `agent.py`. |
| `could not apply patch` | Apply the saved fix by hand: `git -C <project> apply --ignore-whitespace agent_runs/<run>/patch.diff` |
| Git asks who you are when committing | `git config --global user.name "Your Name"` and `git config --global user.email "you@example.com"` |
| `source code string cannot contain null bytes` | A file was saved as UTF-16 (PowerShell's `>` does this). Recreate it with `Set-Content -Encoding ascii` or save it as UTF-8. |
| The browser did not open | Open `agent_runs/<latest>/report.html` by hand. |

---

## 10. Limitations

- It relies on the AI model, so very large or tricky codebases can still beat it, and results vary between runs.
- It needs the internet and a valid API key.
- The proof works best when the project has runnable tests. With no tests, the agent writes its own, which is a weaker proof than an existing suite.
- The default change budget can block large features; raise it with `--max-diff-lines`.
- The task description must say roughly what is wrong or wanted. The agent finds *where*; it cannot guess *what you want*.

---

## 11. Project files

| File | Purpose |
|---|---|
| `agent.py` | The agent and its safety harness (main program) |
| `app.py` | Point-and-click window app |
| `Start Kacknex.bat` | Double-click launcher for the window app (Windows) |
| `make_demo.py` | Creates and resets the demo project used in section 5 |
| `requirements.txt` | Python packages to install |
| `.env.example` | Template for your private `.env` settings |
| `.gitignore` | Keeps `.env`, run outputs and demo projects out of git |
| `agent_runs/` | Reports, patches and logs (created when you run the agent) |
| `demo-repo/` | Demo project (created by `make_demo.py`) |