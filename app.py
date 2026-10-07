#!/usr/bin/env python3
"""Kacknex - point-and-click window for the agent (no command line needed).

Double-click "Start Kacknex.bat" (Windows) or run:  python app.py
"""
import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext

HERE = Path(__file__).resolve().parent


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Kacknex - AI Software Engineer")
        self.geometry("820x640")
        self.q: "queue.Queue[str|None]" = queue.Queue()
        self.repo = tk.StringVar()
        self.apply = tk.BooleanVar(value=True)
        pad = {"padx": 12, "pady": 6}

        tk.Label(self, text="Kacknex", font=("Segoe UI", 20, "bold")).pack(anchor="w", **pad)
        tk.Label(self, text="An AI engineer that must prove its fix before it changes your code.",
                 fg="#555").pack(anchor="w", padx=12)

        tk.Label(self, text="1. Choose your project folder", font=("Segoe UI", 11, "bold")).pack(anchor="w", **pad)
        row = tk.Frame(self)
        row.pack(fill="x", padx=12)
        tk.Entry(row, textvariable=self.repo).pack(side="left", fill="x", expand=True)
        tk.Button(row, text="Browse...", command=self.browse).pack(side="left", padx=6)

        tk.Label(self, text="2. Describe the problem or the change you want (plain English)",
                 font=("Segoe UI", 11, "bold")).pack(anchor="w", **pad)
        self.task = tk.Text(self, height=4, wrap="word")
        self.task.pack(fill="x", padx=12)
        self.task.insert("1.0", "The tests are failing. Find out why and fix it.")

        tk.Checkbutton(self, variable=self.apply,
                       text="Apply the fix to my files when it is proven (untick to only preview it)").pack(anchor="w", **pad)

        self.btn = tk.Button(self, text="▶  Fix it", font=("Segoe UI", 12, "bold"), bg="#2563eb", fg="white",
                             command=self.start)
        self.btn.pack(fill="x", padx=12, pady=6)
        self.status = tk.Label(self, text="Ready.", anchor="w", fg="#333")
        self.status.pack(fill="x", padx=12)

        self.log = scrolledtext.ScrolledText(self, height=14, state="disabled", bg="#111827", fg="#e5e7eb",
                                             font=("Consolas", 9))
        self.log.pack(fill="both", expand=True, padx=12, pady=8)
        self.after(100, self.pump)

    def browse(self):
        d = filedialog.askdirectory(title="Choose the project folder")
        if d:
            self.repo.set(d)

    def write(self, text):
        self.log.configure(state="normal")
        self.log.insert("end", text)
        self.log.see("end")
        self.log.configure(state="disabled")

    def start(self):
        repo, task = self.repo.get().strip(), self.task.get("1.0", "end").strip()
        if not repo or not Path(repo).is_dir():
            return messagebox.showwarning("Kacknex", "Please choose your project folder first.")
        if not task:
            return messagebox.showwarning("Kacknex", "Please describe what should be fixed or changed.")
        if not (HERE / ".env").exists():
            return messagebox.showerror("Kacknex", "No .env file found next to agent.py.\nIt must contain your OPENAI_API_KEY.")
        self.btn.configure(state="disabled", text="Working...")
        self.status.configure(text="The agent is working. This usually takes under a minute.")
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")
        threading.Thread(target=self.run_agent, args=(repo, task), daemon=True).start()

    def run_agent(self, repo, task):
        cmd = [sys.executable, str(HERE / "agent.py"), "--repo", repo, "--task", task, "--no-open"]
        if self.apply.get():
            cmd.append("--apply")
        env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1", NO_COLOR="1")
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            p = subprocess.Popen(cmd, cwd=str(HERE), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                 encoding="utf-8", errors="replace", env=env, creationflags=flags)
            for line in p.stdout:
                self.q.put(line)
            code = p.wait()
        except Exception as e:  # noqa: BLE001
            self.q.put(f"\nCould not start the agent: {e}\n")
            code = 1
        self.q.put(("done", code))

    def pump(self):
        try:
            while True:
                item = self.q.get_nowait()
                if isinstance(item, tuple):
                    self.finish(item[1])
                else:
                    self.write(item)
        except queue.Empty:
            pass
        self.after(100, self.pump)

    def finish(self, code):
        self.btn.configure(state="normal", text="▶  Fix it")
        runs = sorted((HERE / "agent_runs").glob("*/report.html"), key=lambda p: p.stat().st_mtime) if (HERE / "agent_runs").exists() else []
        if code == 0:
            self.status.configure(text="✅ Done - the fix is proven. Opening your report...", fg="#047857")
        else:
            self.status.configure(text="❌ No safe fix was found, so nothing was changed. Opening the report...", fg="#b91c1c")
        if runs:
            webbrowser.open(runs[-1].as_uri())


if __name__ == "__main__":
    App().mainloop()