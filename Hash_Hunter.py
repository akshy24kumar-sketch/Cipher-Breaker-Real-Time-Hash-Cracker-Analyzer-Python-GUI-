#!/usr/bin/env python3
# filename: Hash_Hunter.py
"""
Hash_Hunter (GUI) - Final version with export + live stats

Supports automatic checking of:
 - MD5
 - SHA-1
 - SHA-256 (SHA-2 family)
 - PBKDF2-HMAC-SHA256 (with optional salt/iterations or parsing of iterations$salt$hex)
 - bcrypt (if bcrypt package installed)
 - Argon2 (if argon2-cffi package installed)

Provides an Export button to save found results to a .txt file.
"""

import tkinter as tk
from tkinter import filedialog, messagebox, ttk, scrolledtext
import hashlib
import threading
import time
import os
from datetime import timedelta

# Optional dependencies: bcrypt, argon2
_have_bcrypt = False
_have_argon2 = False
try:
    import bcrypt
    _have_bcrypt = True
except Exception:
    _have_bcrypt = False

try:
    from argon2 import PasswordHasher, exceptions as argon2_exceptions
    _have_argon2 = True
    _argon2_ph = PasswordHasher()
except Exception:
    _have_argon2 = False
    _argon2_ph = None

# ---------------- Helper hash functions ----------------
def md5_hex(s: str) -> str:
    return hashlib.md5(s.encode('utf-8', errors='replace')).hexdigest()

def sha1_hex(s: str) -> str:
    return hashlib.sha1(s.encode('utf-8', errors='replace')).hexdigest()

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode('utf-8', errors='replace')).hexdigest()

def pbkdf2_hex(s: str, salt: bytes, iterations: int) -> str:
    return hashlib.pbkdf2_hmac('sha256', s.encode('utf-8', errors='replace'), salt or b'', iterations).hex()

def try_check_bcrypt(word: str, target_hash: str) -> bool:
    if not _have_bcrypt:
        return False
    try:
        return bcrypt.checkpw(word.encode('utf-8', errors='replace'), target_hash.encode('utf-8', errors='replace'))
    except Exception:
        return False

def try_check_argon2(word: str, target_hash: str) -> bool:
    if not _have_argon2:
        return False
    try:
        return _argon2_ph.verify(target_hash, word)
    except Exception:
        return False

def parse_pbkdf2_target(target: str):
    """
    Try to parse PBKDF2 targets formatted as:
      iterations$salt$hex
    or  pbkdf2$iterations$salt$hex
    Returns (iterations:int, salt:bytes, hexhash:str) or None.
    """
    if '$' not in target:
        return None
    parts = target.split('$')
    if len(parts) == 3:
        try:
            iterations = int(parts[0])
            salt = parts[1].encode('utf-8', errors='replace')
            hexhash = parts[2]
            return (iterations, salt, hexhash)
        except Exception:
            return None
    elif len(parts) == 4:
        try:
            iterations = int(parts[1])
            salt = parts[2].encode('utf-8', errors='replace')
            hexhash = parts[3]
            return (iterations, salt, hexhash)
        except Exception:
            return None
    else:
        return None

# ---------------- Cracker Thread ----------------
class CrackerThread(threading.Thread):
    def __init__(self, targets, wordlist_path, pbkdf2_salt_opt, pbkdf2_iters_opt,
                 progress_callback, done_callback, log_callback, stop_event, max_lines=None):
        super().__init__(daemon=True)
        self.targets = set(t.strip() for t in targets if t.strip())
        self.wordlist_path = wordlist_path
        self.pbkdf2_salt_opt = pbkdf2_salt_opt
        self.pbkdf2_iters_opt = pbkdf2_iters_opt
        self.progress_callback = progress_callback
        self.done_callback = done_callback
        self.log_callback = log_callback
        self.stop_event = stop_event
        self.max_lines = max_lines

    def log(self, msg):
        if callable(self.log_callback):
            self.log_callback(msg)

    def run(self):
        started = time.time()
        attempts = 0
        found = {}

        need_bcrypt = _have_bcrypt
        need_argon2 = _have_argon2

        try:
            with open(self.wordlist_path, 'r', errors='replace') as f:
                for i, line in enumerate(f):
                    if self.stop_event.is_set():
                        break
                    if self.max_lines and i >= self.max_lines:
                        break

                    word = line.rstrip('\n\r')
                    if not word:
                        continue
                    attempts += 1

                    # 🔹 Live update stats every attempt
                    self.progress_callback(attempts, time.time() - started)

                    # Fast hashes
                    h_md5 = md5_hex(word)
                    h_sha1 = sha1_hex(word)
                    h_sha256 = sha256_hex(word)

                    if h_md5 in self.targets:
                        found[h_md5] = f"{word} (md5)"
                        self.targets.discard(h_md5)
                        self.log(f"Matched MD5 -> {h_md5} : {word}")
                    if h_sha1 in self.targets:
                        found[h_sha1] = f"{word} (sha1)"
                        self.targets.discard(h_sha1)
                        self.log(f"Matched SHA1 -> {h_sha1} : {word}")
                    if h_sha256 in self.targets:
                        found[h_sha256] = f"{word} (sha256)"
                        self.targets.discard(h_sha256)
                        self.log(f"Matched SHA256 -> {h_sha256} : {word}")

                    # PBKDF2
                    if self.pbkdf2_iters_opt is not None or any('$' in t for t in self.targets):
                        targets_copy = list(self.targets)
                        for t in targets_copy:
                            parsed = parse_pbkdf2_target(t)
                            if parsed:
                                iters, salt_bytes, target_hex = parsed
                                try:
                                    comp = pbkdf2_hex(word, salt_bytes, iters)
                                    if comp == target_hex:
                                        found[t] = f"{word} (pbkdf2:{iters})"
                                        self.targets.discard(t)
                                        self.log(f"Matched PBKDF2 (parsed) -> {t} : {word}")
                                except Exception:
                                    pass
                            else:
                                if self.pbkdf2_iters_opt is not None:
                                    try:
                                        comp = pbkdf2_hex(word, self.pbkdf2_salt_opt or b'', self.pbkdf2_iters_opt)
                                        if comp.lower() == t.lower():
                                            found[t] = f"{word} (pbkdf2:{self.pbkdf2_iters_opt})"
                                            self.targets.discard(t)
                                            self.log(f"Matched PBKDF2 (user salt/iters) -> {t} : {word}")
                                    except Exception:
                                        pass

                    # bcrypt
                    if need_bcrypt:
                        for t in list(self.targets):
                            if t.startswith("$2a$") or t.startswith("$2b$") or t.startswith("$2y$"):
                                try:
                                    if try_check_bcrypt(word, t):
                                        found[t] = f"{word} (bcrypt)"
                                        self.targets.discard(t)
                                        self.log(f"Matched bcrypt -> {t} : {word}")
                                except Exception:
                                    pass

                    # Argon2
                    if need_argon2:
                        for t in list(self.targets):
                            if t.startswith("$argon2"):
                                try:
                                    if try_check_argon2(word, t):
                                        found[t] = f"{word} (argon2)"
                                        self.targets.discard(t)
                                        self.log(f"Matched Argon2 -> {t} : {word}")
                                except Exception:
                                    pass

                    if not self.targets:
                        break

            elapsed = time.time() - started
            self.done_callback(found, attempts, elapsed, stopped=self.stop_event.is_set())
        except FileNotFoundError:
            self.done_callback({}, attempts, time.time() - started,
                               stopped=True, error="Wordlist file not found.")
        except Exception as e:
            self.done_callback({}, attempts, time.time() - started,
                               stopped=True, error=str(e))

# ---------------- GUI Application ----------------
class App:
    def __init__(self, root):
        self.root = root
        root.title("Hash_Hunter")
        root.geometry("860x640")

        frame = ttk.Frame(root, padding=8)
        frame.pack(fill='x', padx=8, pady=4)

        ttk.Label(frame, text="Hashes (one per line or load from file):").grid(row=0, column=0, sticky='w')
        self.hash_entry = ttk.Entry(frame, width=110)
        self.hash_entry.grid(row=1, column=0, columnspan=4, sticky='we', pady=2)
        ttk.Button(frame, text="Load hashes from file", command=self.load_hashes).grid(row=1, column=4, padx=6)

        ttk.Label(frame, text="Wordlist file:").grid(row=2, column=0, sticky='w', pady=(6,0))
        self.wordlist_entry = ttk.Entry(frame, width=78)
        self.wordlist_entry.grid(row=2, column=1, columnspan=3, sticky='we', pady=(6,0))
        ttk.Button(frame, text="Browse", command=self.browse_wordlist).grid(row=2, column=4, padx=6, pady=(6,0))

        # PBKDF2 optional
        ttk.Label(frame, text="PBKDF2 Salt (optional):").grid(row=3, column=0, sticky='w', pady=(6,0))
        self.pbkdf2_salt_entry = ttk.Entry(frame, width=30)
        self.pbkdf2_salt_entry.grid(row=3, column=1, sticky='w', pady=(6,0))
        ttk.Label(frame, text="PBKDF2 Iterations (optional):").grid(row=3, column=2, sticky='w', pady=(6,0))
        self.pbkdf2_iters_entry = ttk.Entry(frame, width=12)
        self.pbkdf2_iters_entry.grid(row=3, column=3, sticky='w', pady=(6,0))

        self.auth_var = tk.BooleanVar(value=False)
        self.auth_chk = ttk.Checkbutton(frame,
            text="I confirm I am authorized to test these hashes (required)",
            variable=self.auth_var)
        self.auth_chk.grid(row=4, column=0, columnspan=5, sticky='w', pady=(8,0))

        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=5, column=0, columnspan=5, pady=(10,0), sticky='w')
        self.start_btn = ttk.Button(btn_frame, text="Start Cracking", command=self.start_crack)
        self.start_btn.grid(row=0, column=0, padx=4)
        self.stop_btn = ttk.Button(btn_frame, text="Stop", command=self.stop_crack, state='disabled')
        self.stop_btn.grid(row=0, column=1, padx=4)
        self.export_btn = ttk.Button(btn_frame, text="Export Results", command=self.export_results)
        self.export_btn.grid(row=0, column=2, padx=6)
        ttk.Button(btn_frame, text="Clear Log", command=self.clear_log).grid(row=0, column=3, padx=6)

        stats_frame = ttk.LabelFrame(root, text="Progress & Output", padding=8)
        stats_frame.pack(fill='both', expand=True, padx=8, pady=6)
        self.progress_text = scrolledtext.ScrolledText(stats_frame, height=18, wrap='word', state='disabled')
        self.progress_text.pack(fill='both', expand=True)

        stats_lower = ttk.Frame(stats_frame)
        stats_lower.pack(fill='x', pady=(6,0))
        self.attempts_var = tk.StringVar(value="Attempts: 0")
        self.time_var = tk.StringVar(value="Elapsed: 0s")
        self.rate_var = tk.StringVar(value="Rate: 0 tries/s")
        ttk.Label(stats_lower, textvariable=self.attempts_var).pack(side='left', padx=(0,12))
        ttk.Label(stats_lower, textvariable=self.time_var).pack(side='left', padx=(0,12))
        ttk.Label(stats_lower, textvariable=self.rate_var).pack(side='left')

        found_frame = ttk.LabelFrame(root, text="Found Results", padding=8)
        found_frame.pack(fill='both', padx=8, pady=(0,8), expand=False)
        columns = ('hash','password')
        self.tree = ttk.Treeview(found_frame, columns=columns, show='headings', height=6)
        for c in columns:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=410, anchor='center')
        self.tree.pack(fill='both')

        self.thread = None
        self.stop_event = threading.Event()

    def log(self, msg):
        ts = time.strftime('%H:%M:%S')
        self.progress_text.configure(state='normal')
        self.progress_text.insert('end', f"[{ts}] {msg}\n")
        self.progress_text.see('end')
        self.progress_text.configure(state='disabled')

    def clear_log(self):
        self.progress_text.configure(state='normal')
        self.progress_text.delete('1.0','end')
        self.progress_text.configure(state='disabled')

    def browse_wordlist(self):
        p = filedialog.askopenfilename(title="Select wordlist (one password per line)")
        if p:
            self.wordlist_entry.delete(0, 'end')
            self.wordlist_entry.insert(0, p)

    def load_hashes(self):
        p = filedialog.askopenfilename(title="Select file with target hashes (one per line)")
        if p:
            try:
                with open(p, 'r', errors='replace') as f:
                    lines = [l.strip() for l in f if l.strip()]
                if lines:
                    self.hash_entry.delete(0, 'end')
                    self.hash_entry.insert(0, '\n'.join(lines))
            except Exception as e:
                messagebox.showerror("Error", f"Could not read file: {e}")

    def parse_targets(self):
        raw = self.hash_entry.get().strip()
        if not raw:
            return []
        return [l.strip() for l in raw.splitlines() if l.strip()]

    def start_crack(self):
        if not self.auth_var.get():
            messagebox.showwarning("Authorization required", "You must confirm you are authorized.")
            return
        targets = self.parse_targets()
        if not targets:
            messagebox.showwarning("No target hash", "Enter at least one hash (or load file).")
            return
        wordlist = self.wordlist_entry.get().strip()
        if not wordlist or not os.path.isfile(wordlist):
            messagebox.showwarning("Wordlist missing", "Please choose a valid wordlist file.")
            return

        salt_text = self.pbkdf2_salt_entry.get().strip()
        pbkdf2_salt = salt_text.encode('utf-8', errors='replace') if salt_text else None
        iters_text = self.pbkdf2_iters_entry.get().strip()
        pbkdf2_iters = int(iters_text) if iters_text.isdigit() else None

        self.start_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        self.stop_event.clear()
        self.tree.delete(*self.tree.get_children())
        self.log(f"Starting Hash_Hunter with {len(targets)} target(s)...")

        self.thread = CrackerThread(
            targets=targets,
            wordlist_path=wordlist,
            pbkdf2_salt_opt=pbkdf2_salt,
            pbkdf2_iters_opt=pbkdf2_iters,
            progress_callback=self.on_progress,
            done_callback=self.on_done,
            log_callback=self.log,
            stop_event=self.stop_event
        )
        self.thread.start()

    def stop_crack(self):
        if self.thread and self.thread.is_alive():
            self.stop_event.set()
            self.log("Stop requested...")

    def on_progress(self, attempts, elapsed):
        rate = attempts / elapsed if elapsed > 0 else 0.0
        self.root.after(0, lambda: (
            self.attempts_var.set(f"Attempts: {attempts}"),
            self.time_var.set(f"Elapsed: {timedelta(seconds=int(elapsed))}"),
            self.rate_var.set(f"Rate: {rate:.2f} tries/s")
        ))

    def on_done(self, found, attempts, elapsed, stopped=False, error=None):
        def finish():
            self.attempts_var.set(f"Attempts: {attempts}")
            self.time_var.set(f"Elapsed: {timedelta(seconds=int(elapsed))}")
            rate = attempts / elapsed if elapsed > 0 else 0.0
            self.rate_var.set(f"Rate: {rate:.2f} tries/s")
            if found:
                for h, p in found.items():
                    self.tree.insert('', 'end', values=(h, p))
                    self.log(f"FOUND: {h} -> {p}")
            if error:
                messagebox.showerror("Error", error)
            elif stopped:
                self.log("Attack stopped by user.")
            else:
                self.log("Attack finished.")
            self.start_btn.config(state='normal')
            self.stop_btn.config(state='disabled')
        self.root.after(0, finish)

    def export_results(self):
        items = self.tree.get_children()
        if not items:
            messagebox.showwarning("No results", "No results to export.")
            return
        save_path = filedialog.asksaveasfilename(defaultextension=".txt",
            filetypes=(("Text Files","*.txt"),("All Files","*.*")))
        if save_path:
            with open(save_path, 'w', encoding='utf-8') as f:
                f.write("hash\tpassword\n")
                for it in items:
                    h, p = self.tree.item(it, 'values')
                    f.write(f"{h}\t{p}\n")
            self.log(f"Exported results to {save_path}")

def main():
    root = tk.Tk()
    style = ttk.Style(root)
    try:
        style.theme_use('clam')
    except Exception:
        pass
    app = App(root)
    root.mainloop()

if __name__ == '__main__':
    main() 