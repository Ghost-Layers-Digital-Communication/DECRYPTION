#!/usr/bin/env python3
"""
===[Ghost Layers Encrypt/Decrypt GUI]=== coded by: sacred G
Cross-platform | Python ≥3.8 including 3.13
Black & Green theme
"""

import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import os
import sys

# -----------------------------
# Simple XOR function
# -----------------------------
def xor_bytes(data: bytes, key: bytes) -> bytes:
    key_len = len(key)
    return bytes([b ^ key[i % key_len] for i, b in enumerate(data)])

def encrypt_file(input_path: str, key: str):
    """Encrypt file using XOR"""
    output_path = input_path + ".enc"
    with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
        data = fin.read()
        encrypted = xor_bytes(data, key.encode("utf-8"))
        fout.write(encrypted)
    messagebox.showinfo("Encrypted", f"Encrypted file saved as:\n{output_path}")

def decrypt_file(input_path: str, key: str):
    """Decrypt file using XOR (same as encrypt)"""
    output_path = input_path + ".dec"
    with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
        data = fin.read()
        decrypted = xor_bytes(data, key.encode("utf-8"))
        fout.write(decrypted)
    messagebox.showinfo("Decrypted", f"Decrypted file saved as:\n{output_path}")

# -----------------------------
# GUI class:
# -----------------------------
class GhostGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("===[Ghost Layers Encrypt/Decrypt]===")
        self.configure(bg="#0b0b0b")  # black background
        self.geometry("520x240")
        self.resizable(False, False)

        self.fg_green = "#00FF66"
        self.font = ("Consolas", 11)

        self.file_to_encrypt = tk.StringVar()
        self.file_to_decrypt = tk.StringVar()

        self.create_widgets()

    def create_widgets(self):
        # Header
        tk.Label(self, text="===[GHOST ENCRYPT / DECRYPT]=== coded by: sacred G",
                 bg="#0b0b0b", fg=self.fg_green,
                 font=("Consolas", 13, "bold")).pack(pady=10)

        # ENCRYPT panel
        self._make_file_panel("File to Encrypt:",
                              self.file_to_encrypt,
                              self.browse_encrypt,
                              self.do_encrypt)

        # DECRYPT panel
        self._make_file_panel("File to Decrypt:",
                              self.file_to_decrypt,
                              self.browse_decrypt,
                              self.do_decrypt)

        tk.Label(self, text="Cross-platform | Python "+sys.version.split()[0],
                 bg="#0b0b0b", fg=self.fg_green,
                 font=("Consolas", 9)).pack(pady=5)

    def _make_file_panel(self, label, var, browse_cmd, action_cmd):
        frame = tk.Frame(self, bg="#0b0b0b")
        frame.pack(fill="x", padx=20, pady=5)

        tk.Label(frame, text=label,
                 bg="#0b0b0b", fg=self.fg_green,
                 font=self.font).pack(anchor="w")

        tk.Entry(frame, textvariable=var,
                 bg="#1a1a1a", fg=self.fg_green,
                 insertbackground=self.fg_green,
                 font=self.font).pack(fill="x", pady=2)

        btn_frame = tk.Frame(frame, bg="#0b0b0b")
        btn_frame.pack(fill="x")
        tk.Button(btn_frame, text="Browse", command=browse_cmd,
                  bg=self.fg_green, fg="#0b0b0b",
                  font=self.font).pack(side="left", padx=5, pady=2)
        tk.Button(btn_frame, text="Go", command=action_cmd,
                  bg=self.fg_green, fg="#0b0b0b",
                  font=self.font).pack(side="right", padx=5, pady=2)

    def browse_encrypt(self):
        path = filedialog.askopenfilename(title="Select file to encrypt")
        if path:
            self.file_to_encrypt.set(path)

    def browse_decrypt(self):
        path = filedialog.askopenfilename(title="Select file to decrypt")
        if path:
            self.file_to_decrypt.set(path)

    def do_encrypt(self):
        path = self.file_to_encrypt.get()
        if not os.path.isfile(path):
            messagebox.showerror("Error", "Please select a valid file to encrypt.")
            return
        key = simpledialog.askstring("Key", "Enter a password/key:", show="*")
        if not key:
            return
        encrypt_file(path, key)

    def do_decrypt(self):
        path = self.file_to_decrypt.get()
        if not os.path.isfile(path):
            messagebox.showerror("Error", "Please select a valid file to decrypt.")
            return
        key = simpledialog.askstring("Key", "Enter the password/key:", show="*")
        if not key:
            return
        decrypt_file(path, key)

if __name__ == "__main__":
    app = GhostGUI()
    app.mainloop()
