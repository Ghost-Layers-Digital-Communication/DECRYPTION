#!/usr/bin/env python3
"""
Ghost Layers Crypto Lab - self-contained GUI
Includes toy_crypto_lab_windows.py backend exactly as-is, with official Ghost Layers green-on-black GUI
"""

import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import itertools
from collections import Counter

# -------------------------
# Backend (from your script, unchanged)
# -------------------------
def read_file(path):
    path = path.replace("\\","/") # handle Windows paths
    with open(path, "rb") as f:
        return f.read()

def write_file(path, data):
    path = path.replace("\\","/")
    with open(path, "wb") as f:
        f.write(data)

def xor_repeat(data: bytes, key: bytes) -> bytes:
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

ENGLISH_FREQ = {
    'a': .08167,'b': .01492,'c': .02782,'d': .04253,'e': .12702,'f': .02228,'g': .02015,'h': .06094,
    'i': .06966,'j': .00153,'k': .00772,'l': .04025,'m': .02406,'n': .06749,'o': .07507,'p': .01929,
    'q': .00095,'r': .05987,'s': .06327,'t': .09056,'u': .02758,'v': .00978,'w': .02360,'x': .00150,
    'y': .01974,'z': .00074,' ': .13000
}

def english_score(text: bytes) -> float:
    try:
        s = text.decode('utf-8', errors='replace').lower()
    except:
        return -1e9
    score = 0.0
    nonprint = sum(1 for c in text if c < 9 or (c > 13 and c < 32))
    score -= nonprint * 5
    counts = Counter(s)
    length = max(1, len(s))
    for ch, freq in ENGLISH_FREQ.items():
        score += freq * (counts.get(ch,0) / length) * 100
    for w in (" the ", " and ", " to ", " of ", " is ", " that "):
        if w in s:
            score += 5
    return score

def create_ciphertext(input_path, out_path, key_bytes):
    data = read_file(input_path)
    ct = xor_repeat(data, bytes(key_bytes))
    write_file(out_path, ct)

def brute_force_single_byte(ct: bytes, top=5):
    candidates = []
    for k in range(256):
        pt = xor_repeat(ct, bytes([k]))
        sc = english_score(pt)
        candidates.append((sc, k, pt))
    candidates.sort(reverse=True, key=lambda x: x[0])
    return candidates[:top]

def brute_force_repeating(ct: bytes, max_key_bytes=2, top=10):
    best = []
    for L in range(1, max_key_bytes+1):
        total = 256 ** L
        if total > 5_000_000:
            continue
        for key_tuple in itertools.product(range(256), repeat=L):
            key = bytes(key_tuple)
            pt = xor_repeat(ct, key)
            sc = english_score(pt)
            best.append((sc, key, pt))
        best.sort(reverse=True, key=lambda x: x[0])
        best = best[:top*5]
    best.sort(reverse=True, key=lambda x: x[0])
    return best[:top]

# -------------------------
# GUI
# -------------------------
class GhostLayersGUI:
    def __init__(self, root):
        self.root = root
        root.title("Ghost Layers Crypto Lab")
        root.configure(bg="black")

        fg_color = "#00FF00"
        bg_color = "black"
        font = ("Consolas", 12)

        # Input file
        tk.Label(root, text="Input File:", bg=bg_color, fg=fg_color, font=font).grid(row=0, column=0, sticky="w")
        self.infile_entry = tk.Entry(root, width=50, bg=bg_color, fg=fg_color, insertbackground=fg_color, font=font)
        self.infile_entry.grid(row=0, column=1)
        tk.Button(root, text="Browse", command=self.browse_infile, bg=bg_color, fg=fg_color, font=font).grid(row=0, column=2)

        # Output file
        tk.Label(root, text="Output File:", bg=bg_color, fg=fg_color, font=font).grid(row=1, column=0, sticky="w")
        self.outfile_entry = tk.Entry(root, width=50, bg=bg_color, fg=fg_color, insertbackground=fg_color, font=font)
        self.outfile_entry.grid(row=1, column=1)
        tk.Button(root, text="Browse", command=self.browse_outfile, bg=bg_color, fg=fg_color, font=font).grid(row=1, column=2)

        # Key bytes
        tk.Label(root, text="Key (comma or 0x..):", bg=bg_color, fg=fg_color, font=font).grid(row=2, column=0, sticky="w")
        self.key_entry = tk.Entry(root, width=50, bg=bg_color, fg=fg_color, insertbackground=fg_color, font=font)
        self.key_entry.grid(row=2, column=1, columnspan=2, sticky="w")

        # Top N / max key bytes for cracking
        tk.Label(root, text="Top N:", bg=bg_color, fg=fg_color, font=font).grid(row=3, column=0, sticky="w")
        self.top_entry = tk.Entry(root, width=10, bg=bg_color, fg=fg_color, insertbackground=fg_color, font=font)
        self.top_entry.insert(0, "5")
        self.top_entry.grid(row=3, column=1, sticky="w")

        tk.Label(root, text="Max Key Bytes:", bg=bg_color, fg=fg_color, font=font).grid(row=4, column=0, sticky="w")
        self.max_key_entry = tk.Entry(root, width=10, bg=bg_color, fg=fg_color, insertbackground=fg_color, font=font)
        self.max_key_entry.insert(0, "2")
        self.max_key_entry.grid(row=4, column=1, sticky="w")

        # Buttons
        tk.Button(root, text="Encrypt", command=self.encrypt_file, bg=bg_color, fg=fg_color, font=font).grid(row=5, column=0)
        tk.Button(root, text="Brute Force", command=self.brute_force_file, bg=bg_color, fg=fg_color, font=font).grid(row=5, column=1)

        # Output text box
        self.output_text = scrolledtext.ScrolledText(root, width=80, height=20, bg=bg_color, fg=fg_color, font=font, insertbackground=fg_color)
        self.output_text.grid(row=6, column=0, columnspan=3, pady=10)

    # -------------------------
    # Callbacks
    # -------------------------
    def browse_infile(self):
        path = filedialog.askopenfilename()
        if path:
            self.infile_entry.delete(0, tk.END)
            self.infile_entry.insert(0, path)

    def browse_outfile(self):
        path = filedialog.asksaveasfilename(defaultextension=".bin")
        if path:
            self.outfile_entry.delete(0, tk.END)
            self.outfile_entry.insert(0, path)

    def encrypt_file(self):
        infile = self.infile_entry.get()
        outfile = self.outfile_entry.get()
        key = self.key_entry.get()
        if not infile or not outfile or not key:
            messagebox.showerror("Error", "Input file, output file, and key are required for encryption.")
            return
        # parse key
        if "," in key:
            parts = [x.strip() for x in key.split(",")]
            key_bytes = [int(x,16) if x.startswith("0x") else int(x) for x in parts]
        else:
            key_bytes = [int(key,16) if key.startswith("0x") else int(key)]
        try:
            create_ciphertext(infile, outfile, key_bytes)
            self.output_text.insert(tk.END, f"Encrypted {infile} -> {outfile} with key {key_bytes}\n")
        except Exception as e:
            self.output_text.insert(tk.END, f"Error: {e}\n")

    def brute_force_file(self):
        infile = self.infile_entry.get()
        top = int(self.top_entry.get())
        max_key = int(self.max_key_entry.get())
        if not infile:
            messagebox.showerror("Error", "Input file is required for brute force.")
            return
        try:
            ct = read_file(infile)
            self.output_text.insert(tk.END, f"Brute-forcing single-byte XOR...\n")
            single = brute_force_single_byte(ct, top=top)
            for sc,k,pt in single:
                self.output_text.insert(tk.END, f"\nSCORE={sc:.2f} key=0x{k:02X}\n")
                self.output_text.insert(tk.END, pt.decode('utf-8', errors='replace')[:400] + "\n")
            self.output_text.insert(tk.END, f"\nBrute-forcing repeating-key XOR...\n")
            repeating = brute_force_repeating(ct, max_key_bytes=max_key, top=top)
            for sc,k,pt in repeating:
                self.output_text.insert(tk.END, f"\nSCORE={sc:.2f} key={k.hex()}\n")
                self.output_text.insert(tk.END, pt.decode('utf-8', errors='replace')[:400] + "\n")
        except Exception as e:
            self.output_text.insert(tk.END, f"Error: {e}\n")

# -------------------------
# Run GUI
# -------------------------
if __name__ == "__main__":
    root = tk.Tk()
    gui = GhostLayersGUI(root)
    root.mainloop()