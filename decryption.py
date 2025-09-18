#!/usr/bin/env python3
"""
toy_crypto_lab_windows.py

Same functionality as before, minor tweaks for Windows:
- Supports backslashes in paths
- Safe UTF-8 output for PowerShell/Command Prompt
"""
import argparse, itertools, sys
from collections import Counter

# -------------------------
# helpers
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
        s = text.decode('utf-8', errors='replace').lower() # replace invalid chars
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

# -------------------------
# creation
# -------------------------
def create_ciphertext(input_path, out_path, key_bytes):
    data = read_file(input_path)
    ct = xor_repeat(data, bytes(key_bytes))
    write_file(out_path, ct)
    print(f"Wrote ciphertext {out_path} (input {input_path}) key={key_bytes}")

# -------------------------
# brute force single-byte
# -------------------------
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
            print(f"Skipping length {L} (256^{L} = {total} combos) — too big. Increase budget carefully.")
            continue
        print(f"Trying key length {L} ({total} combos)...")
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
# CLI
# -------------------------
def main():
    p = argparse.ArgumentParser()
    p.add_argument("--create", action="store_true")
    p.add_argument("--crack", action="store_true")
    p.add_argument("--in", dest="infile", help="input file path")
    p.add_argument("--out", dest="outfile", help="output file path")
    p.add_argument("--key", help="key bytes, e.g., 0x5A or 0x01,0x02,0x03")
    p.add_argument("--top", type=int, default=5, help="show top N candidates")
    p.add_argument("--max-key-bytes", type=int, default=2, help="for repeating-key brute force max length")
    args = p.parse_args()

    if args.create:
        if not args.infile or not args.outfile or not args.key:
            p.print_help(); sys.exit(1)
        if "," in args.key:
            parts = [x.strip() for x in args.key.split(",")]
            key_bytes = [int(x,16) if x.startswith("0x") else int(x) for x in parts]
        else:
            key_bytes = [int(args.key,16) if args.key.startswith("0x") else int(args.key)]
        create_ciphertext(args.infile, args.outfile, key_bytes)
        return

    if args.crack:
        if not args.infile:
            p.print_help(); sys.exit(1)
        ct = read_file(args.infile)
        print("Brute-forcing single-byte XOR (256 keys)...")
        single = brute_force_single_byte(ct, top=args.top)
        for sc,k,pt in single:
            print(f"\nSCORE={sc:.2f} key=0x{k:02X}")
            print(pt.decode('utf-8', errors='replace')[:400])
        print("\nBrute-forcing repeating-key XOR for small lengths (be careful)...")
        repeating = brute_force_repeating(ct, max_key_bytes=args.max_key_bytes, top=args.top)
        for sc,k,pt in repeating:
            print(f"\nSCORE={sc:.2f} key={k.hex()}")
            print(pt.decode('utf-8', errors='replace')[:400])
        return

    p.print_help()

if __name__ == "__main__":
    main()