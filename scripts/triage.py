
#!/usr/bin/env python3
import sys
import hashlib
import subprocess
import shutil
from pathlib import Path

def inspect(path):
    p = Path(path)

    if not p.is_file():
        print("File not found:", p)
        return

    data = p.read_bytes()

    print(f"\n{'='*55}")
    print("FILE:", p.name)
    print("SIZE:", len(data), "bytes")
    print("SHA256:", hashlib.sha256(data).hexdigest())

    print("\n--- FILE TYPE ---")
    if shutil.which("file"):
        subprocess.run(["file", str(p)])

    print("\n--- MAGIC BYTES ---")
    print(data[:32].hex(" "))

    print("\n--- STRINGS ---")
    strings = []
    current = bytearray()

    for b in data:
        if 32 <= b <= 126:
            current.append(b)
        else:
            if len(current) >= 4:
                strings.append(current.decode(errors="replace"))
            current.clear()

    if len(current) >= 4:
        strings.append(current.decode(errors="replace"))

    for s in strings[:100]:
        print(s)

    print("\n--- METADATA ---")
    if shutil.which("exiftool"):
        subprocess.run(["exiftool", str(p)])

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python triage.py <file>")
    else:
        inspect(sys.argv[1])
