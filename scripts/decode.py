
#!/usr/bin/env python3
import sys
import base64
import codecs
import urllib.parse

def decode(value):
    print("\nOriginal:", value)

    operations = {
        "Base64": lambda x: base64.b64decode(x, validate=True),
        "Base32": lambda x: base64.b32decode(x, casefold=True),
        "Base16": lambda x: base64.b16decode(x, casefold=True),
        "Hex": lambda x: bytes.fromhex(x.decode() if isinstance(x, bytes) else x),
        "Binary": lambda x: bytes(
            int(x[i:i+8], 2) for i in range(0, len(x), 8)
        ),
        "ROT13": lambda x: codecs.decode(
            x.decode() if isinstance(x, bytes) else x, "rot_13"
        ),
        "URL": lambda x: urllib.parse.unquote(
            x.decode() if isinstance(x, bytes) else x
        )
    }

    for name, operation in operations.items():
        try:
            result = operation(value)
            print(f"\n{name}: {result!r}")
        except Exception:
            pass

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Usage: python decode.py "encoded_text"')
    else:
        decode(sys.argv[1])
