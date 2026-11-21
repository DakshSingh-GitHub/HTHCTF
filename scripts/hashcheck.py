
#!/usr/bin/env python3
import hashlib
import sys

def identify(value):
    value = value.strip()

    candidates = {
        32: ["MD5", "NTLM (possible)"],
        40: ["SHA-1"],
        56: ["SHA-224"],
        64: ["SHA-256"],
        96: ["SHA-384"],
        128: ["SHA-512"]
    }

    print("Input:", value)
    print("Length:", len(value))

    if all(c in "0123456789abcdefABCDEF" for c in value):
        print("Possible algorithms:",
              candidates.get(len(value), ["Unknown"]))
    else:
        print("Not a plain hexadecimal hash candidate")

    print("\nHashes of the supplied text:")
    for algorithm in ["md5", "sha1", "sha256", "sha512"]:
        h = hashlib.new(algorithm)
        h.update(value.encode())
        print(algorithm.upper(), h.hexdigest())

if __name__ == "__main__":
    identify(" ".join(sys.argv[1:]))
