
data = open("img.png", "rb").read()
end = data.find(b"IEND") + 8
trailer = data[end:]
print(f"Trailer size: {len(trailer)} bytes")
print("First 64 bytes (hex):", trailer[:64].hex())
print("First 64 bytes (raw):", trailer[:64])
open("trailer.bin", "wb").write(trailer)

import base64
lines = [l.strip() for l in open("trailer.bin", "rb").read().splitlines() if l.strip() and not l.startswith(b"--TTY--")]
decoded = base64.b64decode(b"".join(lines))
print(decoded.decode("utf-8", errors="replace"))
open("decoded_tty.txt", "wb").write(decoded)