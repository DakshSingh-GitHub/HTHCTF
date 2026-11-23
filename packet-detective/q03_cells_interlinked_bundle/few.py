import re

ALPHABET = "pabcdefghijklmno"
KEY = "n"

def decode_chunk(stream: str, key: str = KEY) -> str:
    k = ALPHABET.index(key)
    out = []
    for i in range(0, len(stream) - 1, 2):
        hi = (ALPHABET.index(stream[i]) - k) % 16
        lo = (ALPHABET.index(stream[i + 1]) - k) % 16
        out.append(chr((hi << 4) | lo))
    return "".join(out)


with open("transcript_HTH26-SUV.txt", "r") as f:
    raw = f.read()

# Extract only the machine notation block
block = raw.split("----- MACHINE NOTATION FOLLOWS -----")[1]
block = block.split("----- END OF MACHINE NOTATION -----")[0]
cipher = "".join(block.split())

part1 = decode_chunk(cipher[:266])
part2 = decode_chunk(cipher[267:1519])
part3 = decode_chunk(cipher[1520:])

full_text = f"{part1}[...]{part2}\n{part3}"
print(full_text)

print("\n--- Extracted Seals ---")
for flag in re.findall(r"HTH3\{[^}]+\}", full_text):
    status = "DECOY (bench log)" if "n0t_th3_l1v3" in flag else "LIVE SEAL"
    print(f"[{status}] {flag}")
