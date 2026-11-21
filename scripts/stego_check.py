
#!/usr/bin/env python3
from PIL import Image
import sys

def inspect_image(filename):
    img = Image.open(filename)

    print("Format:", img.format)
    print("Dimensions:", img.size)
    print("Mode:", img.mode)

    print("\nMetadata:")
    for key, value in img.info.items():
        print(key, ":", value)

    print("\nFirst 100 LSB bits from red channel:")

    rgb = img.convert("RGB")
    bits = []

    for r, g, b in rgb.getdata():
        bits.append(str(r & 1))

        if len(bits) >= 100:
            break

    print("".join(bits))

    print("\nFirst 12 decoded bytes:")
    binary = "".join(bits[:96])
    output = bytes(
        int(binary[i:i+8], 2)
        for i in range(0, len(binary), 8)
    )
    print(output)
    
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python stego_check.py image.png")
    else:
        inspect_image(sys.argv[1])
