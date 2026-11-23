
with open("../n6_memory_slate_HTH26-SUV 2.img", "rb") as f:
    data_start = 1184256 + 64 * 32
    f.seek(1048576 + 512)
    fat = f.read(132 * 512)
    c, size = 406, 10984768
    out = bytearray()
    while 2 <= c < 0xfff8 and len(out) < size:
        f.seek(data_start + (c - 2) * 512)
        out.extend(f.read(512))
        c = int.from_bytes(fat[c*2 : c*2+2], "little")
    with open("../SENTBOX.WAV", "wb") as out_f:
        out_f.write(out[:size])
    print(f"Extracted /AUDIO/SENTBOX.WAV ({size} bytes) from cluster 406 (offset {data_start + (406 - 2)*512})")
