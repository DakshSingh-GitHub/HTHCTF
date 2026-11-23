# with open("etc/n6_memory_slate_HTH26-SUV 2.img", "rb") as f:
#     data_start = 1184256 + 64 * 32
#     f.seek(1048576 + 512)
#     fat = f.read(132 * 512)
#     def read_file(c, sz):
#         out = b""
#         while 2 <= c < 0xfff8:
#             f.seek(data_start + (c - 2) * 512)
#             out += f.read(512)
#             c = int.from_bytes(fat[c*2:c*2+2], "little")
#         return out[:sz]
#     print("=== DECOY: CUSTODY/CUSTODY.TXT (Cluster 21861) ===")
#     print(read_file(21861, 304).decode("latin1"))
#     print("=== TRUE: CUSTODY/CUST2DY.TXT (Cluster 21862) ===")
#     print(read_file(21862, 350).decode("latin1"))

# with open("CUST2DY.TXT", "rb") as f:
#     sealed = f.read().split(b"\n")[14]

# key = b"L2-MEMORY-CUSTODY"
# unsealed = bytes([b ^ key[i % len(key)] for i, b in enumerate(sealed)])
# print(unsealed.decode())
