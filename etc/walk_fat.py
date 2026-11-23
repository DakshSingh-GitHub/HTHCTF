#!/usr/bin/env python3
import struct

def walk_fat16(image_path):
    with open(image_path, "rb") as f:
        part_offset = 2048 * 512
        f.seek(part_offset)
        boot = f.read(512)
        bytes_per_sec = struct.unpack_from("<H", boot, 11)[0]
        sec_per_clus = boot[13]
        res_sec = struct.unpack_from("<H", boot, 14)[0]
        fats = boot[16]
        root_entries = struct.unpack_from("<H", boot, 17)[0]
        sec_per_fat = struct.unpack_from("<H", boot, 22)[0]
        
        fat_offset = part_offset + res_sec * bytes_per_sec
        root_offset = fat_offset + fats * sec_per_fat * bytes_per_sec
        data_offset = root_offset + root_entries * 32
        
        f.seek(fat_offset)
        fat = f.read(sec_per_fat * bytes_per_sec)
        
        def get_chain(c):
            chain = []
            while 2 <= c < 0xfff8:
                chain.append(c)
                c = struct.unpack_from("<H", fat, c * 2)[0]
            return chain

        def list_entries(data, prefix=""):
            res = []
            for i in range(0, len(data), 32):
                raw = data[i:i+32]
                if not raw or raw[0] == 0:
                    break
                if raw[0] == 0xe5:
                    continue
                name_base = raw[:8].strip().decode("latin1")
                ext = raw[8:11].strip().decode("latin1")
                if name_base in (".", "..", ""):
                    continue
                name = f"{name_base}.{ext}" if ext else name_base
                attr = raw[11]
                cluster = struct.unpack_from("<H", raw, 26)[0]
                size = struct.unpack_from("<I", raw, 28)[0]
                res.append((f"{prefix}/{name}", attr, cluster, size))
            return res

        f.seek(root_offset)
        root_data = f.read(root_entries * 32)
        entries = list_entries(root_data)
        
        print(f"%-25s %-6s %-10s %-12s" % ("PATH", "TYPE", "CLUSTER", "SIZE (bytes)"))
        print("-" * 58)
        for path, attr, cluster, size in entries:
            is_dir = bool(attr & 0x10)
            t = "DIR" if is_dir else "FILE"
            print(f"%-25s %-6s %-10d %-12d" % (path, t, cluster, size))
            if is_dir:
                chain = get_chain(cluster)
                dir_data = b""
                for clus in chain:
                    f.seek(data_offset + (clus - 2) * sec_per_clus * bytes_per_sec)
                    dir_data += f.read(sec_per_clus * bytes_per_sec)
                sub_entries = list_entries(dir_data, path)
                for spath, sattr, scluster, ssize in sub_entries:
                    st = "DIR" if (sattr & 0x10) else "FILE"
                    print(f"%-25s %-6s %-10d %-12d" % (spath, st, scluster, ssize))

if __name__ == "__main__":
    import sys
    img = sys.argv[1] if len(sys.argv) > 1 else "etc/n6_memory_slate_HTH26-SUV 2.img"
    walk_fat16(img)
