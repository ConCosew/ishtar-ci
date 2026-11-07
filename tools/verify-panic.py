#!/usr/bin/env python3
"""Re-derive the P5 stage-0 panic analysis from the delivered boot.img alone.

Every step prints the raw bytes / arithmetic it used, so nothing depends on trusting
this script's conclusions. Run:

    python out/verify-panic.py out/checkpoint-boot.img

Inputs: only the boot.img that was flashed (sha256 printed first).
Output: symbolication of the 6 panic frames, the call-site instruction, the stub, the
GOT slot bytes, and the decoded pointer. Compare each line with the claims in
out/P5-STAGE0-DIAGNOSIS.md.
"""
import hashlib
import struct
import sys
from pathlib import Path

FRAMES = [
    ("f0", 0xFFFFFFF00B44DDF8),
    ("from", 0xFFFFFFF00AB062BC),
    ("f2", 0xFFFFFFF00AD5EF58),
    ("f3", 0xFFFFFFF00B45BCD4),
    ("f4", 0xFFFFFFF00B45C1CC),
    ("f5", 0xFFFFFFF00AD8F5F0),
]
BASE = 0xFFFFFFF007004000          # __TEXT vmaddr of the emitted kernel
TARGET_LOW48 = 0x4449DC8           # (unixnu_fileset_unmapped - BASE)


def rule(title):
    print("\n== %s ==" % title)


def fat32_file(image, want_suffix):
    bps = struct.unpack_from("<H", image, 11)[0]
    spc = image[13]
    rsvd = struct.unpack_from("<H", image, 14)[0]
    nfats = image[16]
    fatsz = struct.unpack_from("<I", image, 36)[0]
    root = struct.unpack_from("<I", image, 44)[0]
    fat = rsvd * bps
    data = (rsvd + nfats * fatsz) * bps
    clen = spc * bps

    def chain(k):
        out = []
        while 2 <= k < 0x0FFFFFF8:
            out.append(k)
            k = struct.unpack_from("<I", image, fat + k * 4)[0] & 0x0FFFFFFF
        return out

    def read(k, size=None):
        raw = b"".join(image[data + (c - 2) * clen:data + (c - 1) * clen] for c in chain(k))
        return raw[:size] if size else raw

    def walk(k, depth=0):
        if depth > 6:
            return
        for i in range(0, len(read(k)), 32):
            e = read(k)[i:i + 32]
            if len(e) < 32 or e[0] == 0:
                return
            if e[0] == 0xE5 or e[11] == 0x0F:
                continue
            name = e[:11].decode("latin-1")
            base, ext = name[:8].rstrip(), name[8:].rstrip()
            name = base + ("." + ext if ext else "")
            if name in (".", ".."):
                continue
            clu = (struct.unpack_from("<H", e, 20)[0] << 16) | struct.unpack_from("<H", e, 26)[0]
            size = struct.unpack_from("<I", e, 28)[0]
            if e[11] & 0x10:
                yield from walk(clu, depth + 1)
            elif name.upper().endswith(want_suffix):
                yield name, read(clu, size)

    yield from walk(root)


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "out/checkpoint-boot.img")
    data = path.read_bytes()
    rule("input")
    print("file    ", path)
    print("bytes   ", len(data))
    print("sha256  ", hashlib.sha256(data).hexdigest())
    print("expected 894fa1d7eeaca9d55431f2be482d8b103afd9170da460f891a38f3c648904ae6")

    ks, ka, rs, ra, ss, sa, tags, page, ver, _ = struct.unpack_from("<10I", data, 8)
    rule("android boot header")
    print("magic   ", data[:8])
    print("kernel_size %d  ramdisk_size %d  page %d  header_version %d" % (ks, rs, page, ver))
    start = page * (1 + -(-ks // page))
    print("ramdisk offset", hex(start))
    rd = data[start:start + rs]
    print("ramdisk bytes", len(rd), "fstype", rd[82:90])

    macho = None
    for name, blob in fat32_file(rd, ".MAC"):
        print("ramdisk member %-24s %d bytes" % (name, len(blob)))
        if len(blob) > 50_000_000:
            macho = blob
    if macho is None:
        sys.exit("kernel.macho not found in the ramdisk")
    print("kernel.macho sha256", hashlib.sha256(macho).hexdigest())

    # ---- Mach-O ----
    ncmds = struct.unpack_from("<I", macho, 16)[0]
    segs, symtabs, entries = [], [], []
    p = 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", macho, p)
        if cmd == 0x19:
            name = macho[p + 8:p + 24].rstrip(b"\0").decode("latin-1")
            vm, vs, fo, fs = struct.unpack_from("<QQQQ", macho, p + 24)
            segs.append((name, vm, vs, fo, fs))
        elif cmd == 0x2:
            symtabs.append(struct.unpack_from("<IIII", macho, p + 8))
        elif cmd == 0x80000035:
            vm, fo, ilen, _ = struct.unpack_from("<QQII", macho, p + 8)
            entries.append(("".join(c if 32 <= ord(c) < 127 else "?" for c in
                                     macho[p + 32:p + 32 + ilen].rstrip(b"\0").decode("latin-1")), vm, fo))
        p += size
    rule("macho segments")
    for name, vm, vs, fo, fs in segs:
        print("  %-16s vmaddr %#018x vmsize %#010x fileoff %#010x" % (name, vm, vs, fo))

    rule("fileset entries that own each frame")
    for label, addr in FRAMES:
        owner = "?"
        for eid, vm, fo in entries:
            sub_ncmds = struct.unpack_from("<I", macho, fo + 16)[0]
            q = fo + 32
            for _ in range(sub_ncmds):
                c, s = struct.unpack_from("<II", macho, q)
                if c == 0x19:
                    n = macho[q + 8:q + 24].rstrip(b"\0").decode("latin-1")
                    svm, svs = struct.unpack_from("<QQ", macho, q + 24)
                    if svm <= addr < svm + svs:
                        owner = "%s:%s" % (eid, n)
                q += s
            if owner != "?":
                break
        print("  %-5s %#018x  %s" % (label, addr, owner))

    # ---- symbols ----
    rule("symbolication from every LC_SYMTAB in the image")
    pairs = []
    symtabs_all = list(symtabs)
    for eid, vm, fo in entries:
        q = fo + 32
        for _ in range(struct.unpack_from("<I", macho, fo + 16)[0]):
            c, s = struct.unpack_from("<II", macho, q)
            if c == 0x2:
                symtabs_all.append(struct.unpack_from("<IIII", macho, q + 8))
            q += s
    for symoff, nsyms, stroff, strsize in symtabs_all:
        strs = macho[stroff:stroff + strsize]
        for i in range(nsyms):
            strx, ntype, nsect, ndesc, nval = struct.unpack_from("<IBBHQ", macho, symoff + i * 16)
            if not (ntype & 0x0E) or (ntype & 0x01) or not nval:
                continue
            if nval < 0xFFFFFF0000000000:
                continue
            e = strs.find(b"\0", strx)
            pairs.append((nval, strs[strx:e].decode("latin-1")))
    pairs.sort()
    vals = [v for v, _ in pairs]
    print("  nlist_64 defined symbols kept:", len(pairs))
    for label, addr in FRAMES:
        lo, hi = 0, len(vals)
        while lo < hi:
            mid = (lo + hi) // 2
            if vals[mid] <= addr:
                lo = mid + 1
            else:
                hi = mid
        v, n = pairs[lo - 1]
        print("  %-5s %#018x  %s + %#x" % (label, addr, n, addr - v))

    # ---- call site ----
    exec_seg = [s for s in segs if s[0] == "__TEXT_EXEC"][0]
    _, evm, _, efo, efs = exec_seg

    def foff(addr):
        return efo + (addr - evm)

    def ins(addr):
        return struct.unpack_from("<I", macho, foff(addr))[0]

    call = FRAMES[1][1]
    rule("instruction at the call site (bytes straight from the file)")
    for k in range(-4, 2):
        a = call + 4 * k
        i = ins(a)
        txt = ""
        if (i >> 26) == 0x25:
            imm = i & 0x3FFFFFF
            if imm & 0x2000000:
                imm -= 0x4000000
            txt = "BL -> %#x" % (a + imm * 4)
        print("  %#018x  file %#x  %08x  %s" % (a, foff(a), i, txt))

    rule("the stub the call lands on")
    stub = None
    i = ins(call - 4)
    if (i >> 26) == 0x25:
        imm = i & 0x3FFFFFF
        if imm & 0x2000000:
            imm -= 0x4000000
        stub = (call - 4) + imm * 4
    print("stub address", "none" if stub is None else hex(stub))
    if stub is not None:
        for k in range(4):
            print("  %#018x  %08x" % (stub + 4 * k, ins(stub + 4 * k)))
        i0, i1, i2, i3 = (ins(stub + 4 * k) for k in range(4))
        assert (i3 & 0xFFFF0000) in (0xD61F0000, 0xD71F0000), "not a br/braa x16 stub"
        print("  stub kind: %s" % ("braa x16,x17 (authenticated)" if (i3 & 0xFFFF0000) == 0xD71F0000 else "br x16"))
        immlo, immhi = (i0 >> 29) & 3, (i0 >> 5) & 0x7FFFF
        page = ((immhi << 2) | immlo) << 12
        if page >> 32:
            page -= 1 << 33
        page = (stub & ~0xFFF) + page
        add = ((i1 >> 10) & 0xFFF) << (12 * ((i1 >> 22) & 1))
        got = page + add
        rule("GOT slot")
        print("  adrp page %#x  add #%#x  => slot %#018x" % (page, add, got))
        raw = struct.unpack_from("<Q", macho, foff(got))[0]
        print("  raw 8 bytes at file %#x: %016x" % (foff(got), raw))
        low = raw & 0xFFFFFFFFFFFF
        print("  low 48 bits 0x%x + BASE 0x%x = %#x" % (low, BASE, BASE + low))
        print("  expected _unixnu_fileset_unmapped = 0xfffffff00b44ddc8")
        print("  MATCH" if BASE + low == 0xFFFFFFF00B44DDC8 else "  MISMATCH")

    rule('the string in x0 (the panic reported x0 = 0xfffffff007db7045)')
    x0 = 0xFFFFFFF007DB7045
    o = foff(x0)
    print("  file %#x: %r" % (o, macho[o:o + 12]))

    rule("count of slots pointing at the panic stub (independent of the 320 claim)")
    hits = 0
    for off in range(0, len(macho) - 8, 8):
        if struct.unpack_from("<Q", macho, off)[0] & 0xFFFFFFFFFFFF == TARGET_LOW48:
            hits += 1
    print("  8-byte words with low48 == 0x%x : %d" % (TARGET_LOW48, hits))


if __name__ == "__main__":
    main()
