#!/usr/bin/env python3
"""Offline: map every panic stub in a boot.img to the function it SHOULD call.

No device, no CI, no boot. Usage:

    python out/resolve-stubs.py <boot.img> <kernelcache.decompressed>

For each rewritten GOT slot in the emitted kernel, read the same address in the
ORIGINAL kernelcache, decode the arm64e authenticated pointer, and report the
true target. Also reports how many distinct targets remain and the top ones by
slot count, and whether a given panic `from` address' target is in the list.
"""
import collections
import importlib.util
import json
import struct
import sys
from pathlib import Path

BASE = 0xFFFFFFF007004000


def load_verify():
    p = Path(__file__).with_name("verify-panic.py")
    spec = importlib.util.spec_from_file_location("vp", p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def segments(d):
    n = struct.unpack_from("<I", d, 16)[0]
    p, out = 32, []
    for _ in range(n):
        c, s = struct.unpack_from("<II", d, p)
        if c == 0x19:
            vm, vs, fo, fs = struct.unpack_from("<QQQQ", d, p + 24)
            if fs:
                out.append((vm, vs, fo, fs))
        p += s
    return out


def symtabs(d):
    n = struct.unpack_from("<I", d, 16)[0]
    p, tabs, entries, base = 32, [], [], None
    for _ in range(n):
        c, s = struct.unpack_from("<II", d, p)
        if c == 0x19 and d[p + 8:p + 24].split(b"\0")[0] == b"__TEXT":
            base = struct.unpack_from("<Q", d, p + 24)[0]
        elif c == 0x2:
            tabs.append(struct.unpack_from("<IIII", d, p + 8))
        elif c == 0x80000035:
            entries.append(struct.unpack_from("<QQ", d, p + 8)[1])
        p += s
    for fo in entries:
        q = fo + 32
        for _ in range(struct.unpack_from("<I", d, fo + 16)[0]):
            c, s = struct.unpack_from("<II", d, q)
            if c == 0x2:
                tabs.append(struct.unpack_from("<IIII", d, q + 8))
            q += s
    return tabs, base


def find_stub(d, tabs, base):
    found = []
    for so, ns, sto, sts in tabs:
        strs = d[sto:sto + sts]
        for i in range(ns):
            sx, nt, nse, nd, v = struct.unpack_from("<IBBHQ", d, so + i * 16)
            e = strs.find(b"\0", sx)
            if v and strs[sx:e] == b"_unixnu_fileset_unmapped":
                found.append(v)
    # the symbol appears once in the __TEXT view and once in __TEXT_EXEC;
    # rewritten GOT slots use the executable view, i.e. the higher address
    return max(found) if found else None


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    boot = Path(sys.argv[1]).read_bytes()
    kc = Path(sys.argv[2]).read_bytes()
    vp = load_verify()
    ks, _, rs, _, _, _, _, page, _, _ = struct.unpack_from("<10I", boot, 8)
    start = page * (1 + -(-ks // page))
    rd = boot[start:start + rs]
    macho = [b for _, b in vp.fat32_file(rd, ".MAC") if len(b) > 50_000_000][0]

    tabs, base = symtabs(macho)
    stub = find_stub(macho, tabs, base)
    assert stub and base, "could not find the panic stub / __TEXT base"
    low = (stub - base) & 0xFFFFFFFFFFFF
    esg, osg = segments(macho), segments(kc)

    def foff(sg, a):
        for vm, vs, fo, fs in sg:
            if vm <= a < vm + vs:
                return fo + (a - vm)
        return None

    rows = []
    for off in range(0, len(macho) - 8, 8):
        if struct.unpack_from("<Q", macho, off)[0] & 0xFFFFFFFFFFFF != low:
            continue
        va = None
        for vm, vs, fo, fs in esg:
            if fo <= off < fo + fs:
                va = vm + (off - fo)
                break
        o = foff(osg, va) if va is not None else None
        if va is None or o is None:
            continue
        w = struct.unpack_from("<Q", kc, o)[0]
        rows.append((va, BASE + (w & 0xFFFFFFFFFFFF)))

    cnt = collections.Counter(t for _, t in rows)
    print("kernel        ", sys.argv[2])
    print("boot image    ", sys.argv[1])
    print("panic stub    ", hex(stub))
    print("STUB_SLOTS    ", len(rows))
    print("distinct targets", len(cnt))
    print("\ntop targets by number of slots:")
    for t, c in cnt.most_common(20):
        print("  %#018x  slots=%d" % (t, c))
    out = Path("out/stub-targets.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"slots": [[hex(a), hex(t)] for a, t in rows]}, indent=1) + "\n")
    print("\nwrote", out)


if __name__ == "__main__":
    main()
