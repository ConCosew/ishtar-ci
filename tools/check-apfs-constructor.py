#!/usr/bin/env python3
"""Verify the 24A446 IOUserClient constructor ABI in an emitted fileset.

Read-only. Uses XnuPrelink's pinned parser; hashes files through mmap and reads
bounded code ranges. The delivered failing image must FAIL this gate.
"""
import argparse
import bisect
import hashlib
import json
import mmap
from pathlib import Path
import struct
import sys

ORIGINAL_HASH = 'fa07057bf34f33af1ec26681ad0c87c13e5aaa548a300740eddb0e92876e5f95'
ORIGINAL_CTOR = 0xfffffff00b35cac0
ORIGINAL_CTOR_HASH = '9d1511bca55aae2b728ad62a4ef063d4214610a266d77347e77ac2039bfb13d3'
APFS_SITE = 0xfffffff0083d5920
ALLOC = 0xfffffff00a97e9fc
CHAIN = ['__ZN12IOUserClientC2EPK11OSMetaClass',
         '__ZN9IOServiceC2EPK11OSMetaClass',
         '__ZN15IORegistryEntryC2EPK11OSMetaClass',
         '__ZN8OSObjectC2EPK11OSMetaClass', '__ZN15OSMetaClassBaseC2Ev']

class Mapped(mmap.mmap):
    def index(self, needle, start=0, end=None):
        pos = self.find(needle, start, len(self) if end is None else end)
        if pos < 0:
            raise ValueError('missing bounded string')
        return pos

def require(value, message):
    if not value:
        raise ValueError(message)

def function(image, address):
    starts = image.function_starts()
    require(address in starts, f'function start absent: {address:#x}')
    i = bisect.bisect_right(starts, address)
    require(i < len(starts), 'unbounded last function')
    length = starts[i] - address
    require(0 < length <= 4096, f'unexpected constructor length {length}')
    return image.read(address, length)

def calls(code, pc):
    targets = []
    for off in range(0, len(code), 4):
        word, = struct.unpack_from('<I', code, off)
        if word >> 26 == 0x25:
            imm = word & 0x3ffffff
            if imm & 0x2000000:
                imm -= 0x4000000
            targets.append(pc + off + 4 * imm)
    return targets

def check(original, emitted, Image):
    require(hashlib.sha256(original).hexdigest() == ORIGINAL_HASH, 'wrong original kernelcache')
    src = Image(original)
    dst = Image(emitted)
    sk = Image(original, src.entries['com.apple.kernel'][1])
    dk = Image(emitted, dst.entries['com.apple.kernel'][1])
    old_code = function(sk, ORIGINAL_CTOR)
    require(len(old_code) == 44 and hashlib.sha256(old_code).hexdigest() == ORIGINAL_CTOR_HASH,
            'original constructor bytes changed')
    initializer = bytes.fromhex('28008052080800b9')  # mov w8,#1; str w8,[x0,#8]
    require(old_code[4:12] == initializer, 'original refcount initialization absent')
    # APFS allocator passes x1=metaclass and calls the constructor before replacing vptr.
    require(src.read(ALLOC, 108) == dst.read(ALLOC, 108), 'APFS allocator changed or moved')
    require(0xfffffff00aa7b984 in calls(src.read(ALLOC, 108), ALLOC), 'APFS constructor call missing')
    orig_fix, emitted_fix = src.fixups(), dst.fixups()
    require(orig_fix[APFS_SITE][0] == ORIGINAL_CTOR, 'original APFS constructor GOT changed')
    names = {name: va for va, ns in dk.symbols().items() for name in ns}
    chain = []
    for i, name in enumerate(CHAIN):
        require(name in names, f'missing native constructor {name}')
        va = names[name]
        code = function(dk, va)
        edges = calls(code, va)
        expected = [names[CHAIN[i+1]]] if i+1 < len(CHAIN) else []
        require(edges == expected, f'unexpected constructor calls: {name}')
        chain.append({'name': name, 'address': hex(va), 'size': len(code),
                      'sha256': hashlib.sha256(code).hexdigest(),
                      'initializes_refcount': initializer in code})
    require(chain[3]['initializes_refcount'], 'OSObject constructor must initialize refcount to one')
    require(not chain[4]['initializes_refcount'], 'base constructor unexpectedly changed; re-review ABI')
    expected = names[CHAIN[0]]
    retained = []
    for entry, (_, fo) in src.entries.items():
        if entry == 'com.apple.kernel' or entry not in dst.entries:
            continue
        segments = Image(original, fo).segments
        for site, target in orig_fix.items():
            if target[0] != ORIGINAL_CTOR or not any(s['va'] <= site < s['va']+s['size'] for s in segments):
                continue
            actual = emitted_fix.get(site)
            require(actual is not None, f'retained constructor fixup missing: {entry} {site:#x}')
            require(actual[0] == expected,
                    f'wrong constructor binding: {entry} {site:#x} -> {actual[0]:#x}, expected {expected:#x}')
            require(actual[1:] == target[1:], f'authentication metadata changed: {site:#x}')
            retained.append({'entry': entry, 'site': hex(site), 'target': hex(actual[0])})
    require(any(int(r['site'],16) == APFS_SITE for r in retained), 'APFS binding not checked')
    return {'result':'PASS', 'hardware_verified':False,
            'original_sha256':ORIGINAL_HASH, 'kernel_sha256':hashlib.sha256(emitted).hexdigest(),
            'original_constructor':hex(ORIGINAL_CTOR), 'native_constructor':hex(expected),
            'constructor_chain':chain, 'retained_bindings':retained}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--module-dir', type=Path, required=True)
    parser.add_argument('--original', type=Path, required=True)
    parser.add_argument('--kernel', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.module_dir))
    from kc_image import Image
    try:
        with args.original.open('rb') as sf, args.kernel.open('rb') as df:
            with Mapped(sf.fileno(),0,access=mmap.ACCESS_READ) as original, Mapped(df.fileno(),0,access=mmap.ACCESS_READ) as emitted:
                result = check(original, emitted, Image)
    except (ValueError, KeyError, struct.error) as exc:
        result = {'result':'FAIL', 'reason':str(exc), 'hardware_verified':False}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result,indent=2)+'\n', encoding='utf-8')
    print(json.dumps(result,ensure_ascii=True))
    return 0 if result['result']=='PASS' else 1

if __name__ == '__main__':
    raise SystemExit(main())
