#!/usr/bin/env python3
"""Read-only emitted VFS credential binding audit for the pinned 24A446 fileset."""
import argparse
import bisect
import hashlib
import json
import mmap
from pathlib import Path
import struct
import sys

ORIGINAL_HASH = 'fa07057bf34f33af1ec26681ad0c87c13e5aaa548a300740eddb0e92876e5f95'
GETTER_HASH = '91fe54c083eb0b9168494a7cca1b46d068b795c7ba94ea2e14d0c8f9d165b9d5'
GETTER_BYTES = bytes.fromhex('5f2403d5000440f9c0035fd6')
CREDENTIAL = 0xfffffff00add321c
BUF_OFFSET = 0xfffffff00ad7ab64
APFS_GOT = 0xfffffff0083d6600
CALLS = [(0xfffffff00a992064, 0xfffffff00aa7d284, 0xfffffff0083d65a0, '_vfs_context_current'),
         (0xfffffff00a992068, 0xfffffff00aa7d344, APFS_GOT, '_vfs_context_ucred'),
         (0xfffffff00a99206c, 0xfffffff00aa7c6e4, 0xfffffff0083d5fd0, '_kauth_cred_getuid')]

class Mapped(mmap.mmap):
    def index(self, value, start=0, end=None):
        pos = self.find(value, start, len(self) if end is None else end)
        if pos < 0:
            raise ValueError('missing string')
        return pos

def need(ok, message):
    if not ok:
        raise ValueError(message)

def function(image, va):
    starts = image.function_starts()
    need(va in starts, f'not a function start: {va:#x}')
    i = bisect.bisect_right(starts, va)
    need(i < len(starts) and 0 < starts[i]-va <= 4096, 'invalid function extent')
    return image.read(va, starts[i]-va)

def branch(image, pc):
    word, = struct.unpack('<I', image.read(pc, 4))
    need(word >> 26 == 0x25, f'not a BL: {pc:#x}')
    imm = word & 0x3ffffff
    if imm & 0x2000000:
        imm -= 0x4000000
    return pc + imm * 4

def stub_site(image, va):
    a,b,c,d = struct.unpack('<4I',image.read(va,16))
    need(a & 0x9f00001f == 0x90000011, 'expected ADRP x17')
    need(b & 0xffc003ff == 0x91000231, 'expected unshifted ADD x17,x17')
    need(c == 0xf9400230 and d == 0xd71f0a11, 'expected authenticated GOT stub')
    imm = ((a >> 5) & 0x7ffff) << 2 | ((a >> 29) & 3)
    if imm & 0x100000:
        imm -= 0x200000
    return (va & ~4095) + (imm << 12) + ((b >> 10) & 0xfff)

def check(original, emitted, Image):
    need(hashlib.sha256(original).hexdigest()==ORIGINAL_HASH, 'wrong original kernelcache')
    src,dst = Image(original),Image(emitted)
    sk = Image(original,src.entries['com.apple.kernel'][1])
    dk = Image(emitted,dst.entries['com.apple.kernel'][1])
    sf,df = src.fixups(),dst.fixups()
    symbols = {n:va for va,ns in dk.symbols().items() for n in ns}
    identities = {CREDENTIAL:'_vfs_context_ucred',BUF_OFFSET:'_bufattr_cpoff'}
    for va,name in identities.items():
        need(function(sk,va)==GETTER_BYTES, f'original getter bytes changed: {va:#x}')
        need(hashlib.sha256(function(sk,va)).hexdigest()==GETTER_HASH, 'getter digest mismatch')
        need(name in symbols and function(dk,symbols[name])==GETTER_BYTES,
             f'native getter implementation changed: {name}')
    need(sf[APFS_GOT][0]==CREDENTIAL, 'original APFS credential GOT changed')
    # Preserve the complete APFS caller (getattrlistbulk implementation helper).
    caller_start,caller_size = 0xfffffff00a991d40,2440
    need(src.read(caller_start,caller_size)==dst.read(caller_start,caller_size), 'APFS caller changed')
    for pc,stub,got,name in CALLS:
        need(branch(src,pc)==stub and branch(dst,pc)==stub, f'call chain changed at {pc:#x}')
        need(stub_site(src,stub)==got and stub_site(dst,stub)==got, f'GOT stub changed at {stub:#x}')
        actual = df.get(got)
        need(actual is not None and actual[0]==symbols[name],
             f'wrong APFS binding at {got:#x}: {hex(actual[0]) if actual else None}; expected {name}')
        need(actual[1:]==sf[got][1:], 'authentication metadata changed')
    bindings=[]
    for entry,(_,fo) in dst.entries.items():
        if entry=='com.apple.kernel' or entry not in src.entries:
            continue
        ranges=Image(emitted,fo).mapped()
        for site,target in sf.items():
            name=identities.get(target[0])
            if not name or not any(a<=site<b for a,b in ranges):
                continue
            actual=df.get(site)
            need(actual is not None and actual[0]==symbols[name],f'wrong retained {name} binding: {entry} {site:#x}')
            need(actual[1:]==target[1:],f'auth metadata changed: {site:#x}')
            bindings.append({'entry':entry,'site':hex(site),'original':hex(target[0]),'native':hex(actual[0]),'name':name})
    return {'result':'PASS','hardware_verified':False,'original_sha256':ORIGINAL_HASH,
            'kernel_sha256':hashlib.sha256(emitted).hexdigest(),
            'apfs_caller_sha256':hashlib.sha256(dst.read(caller_start,caller_size)).hexdigest(),
            'retained_bindings':bindings,'call_chain':[{'pc':hex(pc),'got':hex(got),'name':name} for pc,stub,got,name in CALLS]}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for arg in ('module-dir','original','kernel','report'):
        p.add_argument('--'+arg,type=Path,required=True)
    args=p.parse_args();sys.path.insert(0,str(args.module_dir))
    from kc_image import Image
    try:
        with args.original.open('rb') as a,args.kernel.open('rb') as b:
            with Mapped(a.fileno(),0,access=mmap.ACCESS_READ) as src,Mapped(b.fileno(),0,access=mmap.ACCESS_READ) as dst:
                result=check(src,dst,Image)
    except (ValueError,KeyError,struct.error) as exc:
        result={'result':'FAIL','reason':str(exc),'hardware_verified':False}
    args.report.parent.mkdir(parents=True,exist_ok=True)
    args.report.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result))
    return 0 if result['result']=='PASS' else 1

if __name__=='__main__':
    raise SystemExit(main())
