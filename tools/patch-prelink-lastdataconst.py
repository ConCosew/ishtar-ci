#!/usr/bin/env python3
"""GPU-stage3 only: treat __LASTDATA_CONST as a zero-length layout marker.

The pinned XnuPrelink 9b950f2e Layout.end() uses the native segment size for
every segment. On the ishtar iPhone17,2 kernelcache, __DATA_CONST is 0x120000
and the __LASTDATA_CONST separator is page-sized to 0x4000, so the marker's
validated span overlaps the first retained __DATA_CONST kext (AppleARMPlatform)
by 0xa88 bytes. Its only payload is a single __mod_init_func pointer; it does
not need a mapped 16 KiB span in the fileset. This patch makes only that marker
zero-length, without moving real data or changing retained kext layout.
"""
from pathlib import Path
import sys

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else 'unixnu')
p = ROOT / 'kits' / 'XnuPrelink' / 'fileset_layout.py'
if not p.is_file():
    raise SystemExit(f'missing XnuPrelink layout: {p}')
text = p.read_text()
old = """    def end(self, name):
        return self.placements[name] + self.segment(name)['size']
"""
new = """    def end(self, name):
        # GPU-stage3: __LASTDATA_CONST is a separator marker with one pointer.
        # Its page-sized native span would overlap the first retained kext.
        if name == '__LASTDATA_CONST':
            return self.placements[name]
        return self.placements[name] + self.segment(name)['size']
"""
if new in text:
    print('already patched', p)
elif text.count(old) != 1:
    raise SystemExit('unexpected pinned fileset_layout.py end() body')
else:
    p.write_text(text.replace(old, new, 1))
    print('PATCHED', p)
