#!/usr/bin/env python3
"""GPU-stage3 only: treat __LASTDATA_CONST as a zero-length layout marker.

The ishtar iPhone17,2 kernelcache leaves 0x123578 bytes before the first
retained __DATA_CONST kext. The native kernel's __DATA_CONST is 0x120000 and
XNU's __LASTDATA_CONST separator is page-sized to 0x4000, so the marker's
validated span overlaps AppleARMPlatform by 0xa88 bytes. Its only payload is a
single __mod_init_func pointer; it does not need a mapped 16 KiB span in the
fileset. This patch makes the XnuPrelink layout use zero span for that marker
without moving any real data or changing the retained kext layout.
"""
from pathlib import Path
import sys

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else 'unixnu')
p = ROOT / 'kits' / 'XnuPrelink' / 'fileset_layout.py'
if not p.is_file():
    raise SystemExit(f'missing XnuPrelink layout: {p}')
text = p.read_text()
old = "        self.mapped = {'__TEXT': min(self.segment('__TEXT')['size'], room // 0x1000 * 0x1000)}\n"
new = (
    old +
    "        # GPU-stage3: __LASTDATA_CONST is a separator marker with a single pointer;\n"
    "        # its page-sized native span would overlap the first retained __DATA_CONST kext.\n"
    "        self.mapped['__LASTDATA_CONST'] = 0\n"
)
if new in text:
    print('already patched', p)
elif text.count(old) != 1:
    raise SystemExit('unexpected fileset_layout.py mapped line')
else:
    p.write_text(text.replace(old, new, 1))
    print('PATCHED', p)
