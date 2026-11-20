#!/usr/bin/env python3
"""Check the emitted Ishtar FTM5/HID path and all 24A446 vtable PAC slots.

This gate checks compiled and emitted artifacts. It does not establish physical
GPI transfers, touch input, power state, IRQ delivery, or successful iOS use.
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
REQUIRED = (
    '_native_ishtar_touch_start', '_ishtar_touch_platform_create',
    '_ishtar_touch_platform_start', '_ishtar_touch_platform_poll',
    '_ishtar_touch_platform_stop', '_ishtar_touch_platform_destroy',
    '_gpi_spi_exchange', '_ftm5_start', '_ftm5_read_events',
    '_touch_contacts_update', '_touch_contacts_prepare',
    '_touch_contacts_commit', '_touch_contacts_release_all',
)

class Mapped(mmap.mmap):
    def index(self, needle, start=0, end=None):
        pos = self.find(needle, start, len(self) if end is None else end)
        if pos < 0:
            raise ValueError('bounded string missing')
        return pos

def require(value, message):
    if not value:
        raise ValueError(message)

def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def branches(code, pc):
    for offset in range(0, len(code) - 3, 4):
        word, = struct.unpack_from('<I', code, offset)
        if word >> 26 in (0x05, 0x25):
            imm = word & 0x3ffffff
            if imm & 0x2000000:
                imm -= 0x4000000
            yield pc + offset + 4 * imm

def function(image, address):
    starts = image.function_starts()
    i = bisect.bisect_right(starts, address)
    require(i > 0 and starts[i - 1] == address and i < len(starts),
            f'function boundary missing: {address:#x}')
    length = starts[i] - address
    require(0 < length <= 256 * 1024, 'unexpected function size')
    return image.read(address, length)

def check(original, emitted, Image, args):
    abi = json.loads(args.abi.read_text())
    report_path = args.tree / 'build/native-ishtar-touch/build-report.json'
    report = json.loads(report_path.read_text())
    require(hashlib.sha256(original).hexdigest() == ORIGINAL_HASH == abi['kernelcache_sha256'] == report['kernelcache_sha256'],
            'wrong original kernelcache or ABI fixture')
    require(report['original_instructions_modified'] is False, 'owned adapter must preserve original instructions')
    archive = args.tree / 'build/native-ishtar-touch/libNativeIshtarTouch.late.a'
    require(sha(archive) == report['archive_sha256'], 'archive changed after qualification')
    require(bool(report['source_sha256']), 'source hashes absent')
    for path, digest in report['source_sha256'].items():
        require(sha(args.tree / path) == digest, 'source changed after compile: ' + path)
    require(len(abi['slots']) == report['virtual_entries'] == len(report['vtable_symbols']) == 207,
            'expected all 207 target IOHIDDevice virtual slots')
    src, dst = Image(original), Image(emitted)
    native = Image(emitted, dst.entries['com.apple.kernel'][1])
    symbols = {name: address for address, names in native.symbols().items() for name in names}
    for name in REQUIRED:
        require(name in symbols, 'missing touch function: ' + name)
    late = symbols.get('_native_legacy_display_late_probe')
    require(late is not None, 'late IOBSD display entry missing')
    require(symbols['_native_ishtar_touch_start'] in set(branches(function(native, late), late)),
            'late IOBSD entry does not call the touch startup')
    vtable = symbols.get(report['vtable_symbol'])
    require(vtable is not None, 'owned touch vtable missing')
    src_fixups, fixups = src.fixups(), dst.fixups()
    rows = []
    for index, ((_, diversity), name) in enumerate(zip(abi['slots'], report['vtable_symbols'])):
        site = vtable + 16 + 8 * index
        actual = fixups.get(site)
        require(actual is not None, f'missing owned vtable fixup {index}')
        require(actual[1:] == (1, 0, int(diversity, 16), 1), f'wrong owned vtable PAC metadata {index}')
        require(name in symbols and actual[0] == symbols[name], f'wrong owned vtable target {index}: {name}')
        rows.append({'slot': index, 'symbol': name, 'target': hex(actual[0]), 'diversity': diversity})
    slide = int(abi['collection_slide'], 16)
    original_vtable = int(abi['vtable'], 16) + slide
    hid_entries = [value for name, value in src.entries.items() if name.endswith('.IOHIDFamily')]
    require(len(hid_entries) == 1, 'original IOHIDFamily entry missing or ambiguous')
    hid = Image(original, hid_entries[0][1])
    code_ranges = [(s['va'], s['va'] + s['size']) for s in hid.segments if s['name'] == '__TEXT_EXEC']
    retained_family_slots = 0
    for index, (target, diversity) in enumerate(abi['slots']):
        site = original_vtable + 8 * index
        before, after = src_fixups.get(site), fixups.get(site)
        require(before is not None and after is not None, f'original class vtable slot {index} absent')
        require(before[0] == int(target, 16) + slide and before[3] == int(diversity, 16), 'fixture slot mismatch')
        require(before[1:] == after[1:], f'original class PAC metadata changed {index}')
        if any(lo <= before[0] < hi for lo, hi in code_ranges):
            require(before == after, f'original IOHIDFamily vtable target changed {index}')
            retained_family_slots += 1
    bindings = []
    for name, address in report['bindings'].items():
        original_address = int(address, 16)
        if name in ('__ZN11IOHIDDevice10gMetaClassE', '__ZTV11IOHIDDevice'):
            continue
        require(name in symbols, 'original class thunk missing: ' + name)
        thunk = symbols[name]
        require(original_address in set(branches(dst.read(thunk, 8), thunk)), 'original class thunk target drift: ' + name)
        require(src.read(original_address, 16) == dst.read(original_address, 16), 'original function instructions changed: ' + name)
        bindings.append({'symbol': name, 'target': address, 'thunk': hex(thunk)})
    return {'result': 'PASS', 'hardware_verified': False, 'input_driver_integrated': True,
            'kernel_sha256': hashlib.sha256(emitted).hexdigest(), 'original_sha256': ORIGINAL_HASH,
            'archive_sha256': report['archive_sha256'], 'virtual_entries': len(rows),
            'vtable': hex(vtable), 'vtable_slots': rows,
            'original_family_slots_preserved': retained_family_slots, 'original_bindings': bindings,
            'startup': {'caller': hex(late), 'callee': hex(symbols['_native_ishtar_touch_start'])},
            'required_functions': {name: hex(symbols[name]) for name in REQUIRED},
            'boot_argument': 'ishtar-touch=1', 'coordinate_maximum': [14400, 32000],
            'hid_coordinate_maximum': [32767, 32767], 'contacts': 10,
            'data_mib': 256, 'root_partition': 'ios_root'}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ('module-dir', 'original', 'kernel', 'tree', 'abi', 'report'):
        parser.add_argument('--' + option, type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.module_dir))
    from kc_image import Image
    try:
        with args.original.open('rb') as source, args.kernel.open('rb') as output:
            with Mapped(source.fileno(), 0, access=mmap.ACCESS_READ) as original, Mapped(output.fileno(), 0, access=mmap.ACCESS_READ) as emitted:
                result = check(original, emitted, Image, args)
    except (ValueError, KeyError, OSError, struct.error) as exc:
        result = {'result': 'FAIL', 'reason': str(exc), 'hardware_verified': False, 'input_driver_integrated': False}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: value for key, value in result.items() if key != 'vtable_slots'}))
    return 0 if result['result'] == 'PASS' else 1

if __name__ == '__main__':
    raise SystemExit(main())
