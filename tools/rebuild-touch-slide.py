#!/usr/bin/env python3
"""Verify emitter-relocated original HID stubs without a second kernel build.

The pinned emitter consumes raw <stub>.original collection addresses. Subtracting
native-slide in the adapter would apply the relocation twice.
"""
import argparse
import importlib.util
import json
import mmap
from pathlib import Path
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tree', type=Path, required=True)
    parser.add_argument('--kernel', type=Path, required=True)
    args = parser.parse_args()
    source = Path(__file__).resolve().with_name('check-ishtar-touch.py')
    spec = importlib.util.spec_from_file_location('touch_gate', source)
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    sys.path.insert(0, str(args.tree / 'kits/XnuPrelink'))
    from kc_image import Image
    report = json.loads((args.tree / 'build/native-ishtar-touch/build-report.json').read_text())
    with args.kernel.open('rb') as stream:
        with gate.Mapped(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
            collection = Image(data)
            native = Image(data, collection.entries['com.apple.kernel'][1])
            symbols = {name: address for address, names in native.symbols().items() for name in names}
            bindings = gate.verify_original_bindings(report, native, symbols)
    result = {'result': 'PASS', 'relocation_mode': report['relocation_mode'],
              'native_slide_compensated': False, 'original_bindings': bindings,
              'hardware_verified': False}
    target = args.tree / 'build/native-ishtar-touch/prelink-bindings.json'
    target.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'result': 'PASS', 'original_bindings': len(bindings),
                      'relocation_mode': report['relocation_mode'], 'native_slide_compensated': False}))


if __name__ == '__main__':
    main()
