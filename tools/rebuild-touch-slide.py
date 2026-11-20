#!/usr/bin/env python3
"""Rebuild once if the first fileset emission moved the owned native text."""
import argparse
import json
from pathlib import Path
import subprocess


def values(tree):
    report = json.loads((tree / 'build/native-ishtar-touch/build-report.json').read_text())
    measured = int((tree / 'build/native-legacy-display/native-slide').read_text().strip(), 16)
    return int(report['native_slide'], 16), measured


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tree', type=Path, required=True)
    parser.add_argument('--device', type=Path, required=True)
    args = parser.parse_args()
    used, measured = values(args.tree)
    if used == measured:
        print(f'Touch original bindings use the measured native slide {used:#x}')
        return
    print(f'Rebuilding original bindings once: used {used:#x}, measured {measured:#x}', flush=True)
    subprocess.run(['./unixnu', 'build', 'kernel', '-D', str(args.device)], check=True)
    used, measured = values(args.tree)
    if used != measured:
        raise SystemExit(f'Native text slide did not stabilize after one rebuild: {used:#x} != {measured:#x}')
    print(f'Touch original bindings stabilized at native slide {used:#x}')

if __name__ == '__main__':
    main()
