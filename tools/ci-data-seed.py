#!/usr/bin/env python3
"""Build the APFS Data seed inside the ishtar CI job and align the kernel config.

Runs on the macOS runner, after `./unixnu defconfig` / `ipsw fetch` / AEA
decrypt and before `./unixnu build kernel`:

    python3 <ci>/tools/ci-data-seed.py \
        --device ../device --unixnu . --config <work>/.config \
        --out out/ishtar/.../data-seed

It calls the device repository's scripts/build-data-seed.py, which needs the
decrypted OS .dmg, its .dmg.json sidecar, hdiutil/diskutil and DarwinBoot's
packed_ramdisk. The generated 32 MiB packed seed is written to
--out/owner-data-32.dbr; its APFS VolumeUUID is written to seed.json and also
patched into the generated .config so CONFIG_XNU_OWNER_DATA_VOLUME_UUID in
kern_exec.c matches the seed the payload carries.

Nothing is written to either repository. The caller passes the printed seed
path to `./unixnu build payload --data-ramdisk FILE`.
"""
import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

UUID = re.compile(r'^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$')
LINE = re.compile(r'^CONFIG_XNU_OWNER_DATA_VOLUME_UUID="[^"]*"$', re.M)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--device', type=Path, required=True)
    ap.add_argument('--unixnu', type=Path, required=True, help='UniXNU checkout (cwd of build-data-seed.py)')
    ap.add_argument('--config', type=Path, required=True, help='generated .config to patch')
    ap.add_argument('--out', type=Path, required=True, help='output directory for the seed')
    a = ap.parse_args()

    device = a.device.resolve()
    tree = a.unixnu.resolve()
    config = a.config.resolve()
    out = a.out.resolve()
    out.mkdir(parents=True, exist_ok=True)

    script = device / 'scripts/build-data-seed.py'
    if not script.is_file():
        raise SystemExit(f'Data seed script missing: {script}')
    if not config.is_file():
        raise SystemExit(f'generated config missing: {config}')

    # build-data-seed.py refuses to overwrite; this job starts from a clean runner.
    packed = out / 'owner-data-32.dbr'
    if packed.is_file():
        packed.unlink()
    raw = out / 'owner-data-32.cdr'
    if raw.is_file():
        raw.unlink()
    report_path = out / 'seed.json'

    env = dict(os.environ)
    subprocess.run([sys.executable, str(script), '--out', str(out)],
                   cwd=tree, env=env, check=True)

    if not packed.is_file() or not report_path.is_file():
        raise SystemExit('build-data-seed.py did not produce owner-data-32.dbr and seed.json')
    report = json.loads(report_path.read_text())
    uuid = report.get('volume_uuid')
    if not isinstance(uuid, str) or not UUID.match(uuid):
        raise SystemExit(f'seed.json has an invalid volume_uuid: {uuid!r}')

    text = config.read_text()
    found = LINE.findall(text)
    if len(found) != 1:
        raise SystemExit(f'expected exactly one CONFIG_XNU_OWNER_DATA_VOLUME_UUID in {config}, got {len(found)}')
    replacement = f'CONFIG_XNU_OWNER_DATA_VOLUME_UUID="{uuid}"'
    patched = LINE.sub(replacement, text, count=1)
    if patched != text:
        config.write_text(patched)
        print(f'patched {config}: {replacement}')
    else:
        print(f'config already matches: {replacement}')

    # Emit the exact path for the payload step (shell captures stdout's last line).
    print(f'DATA_SEED={packed}')
    print(f'DATA_UUID={uuid}')
    print(json.dumps({'seed': str(packed), 'volume_uuid': uuid,
                      'packed_sha256': report.get('packed_sha256')}, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
