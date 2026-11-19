#!/usr/bin/env python3
"""Build the ordinary iOS 27 Data seed with enough verified capacity for its GPU addon.

The pinned seed-data-grow.py supports explicit MiB sizing. This job grows the APFS container to 256 MiB while preserving the Volume UUID and verifying the exact seed identity. The resulting seed remains below RamBlock's 2 GiB volatile-sparse fallback limit. On seed identity mismatch, the existing overlay is kept untouched and this boot runs with volatile Data; it does not resume the old persistent store.
"""
import argparse
import hashlib
import json
import os
import plistlib
import re
import struct
import subprocess
import sys
import tempfile
import tomllib
import zlib
from pathlib import Path

UUID = re.compile(r'^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$')
LINE = re.compile(r'^CONFIG_XNU_OWNER_DATA_VOLUME_UUID="[^"]*"$', re.M)
MIB = 1024 ** 2
GIB = 1024 ** 3
BLOCK = 4096
EXPECTED_ROOT_IMAGE_BYTES = 16_375_611_392
EXPECTED_IOS_ROOT = (71894012, 124322810, 4096)
GUARD_BLOCKS = 1024
RUNTIME_DATA_HEADROOM = 128 * MIB


def inspect_addon(path):
    """Validate the NGPUADD2 table and each zlib stream; return the aggregate expanded size."""
    blob = path.read_bytes()
    if len(blob) < 24:
        raise SystemExit('GPU addon is shorter than its NGPUADD2 header')
    magic, count, _reserved, total = struct.unpack_from('<8sIIQ', blob)
    if magic != b'NGPUADD2' or total != len(blob) or not 0 < count <= 4096:
        raise SystemExit('GPU addon has an invalid NGPUADD2 header')
    offset = 24
    expanded = 0
    names = []
    for _ in range(count):
        if len(blob) - offset < 24:
            raise SystemExit('GPU addon has a truncated entry header')
        name_bytes, mode, size, packed = struct.unpack_from('<IIQQ', blob, offset)
        offset += 24
        padded_name = (name_bytes + 7) & ~7
        padded_data = (packed + 7) & ~7
        if (name_bytes < 2 or name_bytes > 160 or mode & ~0o777 or not size or size > 0x7fffffff or
                not packed or packed > 0x7fffffff or len(blob) - offset < padded_name + padded_data):
            raise SystemExit('GPU addon has an invalid entry length or mode')
        raw_name = blob[offset:offset + name_bytes]
        if (raw_name[-1:] != b'\0' or b'\0' in raw_name[:-1] or raw_name[0] == ord('/') or
                b'..' in raw_name[:-1]):
            raise SystemExit('GPU addon has an invalid relative path')
        name = raw_name[:-1].decode('utf-8', errors='strict')
        names.append(name)
        offset += padded_name
        compressed = blob[offset:offset + packed]
        inflater = zlib.decompressobj()
        data = inflater.decompress(compressed, size + 1)
        if len(data) != size or inflater.unconsumed_tail or not inflater.eof or inflater.unused_data:
            raise SystemExit(f'GPU addon zlib stream is invalid: {name}')
        if inflater.flush():
            raise SystemExit(f'GPU addon zlib stream has trailing output: {name}')
        expanded += size
        offset += padded_data
    if offset != len(blob):
        raise SystemExit('GPU addon has trailing bytes')
    return {'files': count, 'unpacked_bytes': expanded, 'paths': names, 'encoded_bytes': len(blob)}


def read_volume_uuid(device):
    info = plistlib.loads(subprocess.check_output(['diskutil', 'info', '-plist', str(device)]))
    uuid = info.get('VolumeUUID')
    if not isinstance(uuid, str) or not UUID.fullmatch(uuid):
        raise SystemExit(f'APFS Volume UUID missing from diskutil info for {device}')
    return uuid.upper()


def mounted_volume_uuid(raw, mountpoint):
    mountpoint.mkdir()
    attached = plistlib.loads(subprocess.check_output(
        ['hdiutil', 'attach', '-imagekey', 'diskimage-class=CRawDiskImage', '-readonly', '-nobrowse', '-owners', 'off',
         '-mountpoint', str(mountpoint), '-plist', str(raw)]))
    devices = [entry['dev-entry'] for entry in attached.get('system-entities', []) if entry.get('dev-entry')]
    entities = [entry for entry in attached.get('system-entities', [])
                if entry.get('mount-point') == str(mountpoint) and entry.get('dev-entry')]
    if len(entities) != 1:
        for device in reversed(devices):
            subprocess.run(['hdiutil', 'detach', device], capture_output=True)
        raise SystemExit(f'Expected one APFS volume mounted from {raw}, got {len(entities)}')
    device = entities[0]['dev-entry']
    try:
        return read_volume_uuid(device)
    finally:
        subprocess.run(['hdiutil', 'detach', device], check=True, capture_output=True)


def packed_volume_uuid(packed_path, packed_ramdisk):
    logical, extents = packed_ramdisk.regions(packed_path.read_bytes())
    with tempfile.TemporaryDirectory(prefix='verify-data-volume-') as scratch:
        raw = Path(scratch) / 'seed.raw'
        with raw.open('wb') as stream:
            stream.truncate(logical)
            for offset, data in extents:
                stream.seek(offset)
                stream.write(data)
        return mounted_volume_uuid(raw, Path(scratch) / 'mount')


def validate_board(device, root_partition_name, size_mib, reserve_mib, source_bytes, addon_bytes):
    board = tomllib.loads((device / 'board.toml').read_text())
    userdata = board.get('userdata', {})
    actual = (userdata.get('first_lba'), userdata.get('last_lba'), userdata.get('lba_bytes'))
    if root_partition_name != 'ios_root' or actual != EXPECTED_IOS_ROOT:
        raise SystemExit(f'refusing non-ishtar ios_root geometry: name={root_partition_name!r}, geometry={actual!r}')
    if size_mib != 256 or reserve_mib != 1024:
        raise SystemExit('ordinary ishtar runtime is pinned to a 256 MiB Data container and 1024 MiB UFS reserve')
    if 'sheng-log-reserve=' in ' '.join(board.get('payload', {}).get('kernel_args', [])):
        raise SystemExit('unexpected per-boot sheng-log-reserve override; re-evaluate the fixed store reserve')
    partition_blocks = userdata['last_lba'] - userdata['first_lba'] + 1
    partition_bytes = partition_blocks * userdata['lba_bytes']
    container_bytes = size_mib * MIB
    pages = container_bytes // BLOCK
    bitmap_blocks = (pages + 8 * BLOCK - 1) // (8 * BLOCK)
    store_blocks = 1 + bitmap_blocks + pages
    root_blocks = (EXPECTED_ROOT_IMAGE_BYTES + BLOCK - 1) // BLOCK
    reserve_blocks = reserve_mib * MIB // BLOCK
    required_blocks = root_blocks + GUARD_BLOCKS + store_blocks + reserve_blocks
    if required_blocks > partition_blocks:
        raise SystemExit(f'Data store would overlap the root image or reserve: need {required_blocks} blocks, have {partition_blocks}')
    if (not 0 <= source_bytes < container_bytes or
            source_bytes + addon_bytes + RUNTIME_DATA_HEADROOM >= container_bytes):
        raise SystemExit('256 MiB Data container lacks room for the seed, expanded addon and runtime headroom')
    if container_bytes > 2 * GIB:
        raise SystemExit('identity-mismatch fallback exceeds RamBlock volatile-sparse capacity')
    return {'root_partition_name': root_partition_name, 'partition_bytes': partition_bytes,
            'partition_blocks': partition_blocks, 'root_image_bytes': EXPECTED_ROOT_IMAGE_BYTES,
            'root_guard_blocks': GUARD_BLOCKS, 'reserve_mib': reserve_mib,
            'store_window_blocks': store_blocks, 'store_window_bytes': store_blocks * BLOCK,
            'required_partition_bytes': required_blocks * BLOCK,
            'container_target_bytes': container_bytes, 'container_target_mib': size_mib,
            'addon_unpacked_bytes': addon_bytes, 'seed_source_regular_bytes': source_bytes,
            'runtime_data_headroom_bytes': RUNTIME_DATA_HEADROOM}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--device', type=Path, required=True)
    ap.add_argument('--unixnu', type=Path, required=True, help='UniXNU checkout (cwd of build-data-seed.py)')
    ap.add_argument('--config', type=Path, required=True, help='generated .config to patch')
    ap.add_argument('--out', type=Path, required=True, help='output directory for the seed')
    ap.add_argument('--mib', type=int, required=True, help='APFS Data container size; ordinary ishtar build uses 256 MiB')
    ap.add_argument('--root-partition-name', required=True, help='selected UFS root GPT name; must be ios_root')
    a = ap.parse_args()

    device = a.device.resolve()
    tree = a.unixnu.resolve()
    config = a.config.resolve()
    out = a.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    (tree / 'build').mkdir(parents=True, exist_ok=True)
    build_script = device / 'scripts/build-data-seed.py'
    grow_script = tree / 'scripts/seed-data-grow.py'
    addon_path = tree / 'out/gpuaddon.bin'
    if not build_script.is_file() or not grow_script.is_file():
        raise SystemExit(f'Data seed or pinned growth script missing: {build_script} / {grow_script}')
    if not config.is_file() or not addon_path.is_file():
        raise SystemExit(f'generated config or GPU addon missing: {config} / {addon_path}')
    packed = out / 'owner-data-32.dbr'
    grown = out / f'owner-data-{a.mib}m.dbr'
    for path in (packed, grown, out / 'seed.json', out / f'owner-data-{a.mib}m.json'):
        path.unlink(missing_ok=True)
    (out / 'owner-data-32.cdr').unlink(missing_ok=True)
    env = dict(os.environ)
    subprocess.run([sys.executable, str(build_script), '--out', str(out)], cwd=tree, env=env, check=True)
    if not packed.is_file() or not (out / 'seed.json').is_file():
        raise SystemExit('build-data-seed.py did not produce owner-data-32.dbr and seed.json')
    report = json.loads((out / 'seed.json').read_text())
    uuid = report.get('volume_uuid')
    if not isinstance(uuid, str) or not UUID.fullmatch(uuid):
        raise SystemExit(f'seed.json has an invalid volume_uuid: {uuid!r}')

    sys.path.insert(0, str(tree / 'drivers/DarwinBoot/Test'))
    import packed_ramdisk
    base_meta, base_header = packed_ramdisk.inspect(packed)
    if (not base_meta['packed'] or base_meta['bytes'] != 32 * MIB or
            base_meta['encoded_sha256'] != report.get('packed_sha256') or base_header[32:36] != b'NXSB'):
        raise SystemExit('base seed report, packed image or APFS container header does not match')
    source_volume_uuid = packed_volume_uuid(packed, packed_ramdisk)
    if source_volume_uuid != uuid.upper():
        raise SystemExit('build-data-seed.py Volume UUID does not match the APFS volume on its packed seed')

    addon = inspect_addon(addon_path)
    geometry = validate_board(device, a.root_partition_name, a.mib, 1024,
                              int(report.get('source_regular_bytes', -1)), addon['unpacked_bytes'])
    grow = subprocess.run([sys.executable, str(grow_script), '--mib', str(a.mib), '--reserve-mib', '1024',
                           str(packed), str(grown)], cwd=tree, env=env, capture_output=True, text=True)
    if grow.returncode:
        raise SystemExit(f'seed-data-grow.py failed ({grow.returncode})\n{grow.stdout}\n{grow.stderr}')
    try:
        grown_report = json.loads(grow.stdout)
    except json.JSONDecodeError as error:
        raise SystemExit(f'seed-data-grow.py returned no JSON report: {error}\n{grow.stdout}')
    grown_meta, grown_header = packed_ramdisk.inspect(grown)
    block_size = int.from_bytes(grown_header[36:40], 'little')
    block_count = int.from_bytes(grown_header[40:48], 'little')
    container_bytes = block_size * block_count
    if (not grown_meta['packed'] or grown_meta['bytes'] != a.mib * MIB or
            grown_report.get('mib') != a.mib or grown_report.get('bytes') != a.mib * MIB or
            grown_report.get('container_bytes') != container_bytes or block_size != BLOCK or
            grown_header[32:36] != b'NXSB' or not a.mib * MIB - 64 * MIB <= container_bytes <= a.mib * MIB):
        raise SystemExit(f'grown seed does not contain the requested {a.mib} MiB APFS container')
    if grown_meta['sha256'] == base_meta['sha256']:
        raise SystemExit('grown Data seed identity did not change with the container size')
    grown_uuid = packed_volume_uuid(grown, packed_ramdisk)
    if grown_uuid != source_volume_uuid:
        raise SystemExit(f'APFS volume UUID changed during growth: {source_volume_uuid} -> {grown_uuid}')
    if not geometry['container_target_bytes'] - 64 * MIB <= container_bytes <= geometry['container_target_bytes']:
        raise SystemExit('validated Data capacity differs from the grown APFS container')

    text = config.read_text()
    if len(LINE.findall(text)) != 1:
        raise SystemExit(f'expected exactly one CONFIG_XNU_OWNER_DATA_VOLUME_UUID in {config}')
    config.write_text(LINE.sub(f'CONFIG_XNU_OWNER_DATA_VOLUME_UUID="{uuid}"', text, count=1))
    report.update({'base_packed': packed.name, 'base_packed_sha256': base_meta['encoded_sha256'],
                   'base_seed_identity_sha256': base_meta['sha256'],
                   'base_container_bytes': base_meta['bytes'], 'packed': grown.name,
                   'packed_sha256': grown_meta['encoded_sha256'], 'seed_identity_sha256': grown_meta['sha256'],
                   'bytes': grown_meta['bytes'], 'container_bytes': container_bytes,
                   'container_block_size': block_size, 'container_block_count': block_count, 'mib': a.mib,
                   'volume_uuid_before_growth': source_volume_uuid, 'volume_uuid_after_growth': grown_uuid,
                   'volume_uuid_preserved_by_growth': grown_uuid == source_volume_uuid,
                   'old_overlay_policy': 'without reset, the new window returns Kept and leaves the prior 32 MiB store untouched; this seed uses volatile Data',
                   'addon': addon, **geometry})
    (out / 'seed.json').write_text(json.dumps(report, indent=2) + '\n')
    (out / f'owner-data-{a.mib}m.json').write_text(json.dumps(grown_report, indent=2) + '\n')
    print(f'DATA_SEED={grown}')
    print(f'DATA_UUID={uuid}')
    print(json.dumps(report, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
