#!/usr/bin/env python3
"""Reuse the final Setup/no-auto-dim 256 MiB seed from gpu-runtime-44502687562."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import urllib.request
import uuid

PAYLOAD_ASSET = 767376236
PAYLOAD_BYTES = 184549376
PAYLOAD_SHA256 = '7b484a4aaad3d7377b7a05c5e0368b3c6d30f61f18666c49024fd4dd5e5fc136'
SEED_BYTES = 1347712
SEED_ENCODED_SHA256 = '23c7a268214bfe3ca66da988883c2ce9f6618eea42dd31c5a6d9d6b88c5a4989'
SEED_LOGICAL_SHA256 = '6555c58a038ece485aef1f84470325a29c0f0e81e4b15e1f4ec7b868c122f5c3'
VOLUME_UUID = '82B443ED-0E24-40D0-808D-57444E4E7119'
SETUP_ASSET = 767376338
SETUP_SHA256 = '143ac4dbe6141f523a9a1e4a192dce696cb2833aef16eb98c8ad50ce3f1fa2df'


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def download(asset, path, size, digest):
    if path.exists():
        assert path.stat().st_size == size and sha(path) == digest, 'cached input differs'
        return
    request = urllib.request.Request(
        'https://api.github.com/repos/ConCosew/ishtar-device/releases/assets/' + str(asset),
        headers={'Authorization': 'Bearer ' + os.environ['GH_PAT'], 'Accept': 'application/octet-stream'})
    partial = path.with_suffix('.partial')
    actual = hashlib.sha256(); total = 0
    with urllib.request.urlopen(request, timeout=35) as response, partial.open('xb') as stream:
        for _ in range(size // 1048576 + 2):
            chunk = response.read(1048576)
            if not chunk:
                break
            total += len(chunk)
            assert total <= size, 'released input exceeds bound'
            actual.update(chunk); stream.write(chunk)
    assert total == size and actual.hexdigest() == digest, 'released input hash mismatch'
    partial.rename(path)


def configure(config, packed, report, seed, output, setup_path):
    assert seed.stat().st_size == SEED_BYTES and sha(seed) == SEED_ENCODED_SHA256, 'final packed seed differs'
    assert setup_path.stat().st_size == 1021 and sha(setup_path) == SETUP_SHA256, 'source Setup report differs'
    setup = json.loads(setup_path.read_text())
    assert setup['result'] == 'PASS' and setup['build'] == '24A446'
    assert setup['skip_setup'] is True and setup['no_auto_dim'] is True
    assert setup['data_seed_volume_uuid'] == VOLUME_UUID
    assert setup['data_seed_identity_sha256'] == SEED_LOGICAL_SHA256
    assert setup['data_ramdisk_sha256'] == SEED_ENCODED_SHA256
    metadata, header = packed.inspect(seed)
    assert metadata['packed'] and metadata['bytes'] == 256 * 1024**2
    assert metadata['sha256'] == SEED_LOGICAL_SHA256 and header[32:36] == b'NXSB'
    container_bytes = int.from_bytes(header[36:40], 'little') * int.from_bytes(header[40:48], 'little')
    assert container_bytes == 256 * 1024**2 == setup['data_container_bytes'] == setup['final_seed_container_bytes']
    blob = seed.read_bytes()  # bounded to the established 1,347,712 bytes
    _, extents = packed.regions(blob)
    ids = set(); nxsb_versions = []
    for _, region in extents:
        for at in range(0, len(region), 4096):
            page = bytes(region[at:at + 4096])
            if page[32:36] == b'APSB' and struct.unpack_from('<I', page, 24)[0] & 0xffff == 13:
                ids.add(str(uuid.UUID(bytes=page[240:256])).upper())
            if page[32:36] == b'NXSB':
                nxsb_versions.append((int.from_bytes(page[16:24], 'little'),
                                      int.from_bytes(page[36:40], 'little') * int.from_bytes(page[40:48], 'little')))
    assert ids == {VOLUME_UUID}, 'APFS volume identity differs'
    # A grown APFS image retains older 32 MiB checkpoints. Validate the current
    # transaction rather than requiring historical superblocks to be rewritten.
    current_xid = int.from_bytes(header[16:24], 'little')
    assert nxsb_versions and max(xid for xid, _ in nxsb_versions) == current_xid
    assert {size for xid, size in nxsb_versions if xid == current_xid} == {256 * 1024**2}, 'current APFS geometry differs'
    text = config.read_text()
    pattern = r'^CONFIG_XNU_OWNER_DATA_VOLUME_UUID="[^"]*"$'
    assert len(re.findall(pattern, text, re.M)) == 1, 'expected exactly one Data UUID config'
    config.write_text(re.sub(pattern, 'CONFIG_XNU_OWNER_DATA_VOLUME_UUID="' + VOLUME_UUID + '"', text, flags=re.M))
    evidence = {
        'result': 'PASS', 'source_release': 'gpu-runtime-44502687562', 'source_run_id': 44502687562,
        'payload_asset_id': PAYLOAD_ASSET, 'payload_sha256': PAYLOAD_SHA256,
        'source_setup_sha256': SETUP_SHA256,
        'data_ramdisk_sha256': SEED_ENCODED_SHA256, 'seed_identity_sha256': SEED_LOGICAL_SHA256,
        'seed_logical_bytes': metadata['bytes'], 'seed_encoded_bytes': seed.stat().st_size,
        'container_bytes': container_bytes, 'volume_uuid': VOLUME_UUID,
        'build': '24A446', 'skip_setup': True, 'no_auto_dim': True,
        'setup_transform_reapplied': False, 'seed_reused_byte_for_byte': True,
        'root_partition_name': 'ios_root', 'ishtar_latency_seconds': 420, 'hardware_verified': False,
        'persistence': 'Same final seed identity as ordinary 44502687562; actual overlay mode is unverified. No reset or identity bypass.'}
    report.write_text(json.dumps(evidence, indent=2) + '\n')
    output.write_text('DATA_SEED=' + str(seed.resolve()) + '\n')
    return evidence


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ('unixnu', 'config', 'out', 'report', 'path-output'):
        ap.add_argument('--' + name, type=Path, required=True)
    args = ap.parse_args()
    out = args.out.resolve(); out.mkdir(parents=True, exist_ok=True)
    payload = out / 'baseline-payload.img'
    download(PAYLOAD_ASSET, payload, PAYLOAD_BYTES, PAYLOAD_SHA256)
    setup = out / 'baseline-data-setup.json'
    download(SETUP_ASSET, setup, 1021, SETUP_SHA256)
    seed = out / 'baseline-data-44502687562.dbr'
    if not seed.exists():
        subprocess.run(['mcopy', '-i', str(payload), '::/EFI/UniXNU/Payloads/scratch-data.img', str(seed)], check=True)
    spec = importlib.util.spec_from_file_location('aligned_packed', args.unixnu.resolve() / 'drivers/DarwinBoot/Test/packed_ramdisk.py')
    packed = importlib.util.module_from_spec(spec); spec.loader.exec_module(packed)
    evidence = configure(args.config, packed, args.report, seed, args.path_output, setup)
    print(json.dumps(evidence, indent=2))


if __name__ == '__main__':
    main()
