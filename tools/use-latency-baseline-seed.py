#!/usr/bin/env python3
"""Reuse the exact Data seed embedded in the tested 44246601490 release.

This diagnostic does not rebuild/modify the seed or reset/relax overlay identity.
Reads a verified released FAT payload, extracts one small file with mtools, and
aligns the generated kernel UUID with that same seed. Nothing is sent to a device.
"""
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

PAYLOAD_ASSET = 762276082
PAYLOAD_BYTES = 184549376
PAYLOAD_SHA256 = '8aac4c692e8cc3476508df9a38a89f3e57e5585bd922c629afde6e29f54e7bd3'
SEED_BYTES = 1085520
SEED_ENCODED_SHA256 = '0d077255c7c4ae17192ce9844f1942c8d9c5770ef7c1a8828e2581d84a63cb51'
SEED_LOGICAL_SHA256 = '10a334dcf02e9f58e98d07d97d7acda78371c095850d68da0d59308dee40e678'
VOLUME_UUID = '745D9D27-FFC0-4B6F-B119-D94711F2DD9C'

def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def configure(config, packed, report, seed, output):
    assert seed.stat().st_size == SEED_BYTES and sha(seed) == SEED_ENCODED_SHA256, 'baseline packed seed differs'
    metadata, _ = packed.inspect(seed)
    assert metadata['bytes'] == 32 * 1024**2 and metadata['sha256'] == SEED_LOGICAL_SHA256
    blob = seed.read_bytes()  # strict 1,085,520-byte input bound established above
    _, extents = packed.regions(blob)
    ids = set()
    for _, region in extents:
        for at in range(0, len(region), 4096):
            page = bytes(region[at:at + 4096])
            if page[32:36] == b'APSB' and struct.unpack_from('<I', page, 24)[0] & 0xffff == 13:
                ids.add(str(uuid.UUID(bytes=page[240:256])).upper())
    assert ids == {VOLUME_UUID}, 'APFS volume UUID differs from verified baseline'
    text = config.read_text()
    pattern = r'^CONFIG_XNU_OWNER_DATA_VOLUME_UUID="[^"]*"$'
    assert len(re.findall(pattern, text, re.M)) == 1, 'expected one Data UUID config'
    config.write_text(re.sub(pattern, 'CONFIG_XNU_OWNER_DATA_VOLUME_UUID="' + VOLUME_UUID + '"', text, flags=re.M))
    evidence = {'result': 'PASS', 'source_release': 'gpu-runtime-44246601490',
                'payload_asset_id': PAYLOAD_ASSET, 'payload_sha256': PAYLOAD_SHA256,
                'data_ramdisk_sha256': SEED_ENCODED_SHA256, 'seed_identity_sha256': SEED_LOGICAL_SHA256,
                'seed_logical_bytes': metadata['bytes'], 'seed_encoded_bytes': seed.stat().st_size,
                'volume_uuid': VOLUME_UUID, 'skip_setup': False, 'no_auto_dim_transform': False,
                'ishtar_latency_seconds': 420, 'hardware_verified': False,
                'persistence': 'Exact baseline seed reused; actual overlay state must be read from snapshot, no reset or identity bypass'}
    report.write_text(json.dumps(evidence, indent=2) + '\n')
    output.write_text('DATA_SEED=' + str(seed.resolve()) + '\n')
    return evidence

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--unixnu', type=Path, required=True)
    ap.add_argument('--config', type=Path, required=True)
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--report', type=Path, required=True)
    ap.add_argument('--path-output', type=Path, required=True)
    args = ap.parse_args()
    out = args.out.resolve(); out.mkdir(parents=True, exist_ok=True)
    payload = out / 'baseline-payload.img'
    if not payload.exists():
        token = os.environ['GH_PAT']
        request = urllib.request.Request('https://api.github.com/repos/ConCosew/ishtar-device/releases/assets/' + str(PAYLOAD_ASSET),
            headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/octet-stream'})
        partial = payload.with_suffix('.partial')
        digest = hashlib.sha256(); total = 0
        with urllib.request.urlopen(request, timeout=35) as response, partial.open('xb') as stream:
            for _ in range(PAYLOAD_BYTES // (1024**2) + 2):
                chunk = response.read(1024**2)
                if not chunk: break
                total += len(chunk)
                assert total <= PAYLOAD_BYTES, 'payload exceeds bound'
                digest.update(chunk); stream.write(chunk)
        assert total == PAYLOAD_BYTES and digest.hexdigest() == PAYLOAD_SHA256, 'payload hash mismatch'
        partial.rename(payload)
    assert payload.stat().st_size == PAYLOAD_BYTES and sha(payload) == PAYLOAD_SHA256
    seed = out / 'baseline-data-44246601490.dbr'
    if not seed.exists():
        subprocess.run(['mcopy', '-i', str(payload), '::/EFI/UniXNU/Payloads/scratch-data.img', str(seed)], check=True)
    spec = importlib.util.spec_from_file_location('latency_packed', args.unixnu.resolve() / 'drivers/DarwinBoot/Test/packed_ramdisk.py')
    packed = importlib.util.module_from_spec(spec); spec.loader.exec_module(packed)
    evidence = configure(args.config, packed, args.report, seed, args.path_output)
    print(json.dumps(evidence, indent=2))

if __name__ == '__main__':
    main()
