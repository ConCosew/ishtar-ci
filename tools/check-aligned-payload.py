#!/usr/bin/env python3
"""Audit actual final FAT contents against the released ordinary 256 MiB inputs."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import tomllib

SEED = '23c7a268214bfe3ca66da988883c2ce9f6618eea42dd31c5a6d9d6b88c5a4989'
GPU = '21d601e84157d8cb935430ac9c9a998a1ec58179ea392142135e39cc21d3081a'
TRUST = '7aa6455edeabb74f753301a721af51eb2800e026227414bd31e70cffbabe0cef'
SETUP = '143ac4dbe6141f523a9a1e4a192dce696cb2833aef16eb98c8ad50ce3f1fa2df'
BASE_ARGS = ['-v', 'serial=3', 'debug=0x14e', 'kt_fixed_zones=120', '-no_slto_panic', 'use_contiguous_hint=0', 'native-source-storage=1', 'native-ufs-root=1', 'sheng-data-persist=2', 'offline-mobile-graphics-load=1', 'offline-mobile-graphics-client=1', 'offline-iogpu-load=1', 'sheng-fb-gpu=1', 'offline-legacy-register=1', 'offline-legacy-gop=1', 'offline-legacy-unit-scale=3', 'offline-legacy-pm=1', 'offline-legacy-validate=1', 'offline-legacy-transfer=1', 'offline-legacy-cpu-present=1', 'offline-legacy-phase=4', 'offline-key-events=1', 'sheng-aks=1', 'sheng-gpu-addon=1']


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def audit_metadata(payload, base):
    assert payload['skip_setup'] is False, 'final source seed must not be transformed again'
    assert payload['data_ramdisk_sha256'] == SEED == base['data_ramdisk_sha256']
    assert payload['gpu_addon_sha256'] == GPU and payload['trust_cache_sha256'] == TRUST
    assert base['result'] == 'PASS' and base['source_run_id'] == 44502687562
    assert base['seed_logical_bytes'] == base['container_bytes'] == 256 * 1024**2
    assert base['volume_uuid'] == '82B443ED-0E24-40D0-808D-57444E4E7119'
    assert base['seed_identity_sha256'] == '6555c58a038ece485aef1f84470325a29c0f0e81e4b15e1f4ec7b868c122f5c3'
    assert base['skip_setup'] is True and base['no_auto_dim'] is True
    assert base['setup_transform_reapplied'] is False and base['seed_reused_byte_for_byte'] is True
    args = payload['kernel_args'].split()
    assert args == BASE_ARGS + ['ishtar-latency=420'], 'ordinary default args changed'
    assert len(args) == len({arg.split('=', 1)[0] for arg in args})
    return args


def audit_config(config, args):
    assert config['boot']['default'] == 'xnu'
    entries = config['entry']
    assert len(entries) == 3 and {e['id'] for e in entries} == {'xnu', 'reset', 'shutdown'}
    entry = next(e for e in entries if e['id'] == 'xnu')
    assert entry['type'] == 'xnu' and entry['path'] == 'Payloads/kernel.macho'
    assert entry['args'].split() == args and not entry.get('confirm_args')
    assert entry['initrd'] == 'Payloads/scratch-data.img'
    assert next(e for e in entries if e['id'] == 'reset') == {'id': 'reset', 'title': 'Restart', 'type': 'action', 'action': 'reset'}
    assert next(e for e in entries if e['id'] == 'shutdown') == {'id': 'shutdown', 'title': 'Power off', 'type': 'action', 'action': 'shutdown'}
    assert all(not e.get('confirm_args') for e in entries)
    assert not any(a.startswith('sheng-data-reset=') for a in args)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ('payload-dir', 'baseline-report', 'source-setup'):
        ap.add_argument('--' + name, type=Path, required=True)
    args = ap.parse_args()
    payload = json.loads((args.payload_dir/'payload.json').read_text())
    base = json.loads(args.baseline_report.read_text())
    kernel_args = audit_metadata(payload, base)
    assert args.source_setup.stat().st_size == 1021 and sha(args.source_setup) == SETUP
    image = args.payload_dir/'payload.img'
    assert image.stat().st_size == payload['payload_bytes'] and sha(image) == payload['payload_sha256']
    with tempfile.TemporaryDirectory() as name:
        temp = Path(name)
        for embedded, size, digest in [('scratch-data.img', 1347712, SEED), ('kernel.macho.gpuaddon', 13708408, GPU), ('kernel.macho.trustcache', 95828, TRUST)]:
            target = temp/embedded
            subprocess.run(['mcopy','-i',str(image),'::/EFI/UniXNU/Payloads/'+embedded,str(target)], check=True)
            assert target.stat().st_size == size and sha(target) == digest, 'final FAT input mismatch: ' + embedded
        config_path = temp/'unixnu.toml'
        subprocess.run(['mcopy','-i',str(image),'::/EFI/UniXNU/unixnu.toml',str(config_path)], check=True)
        assert config_path.stat().st_size <= 16384
        audit_config(tomllib.loads(config_path.read_text()), kernel_args)
    base['kernel_args'] = kernel_args
    base['payload_checks'] = 'PASS'
    base['final_fat_inputs_verified'] = True
    base['payload_sha256'] = payload['payload_sha256']
    base['source_payload_sha256'] = '7b484a4aaad3d7377b7a05c5e0368b3c6d30f61f18666c49024fd4dd5e5fc136'
    base['gpu_addon_sha256'] = GPU; base['trust_cache_sha256'] = TRUST
    args.baseline_report.write_text(json.dumps(base, indent=2) + '\n')
    # Publish the unchanged source policy report, whose bytes authenticate the reused seed's settings.
    (args.baseline_report.parent/'data-setup.json').write_bytes(args.source_setup.read_bytes())
    print('Aligned final FAT seed/addon/trust/default args verified; source Setup policy retained')


if __name__ == '__main__':
    main()
