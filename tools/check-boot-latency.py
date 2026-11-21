#!/usr/bin/env python3
"""Verify the latency hooks and native data geometry in the emitted kernel fileset."""
import argparse
import bisect
import hashlib
import json
import mmap
from pathlib import Path
import struct
import sys


class Mapped(mmap.mmap):
    def index(self, value, start=0, end=None):
        offset = self.find(value, start, len(self) if end is None else end)
        if offset < 0:
            raise ValueError('Missing terminated string')
        return offset


HOOKS = tuple('_ishtar_boot_latency_' + suffix for suffix in ('init', 'start', 'mark', 'exec'))
LABELS = ('clock-ready irqs-enabled bsd-enter storage-enter family-ready policy-ready apfs-loaded '
          'classes-ready provider-ready ufs-started data-disk-started storage-returned root-mount-enter '
          'root-mounted root-auth-return init-enter systemos-enter systemos-return data-prep-enter '
          'data-mounted addon-install-in addon-install-out addon-prep-out apps-prep-in apps-prep-out '
          'data-prep-out launchd-sig backboardd-sig SpringBoard-sig frame-observed blank-observed').split()
COUNTERS = ('native_ufs_progress_text native_ufs_block_reads native_ufs_block_failures native_ufs_read_ticks '
            'native_ufs_verify_ticks native_ufs_store_rd_ticks native_ufs_store_wr_ticks native_ufs_store_sync_ticks '
            'native_ufs_store_rd_ops native_ufs_store_wr_ops native_ufs_store_sync_ops native_ufs_irq_mode '
            'native_ufs_root_step native_data_persist_state native_data_persist_header native_gpu_addon_files '
            'native_gpu_addon_written native_gpu_addon_same native_gpu_addon_error armcpu_smp_requested '
            'armcpu_smp_running nprocs').split()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def branches(data, start):
    for offset, (word,) in enumerate(struct.iter_unpack('<I', data)):
        if word & 0x7c000000 == 0x14000000:  # AArch64 B and BL
            displacement = word & 0x03ffffff
            if displacement & 0x02000000:
                displacement -= 0x04000000
            site = start + 4 * offset
            yield site, site + 4 * displacement


def segment(image, name):
    matches = [entry for entry in image.segments if entry['name'] == name]
    require(len(matches) == 1, f'Expected one {name} segment')
    entry = matches[0]
    return entry['va'], entry['va'] + entry['size']


def check(data, Image):
    root = Image(data)
    image = Image(data, root.entries['com.apple.kernel'][1])
    symbols = {name: address for address, names in image.symbols().items() for name in names}
    starts = sorted(set(image.function_starts()))
    text = [entry for entry in image.sections if entry['segment'] == '__TEXT_EXEC' and entry['name'] == '__text']
    require(len(text) == 1, 'Expected one native executable text section')
    text_end = text[0]['va'] + text[0]['size']

    def function(name):
        require(name in symbols, f'Missing native symbol {name}')
        start = symbols[name]
        require(text[0]['va'] <= start < text_end and start % 4 == 0, f'Invalid text address for {name}')
        index = bisect.bisect_right(starts, start)
        end = min(text_end, starts[index]) if index < len(starts) else text_end
        require(start < end <= start + 256 * 1024, f'Invalid function bounds for {name}')
        return start, image.read(start, end - start)

    for name in HOOKS:
        function(name)
    call_sites = {}

    def audit(callers, callee, minimum):
        sites = []
        for caller in callers:
            start, code = function(caller)
            sites.extend({'caller': caller, 'callee': callee, 'va': hex(site)}
                         for site, target in branches(code, start) if target == symbols[callee])
        require(len({site['va'] for site in sites}) >= minimum,
                f'Expected {minimum} branches to {callee} in {", ".join(callers)}')
        call_sites.setdefault(callee, []).extend(sites)

    bootstrap = ['_kernel_bootstrap_thread']
    audit(bootstrap, HOOKS[0], 1)
    audit(bootstrap, HOOKS[1], 1)
    audit(['_bsd_init'], HOOKS[2], 4)
    audit(['_native_source_storage_start'], HOOKS[2], 9)
    # Five init/mount marks live in load_init_program. Four Data/app marks may
    # remain in native_owner_data_prepare; two install marks belong to the
    # independently compiled native_gpu_addon_prepare. Account for inlining.
    init_callers = ['_load_init_program'] + [name for name in
        ('_native_owner_data_prepare', '_native_gpu_addon_prepare') if name in symbols]
    audit(['_load_init_program'], HOOKS[2], 5)
    audit(init_callers, HOOKS[2], 11)
    audit(['_native_legacy_frame_observed'], HOOKS[2], 1)
    exec_candidates = [name for name, address in symbols.items()
                       if text[0]['va'] <= address < text_end and
                       not name.startswith('_ishtar_') and
                       any(part in name for part in ('exec', 'spawn', 'signature'))]
    exec_callers = []
    for caller in exec_candidates:
        start, code = function(caller)
        if any(target == symbols[HOOKS[3]] for _, target in branches(code, start)):
            exec_callers.append(caller)
    audit(exec_callers, HOOKS[3], 1)

    for name in COUNTERS:
        require('_' + name in symbols, f'Missing snapshot input {name}')
    labels = [entry for entry in image.sections if entry['segment'] == '__TEXT' and entry['name'] == '__boot_lat']
    require(len(labels) == 1, 'Expected one read-only label table')
    expected = b''.join(label.encode().ljust(20, b'\0') for label in LABELS)
    require(labels[0]['size'] == len(expected) and image.read(labels[0]['va'], len(expected)) == expected,
            'Emitted label table differs')
    for field in (b'ISHTAR LATENCY (intentional stop)', b'overlay state/header=', b'read/hash-ms=',
                  b'smp requested/extra='):
        require(data.find(field) >= 0, f'Missing snapshot field {field!r}')

    # __LASTDATA_CONST is a segment and may have nonzero size on disk. The existing
    # prelink layout policy treats it separately when placing the native segments.
    libm = Image(data, root.entries['com.apple.kec.Libm'][1])
    data_start, data_end = segment(image, '__DATA')
    libm_start, libm_end = segment(libm, '__DATA')
    require(data_start < data_end <= libm_start < libm_end, 'Native __DATA overlaps retained Libm __DATA')
    marker_start, marker_end = segment(image, '__LASTDATA_CONST')
    return {'result': 'PASS', 'kernel_sha256': hashlib.sha256(data).hexdigest(),
            'symbols': {name: hex(symbols[name]) for name in HOOKS}, 'call_sites': call_sites,
            'exec_callers': exec_callers, 'label_section_bytes': len(expected),
            'native_data': [hex(data_start), hex(data_end)], 'retained_libm_data': [hex(libm_start), hex(libm_end)],
            'lastdata_const': [hex(marker_start), hex(marker_end)],
            'snapshot_seconds': 420, 'intentional_stop': True, 'hardware_verified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('module-dir', 'kernel', 'report'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.module_dir))
    from kc_image import Image

    try:
        with args.kernel.open('rb') as stream, Mapped(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
            result = check(data, Image)
    except (KeyError, ValueError, struct.error, StopIteration) as error:
        result = {'result': 'FAIL', 'reason': str(error), 'hardware_verified': False}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
    return 0 if result['result'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
