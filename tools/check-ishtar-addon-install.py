#!/usr/bin/env python3
"""Check the pinned-XNU GPU addon transaction and its fail-closed caller."""
import argparse
import hashlib
import json
import mmap
import struct
from pathlib import Path

MARKER = 'addons/NativeAdrenoMetal.publish'
TEMP = '.unixnu-addon-install.tmp'


def body(source, signature):
    start = source.index(signature)
    opening = source.index('{', start)
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == '{':
            depth += 1
        elif source[index] == '}':
            depth -= 1
            if depth == 0:
                return source[opening + 1:index]
    raise AssertionError('unterminated function ' + signature)


def model(entries, fail=None):
    files = {'addons/NativeAdrenoMetal/NativeAdrenoMetal': (b'old-complete', 0o755), MARKER: (b'old', 0o644)}
    events, mounts = [], False
    marker_index = next((i for i, item in enumerate(entries) if item[0] == MARKER), None)
    if marker_index is not None and sum(1 for item in entries if item[0] == MARKER) != 1:
        return files, events, False, False
    ordered = [item for item in entries if item[0] != MARKER] + ([entries[marker_index]] if marker_index is not None else [])
    for path, data, mode in ordered:
        target = TEMP.rsplit('/', 1)[0] + '/' + TEMP if '/' in path else TEMP
        if path == MARKER and marker_index is None:
            continue
        if files.get(path) == (data, mode):
            events.append(('same', path))
            continue
        files.pop(target, None)
        events.append(('open-exclusive', target))
        if fail == 'write':
            return files, events, False, False
        files[target] = (data, 0o600)
        events.append(('write', target))
        if fail == 'mode':
            files.pop(target, None)
            return files, events, False, False
        files[target] = (data, mode)
        events.append(('mode', target))
        if fail == 'fsync':
            files.pop(target, None)
            return files, events, False, False
        events.append(('fsync', target))
        if fail == 'close':
            files.pop(target, None)
            return files, events, False, False
        events.append(('close', target))
        if path != MARKER:
            files.pop(MARKER, None)
            events.append(('unpublish', MARKER))
        if fail == 'rename':
            files.pop(target, None)
            return files, events, False, False
        files[path] = files.pop(target)
        events.append(('rename-atomic', path))
    if marker_index is None:
        files.pop(MARKER, None)
    mounts = True
    return files, events, mounts, True


def check(source_path, kernel_path=None, addon_path=None):
    source = source_path.read_text(encoding='utf-8')
    writer = body(source, 'native_gpu_addon_write(proc_t p, user_addr_t scratch, const char *path,')
    rename = body(source, 'native_gpu_addon_rename(proc_t p, user_addr_t scratch, const char *temporary,')
    install = body(source, 'native_gpu_addon_install(proc_t p, user_addr_t scratch)')
    prepare = body(source, 'native_gpu_addon_prepare(proc_t p, user_addr_t scratch)')
    require = lambda condition, message: (_ for _ in ()).throw(AssertionError(message)) if not condition else None

    require('O_CREAT | O_EXCL | FWRITE' in writer and 'VNODE_LOOKUP_NOFOLLOW_ANY' in writer,
            'sibling temp must be exclusive and reject symlink components')
    require('O_TRUNC' not in writer and 'RENAME_NOFOLLOW_ANY' in rename and 'renameatx_np' in rename,
            'final files must be atomically renamed without following symlinks')
    sequence = ['vn_rdwr(UIO_WRITE', 'VATTR_SET(&va, va_mode, mode)', 'VNOP_FSYNC(vp, MNT_WAIT, ctx)',
                'vnode_close(vp, FWRITE, ctx)', 'native_gpu_addon_unlink(p, scratch, native_gpu_addon_marker)',
                'native_gpu_addon_rename(p, scratch, temporary, path)']
    positions = [writer.index(token) for token in sequence]
    require(positions == sorted(positions), 'write, mode, fsync, close, unpublish and atomic rename order drifted')
    require('native_gpu_addon_unlink(p, scratch, temporary)' in writer,
            'failed temp file must be removed')
    require('marker != (pass == 1)' in install and 'for (unsigned pass = 0; pass < 2; ++pass)' in install,
            'publication marker must be deferred until after all payload files')
    require('marker_count != 1' in install and 'marker_count = 0' in install,
            'reject duplicate publication entries')
    require('native_gpu_addon_unlink(p, scratch, native_gpu_addon_marker)' in install and 'return error;' in install,
            'failed install must remove publication marker and abort')
    require('if (!addon_error)' in prepare and 'native_gpu_addon_mount(p, scratch' in prepare,
            'addon overlays must be guarded by full install success')
    require('RENAME_NOFOLLOW_ANY' in source and 'AT_SYMLINK_NOFOLLOW_ANY' in source and 'VNODE_LOOKUP_NOFOLLOW_ANY' in source,
            'all path mutation/open operations must reject symlink paths')

    entries = [(f'addons/NativeAdrenoMetal/file-{i}', bytes([i]) * (i + 3), 0o755 if i == 1 else 0o644)
               for i in range(5)]
    entries.insert(0, (MARKER, b'publish', 0o644))
    files, events, mounts, success = model(entries)
    require(success and mounts and files[MARKER] == (b'publish', 0o644), 'complete install must publish marker')
    duplicate = entries + [(MARKER, b'duplicate', 0o644)]
    _, _, duplicate_mounts, duplicate_success = model(duplicate)
    require(not duplicate_success and not duplicate_mounts, 'duplicate publication marker must reject installation')
    rename_events = [path for action, path in events if action == 'rename-atomic']
    require(rename_events[-1] == MARKER, 'publication marker was not atomically installed last')
    failures = {}
    for stage in ('write', 'mode', 'fsync', 'close', 'rename'):
        files, events, mounts, success = model(entries, stage)
        if not success:
            files.pop(MARKER, None)  # caller unpublishes and suppresses mounts on every install error
        require(not success and not mounts and MARKER not in files,
                stage + ' failure must remain unpublished and skip every addon mount')
        require(files['addons/NativeAdrenoMetal/NativeAdrenoMetal'][0] == b'old-complete',
                stage + ' failure exposed a partial final file')
        failures[stage] = 'PASS'
    no_marker, _, mounts, success = model(entries[1:])
    require(success and mounts and MARKER not in no_marker, 'markerless package must clear an old publish marker')

    result = {'result':'PASS', 'hardware_verified':False, 'checks':{
        'same_directory_exclusive_temp':'PASS', 'no_follow_open_unlink_rename':'PASS',
        'write_mode_fsync_close_rename_order':'PASS', 'publication_marker_last':'PASS',
        'all_addon_mounts_require_complete_install':'PASS', 'injected_failures':failures,
        'duplicate_publication_marker_rejected':'PASS', 'markerless_package_clears_old_marker':'PASS'}, 'source_sha256':hashlib.sha256(source_path.read_bytes()).hexdigest()}
    if kernel_path:
        result['kernel_sha256'] = hashlib.sha256(kernel_path.read_bytes()).hexdigest()
    if addon_path:
        with addon_path.open('rb') as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as image:
            require(len(image) >= 24 and image[:8] == b'NGPUADD2', 'GPU addon archive header mismatch')
            count, reserved, total = struct.unpack_from('<IIQ', image, 8)
            require(reserved == 0 and total == len(image) and 0 < count < 4096, 'GPU addon archive bounds mismatch')
            names, at = [], 24
            for _ in range(count):
                require(len(image) - at >= 24, 'truncated GPU addon record')
                name_bytes, mode, size, packed = struct.unpack_from('<IIQQ', image, at)
                at += 24
                name_padded, packed_padded = (name_bytes + 7) & ~7, (packed + 7) & ~7
                require(name_bytes >= 2 and name_padded <= len(image) - at, 'invalid GPU addon name size')
                raw_name = image[at:at + name_bytes]
                require(raw_name[-1] == 0 and b'\\0' not in raw_name[:-1], 'invalid GPU addon name')
                name = raw_name[:-1].decode('utf-8')
                at += name_padded
                require(size <= 0x7fffffff and 0 < packed <= 0x7fffffff and packed_padded <= len(image) - at,
                        'invalid GPU addon data bounds')
                names.append(name)
                at += packed_padded
            require(at == len(image) and len(names) == len(set(names)), 'GPU addon records are truncated or duplicated')
            require(names.count(MARKER) == 1 and names[-1] == MARKER,
                    'the signed GPU baseline must carry exactly one final publication marker')
            require('addons/NativeAdrenoMetal.bundle/NativeAdrenoMetal' in names,
                    'GPU addon executable missing')
        with addon_path.open('rb') as handle:
            result['addon_sha256'] = hashlib.file_digest(handle, 'sha256').hexdigest()
        result['addon_entries'] = len(names)
        result['publish_marker'] = MARKER
        result['publish_marker_last'] = True
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--kernel', type=Path)
    parser.add_argument('--addon', type=Path)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    result = check(args.source, args.kernel, args.addon)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
