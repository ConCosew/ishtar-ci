#!/usr/bin/env python3
"""Install the exact ipsw extras build used by successful run 43711606407."""
import argparse
import hashlib
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.request

VERSION = '3.1.748'
NAME = f'ipsw_{VERSION}_macOS_arm64_extras.tar.gz'
SHA256 = '96940a9a15dc19f66e40b58f84a5cf4ab8dc9800083d0b7d255211c18c6a7720'
URLS = (
    f'https://github.com/blacktop/ipsw/releases/download/v{VERSION}/{NAME}',
    'https://api.github.com/repos/blacktop/ipsw/releases/assets/750772304',
)
MAX_ARCHIVE = 40 * 1024 * 1024


def download(archive):
    for url in URLS:
        for attempt in range(1, 4):
            headers = {'User-Agent': 'ishtar-ci', 'Accept': 'application/octet-stream'}
            if url.startswith('https://api.github.com/') and os.environ.get('GH_PAT'):
                headers['Authorization'] = 'Bearer ' + os.environ['GH_PAT']
            request = urllib.request.Request(url, headers=headers)
            try:
                digest = hashlib.sha256()
                size = 0
                with urllib.request.urlopen(request, timeout=45) as response, archive.open('wb') as out:
                    while chunk := response.read(1024 * 1024):
                        size += len(chunk)
                        if size > MAX_ARCHIVE:
                            raise RuntimeError('ipsw archive exceeds size bound')
                        digest.update(chunk)
                        out.write(chunk)
                if digest.hexdigest() != SHA256:
                    raise RuntimeError('ipsw archive SHA-256 mismatch')
                print(f'ipsw {VERSION}: archive verified ({size} bytes)', flush=True)
                return
            except (OSError, urllib.error.URLError) as exc:
                # Do not print request headers, including the optional API credential.
                print(f'ipsw download attempt {attempt}/3 failed: {type(exc).__name__}', flush=True)
    raise RuntimeError('all bounded ipsw download attempts failed')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--verify-only', action='store_true')
    args = parser.parse_args()
    if not args.verify_only and (platform.system() != 'Darwin' or platform.machine() != 'arm64'):
        raise SystemExit('pinned ipsw requires macOS arm64')
    with tempfile.TemporaryDirectory(prefix='ipsw-pinned-') as temp:
        archive = Path(temp) / NAME
        download(archive)
        with tarfile.open(archive, 'r:gz') as tar:
            members = [m for m in tar.getmembers() if m.isfile() and Path(m.name).name == 'ipsw']
            if len(members) != 1 or not 0 < members[0].size <= 100 * 1024 * 1024:
                raise RuntimeError('ipsw archive must contain exactly one bounded CLI executable')
            with tar.extractfile(members[0]) as source:
                if source.read(4) != b'\xcf\xfa\xed\xfe':
                    raise RuntimeError('ipsw CLI is not a little-endian 64-bit Mach-O')
            if args.verify_only:
                print('PASS: pinned archive SHA-256 and Mach-O executable verified')
                return
            dest = Path(os.environ['RUNNER_TEMP']) / 'ishtar-tools' / 'bin'
            dest.mkdir(parents=True, exist_ok=True)
            binary = dest / 'ipsw'
            with tar.extractfile(members[0]) as source, binary.open('wb') as out:
                shutil.copyfileobj(source, out, length=1024 * 1024)
            binary.chmod(0o755)
        result = subprocess.run([str(binary), 'version'], check=True, capture_output=True, text=True)
        output = result.stdout + result.stderr
        if VERSION not in output:
            raise RuntimeError('installed ipsw version does not match pin')
        print(output.strip())
        with Path(os.environ['GITHUB_PATH']).open('a') as path_file:
            path_file.write(str(dest) + '\n')
        print('PASS: ipsw executable installed and version checked before IPSW fetch')


if __name__ == '__main__':
    main()
