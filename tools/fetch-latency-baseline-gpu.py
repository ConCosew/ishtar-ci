#!/usr/bin/env python3
"""Fetch the exact tested GPU addon/trust bytes; no rebuild changes for timing test."""
import hashlib
import os
from pathlib import Path
import urllib.request

ASSETS = [
    ('gpuaddon.bin', 762276078, 13708376, '1f58109d7bd75984da9a74635936f5f7db880f3e4c13dea58a486b01cb7084a7'),
    ('owner-trust.bundle', 762276075, 95828, 'a963d31f047723f775c64c7b59ccc7f8053fec98ad892f305f84182432e766a7'),
]
def main():
    Path('out').mkdir(exist_ok=True)
    for name, asset, size, digest in ASSETS:
        path = Path('out') / name
        request = urllib.request.Request('https://api.github.com/repos/ConCosew/ishtar-device/releases/assets/' + str(asset),
            headers={'Authorization': 'Bearer ' + os.environ['GH_PAT'], 'Accept': 'application/octet-stream'})
        seen = 0; actual = hashlib.sha256()
        with urllib.request.urlopen(request, timeout=35) as response, path.open('xb') as out:
            for _ in range(size // (1024**2) + 2):
                chunk = response.read(1024**2)
                if not chunk: break
                seen += len(chunk)
                assert seen <= size, 'asset exceeds expected bound'
                actual.update(chunk); out.write(chunk)
        assert seen == size and actual.hexdigest() == digest, 'baseline GPU input mismatch'
        print('baseline', name, size, digest, 'PASS')
if __name__ == '__main__':
    main()
