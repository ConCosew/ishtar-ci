#!/usr/bin/env python3
"""Fetch the exact tested GPU addon/trust bytes; no rebuild changes for timing test."""
import hashlib
import os
from pathlib import Path
import urllib.request

ASSETS = [
    ('gpuaddon.bin', 767376238, 13708408, '21d601e84157d8cb935430ac9c9a998a1ec58179ea392142135e39cc21d3081a'),
    ('owner-trust.bundle', 767376234, 95828, '7aa6455edeabb74f753301a721af51eb2800e026227414bd31e70cffbabe0cef'),
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
