#!/usr/bin/env python3
"""Reuse the byte-verified 256 MiB baseline GPU inputs for the touch-only experiment."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import urllib.parse
import urllib.request

RUN = 44502687562
TAG = f'gpu-runtime-{RUN}'
SOURCE_COMMIT = '0a03cb6d39f582cd3a527c06eeb6b42b3ba8f02c'
DEVICE_COMMIT = '7f8aae4f4abddb056e73b2e5c6e08f9a6f4e45d9'
API = 'https://api.github.com/repos/ConCosew/ishtar-device'
DIGESTS = {
    'gpuaddon.bin': '21d601e84157d8cb935430ac9c9a998a1ec58179ea392142135e39cc21d3081a',
    'owner-trust.bundle': '7aa6455edeabb74f753301a721af51eb2800e026227414bd31e70cffbabe0cef',
}

class AssetRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        target = urllib.parse.urlparse(newurl)
        if target.scheme != 'https' or target.hostname not in (
                'api.github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com'):
            raise RuntimeError('Unexpected baseline asset redirect host')
        successor = super().redirect_request(request, fp, code, msg, headers, newurl)
        if target.hostname != urllib.parse.urlparse(request.full_url).hostname:
            successor.remove_header('Authorization')
        return successor


def open_api(path, binary=False):
    request = urllib.request.Request(API + path, headers={
        'Authorization': 'Bearer ' + os.environ['GH_PAT'],
        'Accept': 'application/octet-stream' if binary else 'application/vnd.github+json',
    })
    return urllib.request.build_opener(AssetRedirect()).open(request, timeout=35)


def metadata(path):
    with open_api(path) as response:
        data = response.read(1024 * 1024 + 1)
    assert len(data) <= 1024 * 1024, 'Unexpectedly large release metadata'
    return json.loads(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    actual = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    assert actual == SOURCE_COMMIT, 'GPU input reuse requires the unchanged pinned UniXNU source and gitlinks'
    assert metadata('')['private'] is True
    release = metadata('/releases/tags/' + TAG)
    assert release['tag_name'] == TAG and release['prerelease'] and not release['draft']
    ref = metadata('/git/ref/tags/' + TAG)['object']
    if ref['type'] == 'tag':
        ref = metadata('/git/tags/' + ref['sha'])['object']
    assert ref['type'] == 'commit' and ref['sha'] == DEVICE_COMMIT
    assets = {a['name']: a for a in release['assets']}
    output = Path('out')
    output.mkdir(exist_ok=True)
    checked = {}
    for name, digest in DIGESTS.items():
        asset = assets[name]
        assert asset['state'] == 'uploaded' and asset['digest'] == 'sha256:' + digest
        assert 0 < asset['size'] <= 64 * 1024 * 1024
        temporary = output / ('.' + name + '.baseline.part')
        try:
            seen, hashed = 0, hashlib.sha256()
            with open_api('/releases/assets/' + str(asset['id']), binary=True) as response, temporary.open('xb') as handle:
                for _ in range(asset['size'] // (1024 * 1024) + 2):
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    seen += len(chunk)
                    assert seen <= asset['size'], 'Baseline asset exceeds its advertised size'
                    hashed.update(chunk)
                    handle.write(chunk)
            assert seen == asset['size'] and hashed.hexdigest() == digest, 'Baseline GPU input mismatch'
            temporary.replace(output / name)
        finally:
            temporary.unlink(missing_ok=True)
        checked[name] = {'id': asset['id'], 'bytes': seen, 'sha256': digest}
        print('Verified baseline', name, seen, digest)
    result = {'result': 'PASS', 'run_id': RUN, 'tag': TAG, 'device_commit': DEVICE_COMMIT,
              'unixnu_commit': SOURCE_COMMIT, 'files': checked, 'hardware_verified': False}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2) + '\n')

if __name__ == '__main__':
    main()
