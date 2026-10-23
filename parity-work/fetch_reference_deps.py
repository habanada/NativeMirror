from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import shutil
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
DEST = ROOT / 'parity-work/references/pe-sieve-0.4.1.5/build-source'
SOURCE = ROOT / 'pe-sieve-master/pe-sieve-master'
if not DEST.exists():
    shutil.copytree(SOURCE, DEST)
paramkit = ROOT / 'parity-work/references/paramkit-60c88544e101bf7052e26b97a13484d013c2bd19'
shutil.copytree(paramkit, DEST / 'paramkit', dirs_exist_ok=True)
dependencies = {
    'libpeconv': '0fc25f680e03699d33ef3b2034a6724365f3d1a4',
    'sig_finder': '9f4a36d7cbea99b8318e4803b0c87ebeb1a764c0',
}


def request(url):
    req = urllib.request.Request(url, headers={'User-Agent': 'NativeMirror-reference-verification'})
    with urllib.request.urlopen(req, timeout=60) as response:
        return response.read()


def download(job):
    repo, commit, entry = job
    relative = Path(entry['path'])
    if relative.is_absolute() or '..' in relative.parts:
        raise RuntimeError('Invalid reference path')
    destination = DEST / repo / relative
    data = request(f'https://raw.githubusercontent.com/hasherezade/{repo}/{commit}/{entry["path"]}')
    actual = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
    if actual != entry['sha']:
        raise RuntimeError('Hash mismatch: ' + str(destination))
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    return str(destination.relative_to(DEST))


jobs = []
for repo, commit in dependencies.items():
    data = request(f'https://api.github.com/repos/hasherezade/{repo}/git/trees/{commit}?recursive=1')
    (DEST.parent / (repo + '-tree.json')).write_bytes(data)
    tree = json.loads(data)
    if tree.get('truncated'):
        raise RuntimeError('Truncated tree')
    for entry in tree['tree']:
        if entry['mode'] == '160000':
            raise RuntimeError('Unresolved nested dependency: ' + entry['path'])
        if entry['type'] == 'blob' and Path(entry['path']).suffix.lower() in ('.cpp', '.c', '.h', '.hpp', '.txt', '.cmake', '.asm', '.def', '.rc', '.in'):
            jobs.append((repo, commit, entry))
with ThreadPoolExecutor(max_workers=6) as executor:
    files = list(executor.map(download, jobs))
(DEST.parent / 'dependency-download.json').write_text(json.dumps(dict(dependencies=dependencies, files=files), indent=2))
print('Verified dependency files:', len(files), flush=True)
