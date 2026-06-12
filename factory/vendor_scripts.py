# -*- coding: utf-8 -*-
"""镜像 module 中 script-path 引用的远端脚本，并重写为仓库 raw 地址。"""

from __future__ import annotations

import hashlib
import re
import time
from pathlib import Path
from urllib.parse import unquote, urlparse

from build_util import FACTORY_ROOT, RESULTANT_DIR, atomic_write, fetch_text, log
from publish_urls import RELEASE_RAW_BASE

REPO_ROOT = FACTORY_ROOT.parent
SCRIPTS_ROOT = REPO_ROOT / 'scripts'
MODULE_ROOT = REPO_ROOT / 'module'
VENDOR_ROOT = FACTORY_ROOT / 'vendor'

SCRIPT_PATH_RE = re.compile(r'(script-path=)(https?://[^,\s]+)', re.I)
MODULE_GLOBS = ('*.module', '*.sgmodule')

_GITHUB_BLOB_RE = re.compile(
    r'^https://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.*)$', re.I
)
_GITHUB_RAW_RE = re.compile(
    r'^https://github\.com/([^/]+)/([^/]+)/raw/([^/]+)/(.*)$', re.I
)
_GH_REFS_HEADS_RE = re.compile(
    r'^https://raw\.githubusercontent\.com/([^/]+)/([^/]+)/refs/heads/([^/]+)/(.*)$',
    re.I,
)


def normalize_script_url(url: str) -> str:
    url = url.strip()
    m = _GITHUB_BLOB_RE.match(url)
    if m:
        return (
            f'https://raw.githubusercontent.com/{m.group(1)}/{m.group(2)}/'
            f'{m.group(3)}/{m.group(4)}'
        )
    m = _GITHUB_RAW_RE.match(url)
    if m:
        return (
            f'https://raw.githubusercontent.com/{m.group(1)}/{m.group(2)}/'
            f'{m.group(3)}/{m.group(4)}'
        )
    m = _GH_REFS_HEADS_RE.match(url)
    if m:
        return (
            f'https://raw.githubusercontent.com/{m.group(1)}/{m.group(2)}/'
            f'{m.group(3)}/{m.group(4)}'
        )
    return url


def _local_relpath(url: str) -> str:
    parsed = urlparse(url)
    path = unquote(parsed.path).lstrip('/')
    if not path:
        path = 'index'
    digest = hashlib.sha1(url.encode('utf-8')).hexdigest()[:10]
    suffix = Path(path).suffix or '.js'
    stem = Path(path).stem
    parent = str(Path(path).parent).replace('\\', '/')
    if parent in ('.', ''):
        rel = f'{parsed.netloc}/{stem}.{digest}{suffix}'
    else:
        rel = f'{parsed.netloc}/{parent}/{stem}.{digest}{suffix}'
    return f'scripts/{rel}'


def _mirrored_url(rel_path: str) -> str:
    return RELEASE_RAW_BASE + rel_path.replace('\\', '/')


def _is_mirrored_url(url: str) -> bool:
    prefix = RELEASE_RAW_BASE + 'scripts/'
    return url.startswith(prefix)


def _scan_module_files() -> list[Path]:
    """仅扫描发布的 module/；vendor/ 为历史缓存，可能含失效外链。"""
    files: list[Path] = []
    if MODULE_ROOT.is_dir():
        for pattern in MODULE_GLOBS:
            files.extend(sorted(MODULE_ROOT.glob(pattern)))
    return files


def _count_local_scripts() -> int:
    if not SCRIPTS_ROOT.is_dir():
        return 0
    return sum(1 for p in SCRIPTS_ROOT.rglob('*') if p.is_file())


def _collect_script_urls(files: list[Path]) -> dict[str, set[str]]:
    """original url -> set of normalized aliases"""
    groups: dict[str, set[str]] = {}
    for path in files:
        text = path.read_text(encoding='utf-8', errors='replace')
        for _prefix, url in SCRIPT_PATH_RE.findall(text):
            original = url.strip()
            if _is_mirrored_url(original):
                continue
            normalized = normalize_script_url(original)
            key = normalized
            groups.setdefault(key, set()).add(original)
            groups[key].add(normalized)
    return groups


def _download_scripts(groups: dict[str, set[str]]) -> dict[str, str]:
    """normalized url -> mirrored public url"""
    url_map: dict[str, str] = {}
    manifest_lines = [
        '# original\tnormalized\tlocal_path\tmirrored_url',
    ]
    ok = 0
    fail = 0

    for normalized, aliases in sorted(groups.items()):
        rel = _local_relpath(normalized)
        dest = REPO_ROOT / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        fetched = False
        for candidate in (normalized, *sorted(aliases)):
            try:
                body = fetch_text(candidate, retries=3)
                if not body.strip():
                    raise ValueError('empty body')
                atomic_write(dest, body)
                fetched = True
                ok += 1
                break
            except Exception as exc:
                last_exc = exc
        if not fetched:
            if dest.is_file() and dest.stat().st_size > 0:
                log(f'vendor_scripts: keep existing {rel} ({last_exc})')
                ok += 1
            else:
                log(f'vendor_scripts: FAIL {normalized} ({last_exc})')
                fail += 1
                continue

        mirrored = _mirrored_url(rel)
        for alias in aliases:
            url_map[alias] = mirrored
        for sample in sorted(aliases)[:1]:
            manifest_lines.append(
                f'{sample}\t{normalized}\t{rel}\t{mirrored}'
            )

    manifest = '\n'.join(manifest_lines) + '\n'
    atomic_write(RESULTANT_DIR / 'script_mirror.manifest.tsv', manifest)
    log(f'vendor_scripts: downloaded/kept {ok}, failed {fail}')
    return url_map


def _rewrite_modules(files: list[Path], url_map: dict[str, str]) -> int:
    changed = 0
    for path in files:
        if path.parent not in (MODULE_ROOT, VENDOR_ROOT):
            continue
        text = path.read_text(encoding='utf-8', errors='replace')

        def repl(match: re.Match[str]) -> str:
            prefix, url = match.group(1), match.group(2).strip()
            new_url = url_map.get(url) or url_map.get(normalize_script_url(url))
            if new_url and new_url != url:
                return prefix + new_url
            return match.group(0)

        new_text = SCRIPT_PATH_RE.sub(repl, text)
        if new_text != text:
            atomic_write(path, new_text)
            changed += 1
    return changed


def build() -> dict:
    files = _scan_module_files()
    groups = _collect_script_urls(files)
    local_scripts = _count_local_scripts()
    if not groups:
        log(
            f'vendor_scripts: skip fetch, all script-path already mirrored '
            f'({local_scripts} local files)'
        )
        return {
            'scripts': 0,
            'mapped': 0,
            'modules_rewritten': 0,
            'local_scripts': local_scripts,
            'time': time.strftime('%Y-%m-%d %H:%M:%S'),
        }

    url_map = _download_scripts(groups)
    changed = _rewrite_modules(files, url_map)
    log(f'vendor_scripts: rewritten {changed} module files')
    return {
        'scripts': len(groups),
        'mapped': len(url_map),
        'modules_rewritten': changed,
        'local_scripts': local_scripts,
        'time': time.strftime('%Y-%m-%d %H:%M:%S'),
    }


def main() -> int:
    build()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
