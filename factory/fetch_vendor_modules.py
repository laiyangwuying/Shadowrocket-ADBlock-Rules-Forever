# -*- coding: utf-8 -*-
"""
构建时从远端拉取模块：
  module_urls.txt → 仓库 module/
  vendor_urls.txt → factory/vendor/
成功则原子替换；失败保留本地已有文件。
"""

from __future__ import annotations

import os
import re
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional

import requests

FACTORY_ROOT = Path(__file__).resolve().parent
REPO_ROOT = FACTORY_ROOT.parent
MODULE_ROOT = REPO_ROOT / 'module'
VENDOR_ROOT = FACTORY_ROOT / 'vendor'
MODULE_CONFIG = FACTORY_ROOT / 'module_urls.txt'
VENDOR_CONFIG = FACTORY_ROOT / 'vendor_urls.txt'

USER_AGENT = (
    'Mozilla/5.0 (compatible; Shadowrocket-ADBlock-Rules-Forever/vendor-fetch; +https://github.com/)'
)

_LINE_RE = re.compile(r'^([^#\s]+)\s+(https?://\S+)\s*$', re.I)


def _log(msg: str) -> None:
    print(msg, file=sys.stderr)


def _safe_dest(root: Path, rel: str) -> Optional[Path]:
    rp = Path(rel.strip().lstrip(os.sep).replace('\\', '/'))
    if rp.is_absolute() or '..' in rp.parts:
        return None
    dest = (root / rp).resolve()
    try:
        dest.relative_to(root.resolve())
    except ValueError:
        return None
    return dest


def fetch_one(url: str, dest: Path, *, label: str) -> bool:
    dest.parent.mkdir(parents=True, exist_ok=True)
    headers = {'User-Agent': USER_AGENT}

    fd, tmppath = tempfile.mkstemp(
        suffix='.part',
        prefix='.dl-' + dest.name.replace(os.sep, '_') + '-',
        dir=str(dest.parent),
    )
    os.close(fd)
    tmp = Path(tmppath)

    last_exc: Exception | None = None
    for attempt in range(3):
        try:
            r = requests.get(
                url,
                headers=headers,
                timeout=(12, 90),
                allow_redirects=True,
            )
            r.raise_for_status()
            data = r.content
            if not data.strip():
                raise ValueError('empty response body')

            tmp.write_bytes(data)
            os.replace(tmp, dest)
            _log(f'{label}: OK {url} → {dest.relative_to(REPO_ROOT)}')
            return True
        except Exception as exc:
            last_exc = exc
            if attempt < 2:
                time.sleep(1.5 * (attempt + 1))
    _log(f'{label}: FAIL keep existing → {dest.name}: {last_exc}')
    try:
        if tmp.exists():
            tmp.unlink()
    except OSError:
        pass
    return False


def _load_entries(path: Path) -> list[tuple[str, str]]:
    if not path.is_file():
        return []
    entries: list[tuple[str, str]] = []
    for raw in path.read_text(encoding='utf-8').splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        mo = _LINE_RE.match(line)
        if not mo:
            _log(f'fetch_modules: 忽略无法解析的行 → {raw!r}')
            continue
        entries.append((mo.group(1), mo.group(2)))
    return entries


def _fetch_config(
    config: Path,
    root: Path,
    *,
    label: str,
) -> tuple[int, int]:
    entries = _load_entries(config)
    if not entries:
        return 0, 0

    ok_n = 0
    for rel, url in entries:
        dest = _safe_dest(root, rel)
        if dest is None:
            _log(f'{label}: 路径非法 → {rel!r}')
            continue
        if fetch_one(url, dest, label=label):
            ok_n += 1
    return ok_n, len(entries)


def main() -> dict:
    MODULE_ROOT.mkdir(parents=True, exist_ok=True)
    VENDOR_ROOT.mkdir(parents=True, exist_ok=True)

    module_ok, module_total = _fetch_config(MODULE_CONFIG, MODULE_ROOT, label='fetch_module')
    vendor_ok, vendor_total = _fetch_config(VENDOR_CONFIG, VENDOR_ROOT, label='fetch_vendor')

    if module_total == 0 and vendor_total == 0:
        _log('fetch_modules: 无有效条目 — 跳过')
    else:
        _log(
            'fetch_modules: module %d/%d, vendor %d/%d @ %s'
            % (
                module_ok,
                module_total,
                vendor_ok,
                vendor_total,
                time.strftime('%Y-%m-%d %H:%M:%S'),
            )
        )

    return {
        'module_ok': module_ok,
        'module_total': module_total,
        'vendor_ok': vendor_ok,
        'vendor_total': vendor_total,
    }


if __name__ == '__main__':
    raise SystemExit(0 if main()['module_ok'] == main()['module_total'] else 0)
