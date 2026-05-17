# -*- coding: utf-8 -*-
"""
读取 vendor_urls.txt：构建时按需下载模块到 vendor/。
成功则原子替换目标文件；任一步失败则删除临时文件并保留原文件。
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
VENDOR_ROOT = FACTORY_ROOT / 'vendor'
CONFIG_PATH = FACTORY_ROOT / 'vendor_urls.txt'

USER_AGENT = (
    'Mozilla/5.0 (compatible; Shadowrocket-ADBlock-Rules-Forever/vendor-fetch; +https://github.com/)'
)

_LINE_RE = re.compile(r'^([^#\s]+)\s+(https?://\S+)\s*$', re.I)


def _log(msg: str) -> None:
    print(msg, file=sys.stderr)


def safe_vendor_path(rel: str) -> Optional[Path]:
    rp = Path(rel.strip().lstrip(os.sep).replace('\\', '/'))
    if rp.is_absolute() or '..' in rp.parts:
        return None
    dest = (VENDOR_ROOT / rp).resolve()
    try:
        dest.relative_to(VENDOR_ROOT.resolve())
    except ValueError:
        return None
    return dest


def fetch_one(url: str, dest: Path) -> bool:
    dest.parent.mkdir(parents=True, exist_ok=True)
    headers = {'User-Agent': USER_AGENT}

    fd, tmppath = tempfile.mkstemp(
        suffix='.part',
        prefix='.dl-' + dest.name.replace(os.sep, '_') + '-',
        dir=str(dest.parent),
    )
    os.close(fd)
    tmp = Path(tmppath)

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
        _log(f'fetch_vendor_modules: OK {url} → {dest.relative_to(FACTORY_ROOT)}')
        return True
    except Exception as exc:
        _log(f'fetch_vendor_modules: FAIL keep existing → {dest.name}: {exc}')
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass
        return False


def main() -> int:
    VENDOR_ROOT.mkdir(parents=True, exist_ok=True)
    if not CONFIG_PATH.is_file():
        _log('fetch_vendor_modules: vendor_urls.txt 不存在 — 跳过')
        return 0

    raw_txt = CONFIG_PATH.read_text(encoding='utf-8')
    todo = []
    for raw in raw_txt.splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        mo = _LINE_RE.match(line)
        if not mo:
            _log(f'fetch_vendor_modules: 忽略无法解析的行 → {raw!r}')
            continue
        todo.append((mo.group(1), mo.group(2)))

    if not todo:
        _log('fetch_vendor_modules: vendor_urls.txt 无有效条目 — 跳过')
        return 0

    ok_n = 0
    for rel, url in todo:
        dest = safe_vendor_path(rel)
        if dest is None:
            _log(f'fetch_vendor_modules: 路径非法（须落在 vendor 下）→ {rel!r}')
            continue
        if fetch_one(url, dest):
            ok_n += 1

    _log(
        'fetch_vendor_modules: 完成 %d/%d @ %s'
        % (ok_n, len(todo), time.strftime('%Y-%m-%d %H:%M:%S'))
    )
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
