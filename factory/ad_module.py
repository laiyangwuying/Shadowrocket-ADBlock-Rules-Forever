# -*- coding: utf-8 -*-
"""生成 module/AdBlock.module（静态 App 规则 + 过滤器 URL Rewrite）。"""

from __future__ import annotations

import time
from pathlib import Path

from build_util import FACTORY_ROOT, RESULTANT_DIR, atomic_write, log

REPO_ROOT = FACTORY_ROOT.parent
MODULE_PATH = REPO_ROOT / 'module' / 'AdBlock.module'
TEMPLATE_DIR = FACTORY_ROOT / 'template'


def _read_optional(path: Path) -> str:
    if not path.is_file():
        return ''
    return path.read_text(encoding='utf-8').rstrip('\n')


def build() -> dict:
    static = _read_optional(TEMPLATE_DIR / 'adblock_rewrite_static.txt')
    generated = _read_optional(RESULTANT_DIR / 'ad_rewrite.list')
    mitm_hosts = _read_optional(TEMPLATE_DIR / 'adblock_mitm_hosts.txt')

    parts = [
        '#!name= NoAd',
        '#!desc= 广告屏蔽（EasyList China + AdGuard 中文，每日构建）',
        '#!homepage=https://github.com/laiyangwuying/Shadowrocket-ADBlock-Rules-Forever',
        '#!author= Tartarus2014 + build',
        '#!icon= https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Advertising.png',
        f'#!date= {time.strftime("%Y-%m-%d %H:%M:%S")}',
        '',
        '[URL Rewrite]',
    ]
    if static:
        parts.append(static)
    if generated:
        parts.extend(['', '# --- EasyList China + AdGuard 中文（自动生成）---', generated])
    parts.extend(['', '[MITM]', mitm_hosts or 'hostname = %APPEND% example.com', ''])

    atomic_write(MODULE_PATH, '\n'.join(parts) + '\n')
    log(f'ad_module: wrote {MODULE_PATH.relative_to(REPO_ROOT)}')
    return {'module': str(MODULE_PATH.name)}


def main() -> int:
    build()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
