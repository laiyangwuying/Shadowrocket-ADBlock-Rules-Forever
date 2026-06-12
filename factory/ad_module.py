# -*- coding: utf-8 -*-
"""生成 module/AdBlock.module（静态 App 规则 + 过滤器 URL Rewrite）。"""

from __future__ import annotations

import time
from pathlib import Path

from ad_block_util import (
    merge_rewrite_bodies,
    normalize_rewrite_body,
    rewrite_lines_from_list_file,
)
from build_util import FACTORY_ROOT, RESULTANT_DIR, atomic_write, log

REPO_ROOT = FACTORY_ROOT.parent
MODULE_PATH = REPO_ROOT / 'module' / 'AdBlock.module'
TEMPLATE_DIR = FACTORY_ROOT / 'template'
_GEN_MARKER = '# --- EasyList China + AdGuard 中文（自动生成）---'


def _read_optional(path: Path) -> str:
    if not path.is_file():
        return ''
    return path.read_text(encoding='utf-8')


def _generated_rewrite_block() -> str:
    lines = rewrite_lines_from_list_file(RESULTANT_DIR / 'ad_rewrite.list')
    if not lines:
        return ''
    return f'{_GEN_MARKER}\n' + '\n'.join(lines)


def build() -> dict:
    static = normalize_rewrite_body(_read_optional(TEMPLATE_DIR / 'adblock_rewrite_static.txt'))
    rewrite_body = merge_rewrite_bodies(static, _generated_rewrite_block())
    mitm_raw = _read_optional(TEMPLATE_DIR / 'adblock_mitm_hosts.txt').strip()

    parts = [
        '#!name= NoAd',
        '#!desc= 广告屏蔽（EasyList China + AdGuard 中文，每日构建）',
        '#!homepage=https://github.com/laiyangwuying/Shadowrocket-ADBlock-Rules-Forever',
        '#!author= Tartarus2014 + build',
        '#!icon= https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Advertising.png',
        f'#!date= {time.strftime("%Y-%m-%d %H:%M:%S")}',
        '',
        '[URL Rewrite]',
        rewrite_body,
        '',
        '[MITM]',
        mitm_raw or 'hostname = %APPEND% example.com',
        '',
    ]

    atomic_write(MODULE_PATH, '\n'.join(parts))
    log(f'ad_module: wrote {MODULE_PATH.relative_to(REPO_ROOT)}')
    return {'module': str(MODULE_PATH.name)}


def main() -> int:
    build()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
