# -*- coding: utf-8 -*-
"""将 factory/lazy/ 中的懒人配置发布到仓库根目录（供 Pages / 订阅 URL 使用）。"""

from __future__ import annotations

from build_util import FACTORY_ROOT, atomic_write, log

REPO_ROOT = FACTORY_ROOT.parent

LAZY_DIR = FACTORY_ROOT / 'lazy'
LAZY_FILES = ('lazy.conf', 'lazy_group.conf')


def _validate(name: str, content: str) -> None:
    if not content.strip():
        raise ValueError(f'{name}: empty')
    if '404: Not Found' in content:
        raise ValueError(f'{name}: invalid placeholder')
    if '[General]' not in content:
        raise ValueError(f'{name}: missing [General] section')


def publish() -> dict:
    if not LAZY_DIR.is_dir():
        raise FileNotFoundError(f'lazy source dir missing: {LAZY_DIR}')

    for name in LAZY_FILES:
        src = LAZY_DIR / name
        if not src.is_file():
            raise FileNotFoundError(src)
        content = src.read_text(encoding='utf-8')
        _validate(name, content)
        atomic_write(REPO_ROOT / name, content)

    log(f'lazy: published {", ".join(LAZY_FILES)} from factory/lazy/')
    return {'files': len(LAZY_FILES)}


def main() -> int:
    publish()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
