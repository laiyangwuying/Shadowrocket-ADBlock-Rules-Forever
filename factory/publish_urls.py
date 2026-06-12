# -*- coding: utf-8 -*-
"""GitHub Pages / raw 订阅地址（供 conf、二维码、readme 共用）。"""

from __future__ import annotations

GITHUB_REPO = 'laiyangwuying/Shadowrocket-ADBlock-Rules-Forever'

PAGES_BASE = f'https://laiyangwuying.github.io/{GITHUB_REPO.split("/")[1]}/'
RELEASE_RAW_BASE = f'https://raw.githubusercontent.com/{GITHUB_REPO}/refs/heads/build/'

GUIDE_PNG_URL = (
    'https://raw.githubusercontent.com/Johnshall/'
    'Shadowrocket-ADBlock-Rules-Forever/build/figure/guide.png'
)


def pages_conf_url(filename: str) -> str:
    return f'{PAGES_BASE}{filename}'
