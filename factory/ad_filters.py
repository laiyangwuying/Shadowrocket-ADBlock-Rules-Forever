# -*- coding: utf-8 -*-
"""EasyList China + AdGuard 中文过滤器：拉取与规则行解析。"""

from __future__ import annotations

import re
from typing import Iterable, Iterator

from build_util import fetch_text_parallel

EASYLIST_CHINA_URL = 'https://easylist-downloads.adblockplus.org/easylistchina.txt'
ADGUARD_CHINESE_URL = (
    'https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/'
    'master/filters/filter_224_Chinese/filter.txt'
)

FILTER_URLS = (EASYLIST_CHINA_URL, ADGUARD_CHINESE_URL)

_SKIP_OPTION_RE = re.compile(
    r'elemhide|generichide|specifichide|append|removeparam|redirect',
    re.I,
)


def fetch_combined_filters() -> str:
    texts = fetch_text_parallel(FILTER_URLS)
    return '\n'.join(texts[u] for u in FILTER_URLS) + '\n'


def iter_filter_rules(text: str) -> Iterator[str]:
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith('!') or line.startswith('['):
            continue
        if line.startswith('@@'):
            continue
        yield line.split('!', 1)[0].strip()


def split_rule_options(rule: str) -> tuple[str, str]:
    if '$' not in rule:
        return rule, ''
    pattern, opts = rule.split('$', 1)
    return pattern.strip(), opts.strip()


def should_skip_options(opts: str) -> bool:
    if not opts:
        return False
    return bool(_SKIP_OPTION_RE.search(opts))
