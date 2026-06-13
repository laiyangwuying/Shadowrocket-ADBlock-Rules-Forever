# -*- coding: utf-8 -*-
"""广告过滤器拉取与 ABP 规则行解析。"""

from __future__ import annotations

import re
from typing import Iterator

from build_util import fetch_text, fetch_text_parallel

CATS_TEAM_DNS_URL = (
    'https://raw.githubusercontent.com/Cats-Team/AdRules/refs/heads/main/dns.txt'
)

EASYLIST_CHINA_URL = 'https://easylist-downloads.adblockplus.org/easylistchina.txt'
ADGUARD_CHINESE_URL = (
    'https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/'
    'master/filters/filter_224_Chinese/filter.txt'
)

FILTER_URLS = (EASYLIST_CHINA_URL, ADGUARD_CHINESE_URL)

_filter_cache: str | None = None
_cats_team_dns_cache: str | None = None

_SKIP_OPTION_RE = re.compile(
    r'elemhide|generichide|specifichide|append|removeparam|redirect',
    re.I,
)
# 带作用域限制的选项无法忠实转为 Shadowrocket 全局规则
_SKIP_SCOPED_OPTS_RE = re.compile(
    r'domain=|third-party|first-party|popup|subdocument|xmlhttprequest|'
    r'websocket|image|script|stylesheet|font|media|object|match-case|~',
    re.I,
)


def fetch_combined_filters(*, force: bool = False) -> str:
    global _filter_cache
    if _filter_cache is not None and not force:
        return _filter_cache
    texts = fetch_text_parallel(FILTER_URLS)
    _filter_cache = '\n'.join(texts[u] for u in FILTER_URLS) + '\n'
    return _filter_cache


def fetch_cats_team_dns(*, force: bool = False) -> str:
    """Cats-Team AdRules DNS 列表（供 conf 域名 REJECT）。"""
    global _cats_team_dns_cache
    if _cats_team_dns_cache is not None and not force:
        return _cats_team_dns_cache
    _cats_team_dns_cache = fetch_text(CATS_TEAM_DNS_URL) + '\n'
    return _cats_team_dns_cache


def clear_filter_cache() -> None:
    global _filter_cache, _cats_team_dns_cache
    _filter_cache = None
    _cats_team_dns_cache = None


def iter_filter_rules(text: str) -> Iterator[str]:
    """ABP 网络规则行（跳过例外 @@，供 adblock.txt 等）。"""
    for line in iter_dns_lines(text):
        if line.startswith('@@'):
            continue
        yield line


def iter_dns_lines(text: str) -> Iterator[str]:
    """dns.txt 有效行（保留 @@ 例外；跳过 ! / # 注释）。"""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith('!') or line.startswith('#'):
            continue
        if line.startswith('['):
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


def should_skip_scoped_options(opts: str) -> bool:
    """跳过带 domain=/third-party 等上下文选项的规则（避免误伤）。"""
    if not opts:
        return False
    if should_skip_options(opts):
        return True
    return bool(_SKIP_SCOPED_OPTS_RE.search(opts))
