# -*- coding: utf-8 -*-
#
# 提取广告规则，并且只提取对全域禁止的那种规则
# 参考 ADB 广告规则格式：https://adblockplus.org/filters

from __future__ import annotations

import re
import time
from typing import Set

from ad_block_util import YOUTUBE_PROTECTED_SUFFIXES, is_youtube_protected_host
from ad_filters import (
    fetch_combined_filters,
    iter_filter_rules,
    should_skip_scoped_options,
    split_rule_options,
)
from build_util import RESULTANT_DIR, log, read_entries, write_list
from idna_util import drain_corrections, is_ip_host, normalize_hostname, write_corrections_log

_DOMAIN_RE = re.compile(
    r'^\.?[a-zA-Z0-9][-a-zA-Z0-9]{0,62}'
    r'(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})*\.[a-zA-Z0-9][-a-zA-Z0-9]{1,}$'
)


def _load_ignore() -> set[str]:
    path = RESULTANT_DIR / 'ad_ignore.list'
    if not path.is_file():
        return set()
    return set(read_entries(path))


def _parse_row(row: str, domains: Set[str], ignore: set[str]) -> int:
    """解析一行；返回 1 表示因 IDNA 无效而跳过。"""
    if row.startswith('@@'):
        to_remove = [d for d in domains if d in row]
        for d in to_remove:
            domains.discard(d)
        return 0

    if not row or '##' in row or '#@#' in row or '#?#' in row:
        return 0

    pattern, opts = split_rule_options(row)
    if not pattern.startswith('||'):
        return 0
    if should_skip_scoped_options(opts):
        return 0

    row = pattern[2:]
    if row.endswith('^'):
        row = row[:-1]
    # ||host/path 为按 URL 拦截，非整域拦截（由 ad_rewrite 处理）
    if '/' in row:
        return 0
    row = re.sub(r':\d{2,5}$', '', row)

    if not row or re.search(r'[/^:*|]', row):
        return 0
    if row in ignore:
        return 0

    normalized = normalize_hostname(row, source='ad')
    if normalized is None:
        return 1
    if is_youtube_protected_host(normalized):
        return 0

    is_domain = '.' in normalized and _DOMAIN_RE.match(normalized)
    if is_domain or is_ip_host(normalized):
        domains.add(normalized)
    return 0


def build() -> dict:
    ignore = _load_ignore() | set(YOUTUBE_PROTECTED_SUFFIXES)
    rule = fetch_combined_filters()

    domains: Set[str] = set()
    idna_skipped = 0
    for row in iter_filter_rules(rule):
        idna_skipped += _parse_row(row, domains, ignore)

    header = (
        '# adblock domains: EasyList China + AdGuard Chinese @ '
        + time.strftime('%Y-%m-%d %H:%M:%S')
    )
    domains = {d for d in domains if not is_youtube_protected_host(d)}
    count = write_list(RESULTANT_DIR / 'ad.list', header, domains)
    write_corrections_log(
        str(RESULTANT_DIR / 'idna_corrections.log'),
        drain_corrections(),
        append=False,
    )
    log(f'ad: {count} domains, {idna_skipped} idna-skipped')
    return {'domains': count, 'idna_skipped': idna_skipped}


def main() -> int:
    build()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
