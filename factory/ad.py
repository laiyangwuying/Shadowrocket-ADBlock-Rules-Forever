# -*- coding: utf-8 -*-
#
# 提取广告规则，并且只提取对全域禁止的那种规则
# 参考 ADB 广告规则格式：https://adblockplus.org/filters

from __future__ import annotations

import re
import time
from typing import Set

from build_util import RESULTANT_DIR, fetch_text_parallel, log, read_entries, write_list
from idna_util import drain_corrections, is_ip_host, normalize_hostname, write_corrections_log

RULES_URL = [
    'https://easylist-downloads.adblockplus.org/easylistchina.txt',
    'https://easylist-downloads.adblockplus.org/easylistchina+easylist.txt',
    'https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/rule.txt',
    'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus;showintro=0',
]

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

    if (
        not row
        or row.startswith('!')
        or row.startswith('[')
        or '$' in row
        or '##' in row
        or '#@#' in row
        or '#?#' in row
    ):
        return 0

    row = re.sub(r'^\|?https?://', '', row)
    row = re.sub(r'^\|\|', '', row)
    row = row.lstrip('.*')
    row = row.rstrip('/*')
    if row.endswith('^'):
        row = row[:-1]
    row = re.sub(r':\d{2,5}$', '', row)

    if not row or re.search(r'[/^:*|]', row):
        return 0
    if row in ignore:
        return 0

    normalized = normalize_hostname(row, source='ad')
    if normalized is None:
        return 1

    is_domain = '.' in normalized and _DOMAIN_RE.match(normalized)
    if is_domain or is_ip_host(normalized):
        domains.add(normalized)
    return 0


def build() -> dict:
    ignore = _load_ignore()
    texts = fetch_text_parallel(RULES_URL)
    rule = '\n'.join(texts[u] for u in RULES_URL) + '\n'

    domains: Set[str] = set()
    idna_skipped = 0
    for row in rule.splitlines():
        idna_skipped += _parse_row(row.strip(), domains, ignore)

    header = '# adblock rules refresh time: ' + time.strftime('%Y-%m-%d %H:%M:%S')
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
