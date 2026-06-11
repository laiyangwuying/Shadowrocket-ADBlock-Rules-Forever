# -*- coding: utf-8 -*-
#
# 下载并解析 GFW / 代理域名列表
# resultant/gfw.list：FULL: → DOMAIN；其余 → DOMAIN-SUFFIX
# 数据源：github.com/Loyalsoldier/v2ray-rules-dat
#

from __future__ import annotations

import re
from typing import List, Set

from build_util import FACTORY_ROOT, RESULTANT_DIR, atomic_write, fetch_text_parallel, log, read_entries
from idna_util import drain_corrections, normalize_list_entry, write_corrections_log

GFW_URLS = [
    'https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/gfw.txt',
    'https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/proxy-list.txt',
]

_FULL_MARK = 'FULL:'
unhandle_rules: List[str] = []


def clear_format(rule: str) -> list[str]:
    rules: list[str] = []
    for raw in rule.splitlines():
        row = raw.strip()
        if (
            not row
            or row.startswith('!')
            or row.startswith('@@')
            or row.startswith('[AutoProxy')
            or row.lower().startswith('regexp:')
        ):
            continue

        row = re.sub(r'^\|?https?://', '', row)
        row = re.sub(r'^\|\|', '', row)

        is_full_host = bool(re.match(r'(?i)^full:', row))
        if is_full_host:
            row = re.sub(r'(?i)^full:', '', row)
        elif re.match(r'(?i)^domain:', row):
            row = re.sub(r'(?i)^domain:', '', row)

        if not is_full_host:
            row = row.lstrip('.*')

        row = row.rstrip('/^*')
        if not row or row.lower().startswith('regexp:'):
            continue

        rules.append(_FULL_MARK + row if is_full_host else row)
    return rules


def filtrate_rules(rules: list[str], excludes: list[str]) -> list[str]:
    ret: Set[str] = set()

    for rule in rules:
        canonical = normalize_list_entry(rule, full_mark=_FULL_MARK, source='gfwlist')
        if canonical is None:
            unhandle_rules.append(rule)
            continue

        body = canonical[len(_FULL_MARK):] if canonical.startswith(_FULL_MARK) else canonical
        if body in excludes:
            continue
        if any(re.search(pat, body) for pat in excludes):
            continue
        ret.add(canonical)

    return sorted(ret)


def build() -> dict:
    global unhandle_rules
    unhandle_rules = []

    texts = fetch_text_parallel(GFW_URLS)
    merged = ''.join(texts[u] for u in GFW_URLS)
    rules = clear_format(merged)

    excludes = read_entries(FACTORY_ROOT / 'manual_gfwlist_excludes.txt')
    rules = filtrate_rules(rules, excludes)
    rules = sorted(set(rules))

    atomic_write(RESULTANT_DIR / 'gfw.list', '\n'.join(rules) + '\n')
    atomic_write(RESULTANT_DIR / 'gfw_unhandle.log', '\n'.join(unhandle_rules) + '\n')
    write_corrections_log(
        str(RESULTANT_DIR / 'idna_corrections.log'),
        drain_corrections(),
        append=True,
    )

    log(f'gfwlist: {len(rules)} rules, {len(unhandle_rules)} unhandled')
    return {'rules': len(rules), 'unhandled': len(unhandle_rules)}


def main() -> int:
    build()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
