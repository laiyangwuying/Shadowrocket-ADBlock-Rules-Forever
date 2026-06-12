# -*- coding: utf-8 -*-
"""拉取 Cats-Team AdRules Plus，补充 EasyList 未覆盖的 URL Rewrite。"""

from __future__ import annotations

import time
from typing import Set

from ad_block_util import is_youtube_rewrite_rule, rewrite_lines_from_list_file
from ad_filters import iter_filter_rules
from ad_rewrite import abp_network_rule_to_rewrite
from build_util import RESULTANT_DIR, atomic_write, fetch_text, log

CATS_TEAM_RULES_URL = (
    'https://raw.githubusercontent.com/Cats-Team/AdRules/main/adblock_plus.txt'
)
_OUTPUT = RESULTANT_DIR / 'cats_team_rewrite.list'
_MAX_DELTA = 8000


def _existing_rewrite_keys() -> set[str]:
    return set(rewrite_lines_from_list_file(RESULTANT_DIR / 'ad_rewrite.list'))


def _cats_line_to_rewrite(line: str) -> str | None:
    stripped = line.strip()
    if not stripped or stripped.startswith('!'):
        return None
    if stripped.startswith('@@'):
        return None
    return abp_network_rule_to_rewrite(
        stripped,
        allow_domain_block=True,
        skip_scoped_options=True,
    )


def build() -> dict:
    existing = _existing_rewrite_keys()
    text = fetch_text(CATS_TEAM_RULES_URL)
    rewrites: Set[str] = set()
    skipped_replace = 0
    skipped_dup = 0
    skipped_other = 0

    for line in iter_filter_rules(text):
        raw = line.strip()
        if '$replace' in raw.lower():
            skipped_replace += 1
            continue
        rewrite = _cats_line_to_rewrite(raw)
        if rewrite is None:
            skipped_other += 1
            continue
        if is_youtube_rewrite_rule(rewrite):
            skipped_other += 1
            continue
        if rewrite in existing or rewrite in rewrites:
            skipped_dup += 1
            continue
        rewrites.add(rewrite)
        if len(rewrites) >= _MAX_DELTA:
            log(f'ad_cats_team: hit cap {_MAX_DELTA}')
            break

    header = (
        f'# Cats-Team AdRules Plus delta @ {time.strftime("%Y-%m-%d %H:%M:%S")}\n'
        f'# source: {CATS_TEAM_RULES_URL}\n'
        f'# 相对 EasyList+AdGuard 的 ad_rewrite.list 增量（上限 {_MAX_DELTA}）\n'
    )
    body = '\n'.join(sorted(rewrites)) + '\n'
    atomic_write(_OUTPUT, header + body)
    log(
        f'ad_cats_team: {len(rewrites)} delta rewrite lines '
        f'({skipped_dup} dup, {skipped_replace} $replace, {skipped_other} other skipped)'
    )
    return {
        'rewrites': len(rewrites),
        'skipped_dup': skipped_dup,
        'skipped_replace': skipped_replace,
        'skipped_other': skipped_other,
    }


def main() -> int:
    build()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
