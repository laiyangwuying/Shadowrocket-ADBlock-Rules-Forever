# -*- coding: utf-8 -*-
"""拉取 Cats-Team AdRules，全量生成 Shadowrocket URL Rewrite。"""

from __future__ import annotations

import time
from typing import Set

from ad_block_util import is_dedicated_module_abp_rule, is_dedicated_module_rewrite
from ad_filters import iter_filter_rules
from dedicated_modules import get_dedicated_module_index
from ad_rewrite import abp_network_rule_to_rewrite, static_rewrite_keys
from build_util import RESULTANT_DIR, atomic_write, fetch_text, log

CATS_TEAM_RULES_URL = (
    'https://raw.githubusercontent.com/Cats-Team/AdRules/main/adblock.txt'
)
_OUTPUT = RESULTANT_DIR / 'cats_team_rewrite.list'
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
    get_dedicated_module_index.cache_clear()
    static_keys = static_rewrite_keys()
    text = fetch_text(CATS_TEAM_RULES_URL)
    rewrites: Set[str] = set()
    skipped_replace = 0
    skipped_dup = 0
    skipped_other = 0

    for line in iter_filter_rules(text):
        raw = line.strip()
        if is_dedicated_module_abp_rule(raw):
            skipped_other += 1
            continue
        if '$replace' in raw.lower():
            skipped_replace += 1
            continue
        rewrite = _cats_line_to_rewrite(raw)
        if rewrite is None:
            skipped_other += 1
            continue
        if is_dedicated_module_rewrite(rewrite):
            skipped_other += 1
            continue
        if rewrite in static_keys or rewrite in rewrites:
            skipped_dup += 1
            continue
        rewrites.add(rewrite)

    header = (
        f'# Cats-Team AdRules @ {time.strftime("%Y-%m-%d %H:%M:%S")}\n'
        f'# source: {CATS_TEAM_RULES_URL}\n'
    )
    body = '\n'.join(sorted(rewrites)) + '\n'
    atomic_write(_OUTPUT, header + body)
    log(
        f'ad_cats_team: {len(rewrites)} rewrite lines '
        f'({skipped_dup} dup static, {skipped_replace} $replace, '
        f'{skipped_other} other skipped)'
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
