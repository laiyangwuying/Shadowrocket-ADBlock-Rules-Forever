# -*- coding: utf-8 -*-
"""拉取 Cats-Team AdRules 网络规则并转为 Shadowrocket URL Rewrite。"""

from __future__ import annotations

import time
from typing import Set

from ad_block_util import is_youtube_rewrite_rule
from ad_filters import iter_filter_rules
from ad_rewrite import abp_network_rule_to_rewrite
from build_util import RESULTANT_DIR, atomic_write, fetch_text, log

CATS_TEAM_RULES_URL = (
    'https://raw.githubusercontent.com/Cats-Team/AdRules/'
    'script/mod/rules/adblock-rules.txt'
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
        skip_scoped_options=False,
    )


def build() -> dict:
    text = fetch_text(CATS_TEAM_RULES_URL)
    rewrites: Set[str] = set()
    skipped_replace = 0
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
        rewrites.add(rewrite)

    header = (
        f'# Cats-Team AdRules network rules @ {time.strftime("%Y-%m-%d %H:%M:%S")}\n'
        f'# source: {CATS_TEAM_RULES_URL}\n'
        f'# $replace / cosmetic / @@ 白名单规则未转换（Shadowrocket 不支持）\n'
    )
    body = '\n'.join(sorted(rewrites)) + '\n'
    atomic_write(_OUTPUT, header + body)
    log(
        f'ad_cats_team: {len(rewrites)} rewrite lines '
        f'({skipped_replace} $replace skipped, {skipped_other} other skipped)'
    )
    return {
        'rewrites': len(rewrites),
        'skipped_replace': skipped_replace,
        'skipped_other': skipped_other,
    }


def main() -> int:
    build()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
