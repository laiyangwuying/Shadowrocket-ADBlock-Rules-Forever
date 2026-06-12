# -*- coding: utf-8 -*-
"""从 EasyList China + AdGuard 中文过滤器生成 Shadowrocket URL Rewrite 规则。"""

from __future__ import annotations

import re
import time
from typing import Set

from ad_filters import (
    fetch_combined_filters,
    iter_filter_rules,
    should_skip_options,
    split_rule_options,
)
from build_util import RESULTANT_DIR, atomic_write, log

_ACTION = 'reject'
_MAX_REWRITES = 12000


def _wildcard_escape(pattern: str) -> str:
    out: list[str] = []
    for ch in pattern:
        if ch == '*':
            out.append(r'[\w-]+')
        elif ch in r'.[](){}+?^$|\\':
            out.append('\\' + ch)
        else:
            out.append(ch)
    return ''.join(out)


def _host_to_re(host: str) -> str:
    host = host.split(':', 1)[0]
    escaped = _wildcard_escape(host)
    return rf'([\w-]+\.)*{escaped}'


def _abp_line_to_rewrite(line: str) -> str | None:
    if '##' in line or '#@#' in line or '#?#' in line:
        return None

    pattern, opts = split_rule_options(line)
    if not pattern or should_skip_options(opts):
        return None

    # 完整 URL：|http(s)://...
    if pattern.startswith('|http://') or pattern.startswith('|https://'):
        url = pattern[1:]
        if url.endswith('^'):
            url = url[:-1]
        url = re.sub(r'^https?://', '', url)
        if not url or len(url) < 2:
            return None
        return rf'^https?:\/\/{_wildcard_escape(url)} {_ACTION}'

    # 域名 + 路径：||host/path^
    if pattern.startswith('||'):
        body = pattern[2:]
        if body.endswith('^'):
            body = body[:-1]
        if '/' not in body:
            return None
        host, path = body.split('/', 1)
        if not host or not path or len(path) < 2:
            return None
        return (
            rf'^https?:\/\/{_host_to_re(host)}\/{_wildcard_escape(path)} {_ACTION}'
        )

    # ABP 正则：/.../options
    if pattern.startswith('/') and pattern.count('/') >= 2:
        m = re.match(r'^/(.*?)/([^/]*)$', pattern)
        if not m:
            return None
        inner = m.group(1)
        if not inner or len(inner) < 3:
            return None
        if inner.startswith('^https'):
            return f'{inner} {_ACTION}'
        if inner.startswith('^'):
            return f'^https?:\\/\\/[\\w.-]+{inner[1:]} {_ACTION}'
        return rf'^https?:\/\/[\w.-]+{inner} {_ACTION}'

    # 路径 / 域名片段规则：.com/ads/、/banner.js 等
    if pattern.startswith('/') or pattern.startswith('.'):
        if len(pattern) < 4:
            return None
        if pattern.endswith('^'):
            pattern = pattern[:-1]
        return rf'^https?:\/\/[\w.-]+{_wildcard_escape(pattern)} {_ACTION}'

    return None


def build() -> dict:
    text = fetch_combined_filters()
    rewrites: Set[str] = set()
    skipped = 0

    for line in iter_filter_rules(text):
        rewrite = _abp_line_to_rewrite(line)
        if rewrite is None:
            skipped += 1
            continue
        rewrites.add(rewrite)
        if len(rewrites) >= _MAX_REWRITES:
            log(f'ad_rewrite: hit cap {_MAX_REWRITES}, remaining rules skipped')
            break

    header = (
        f'# ad url rewrite from EasyList China + AdGuard Chinese @ '
        f'{time.strftime("%Y-%m-%d %H:%M:%S")}\n'
    )
    body = '\n'.join(sorted(rewrites)) + '\n'
    atomic_write(RESULTANT_DIR / 'ad_rewrite.list', header + body)
    log(f'ad_rewrite: {len(rewrites)} lines ({skipped} filter rows not converted)')
    return {'rewrites': len(rewrites), 'skipped': skipped}


def main() -> int:
    build()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
