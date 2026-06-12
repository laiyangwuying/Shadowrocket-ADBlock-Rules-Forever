# -*- coding: utf-8 -*-
"""从 EasyList China + AdGuard 中文过滤器生成 Shadowrocket URL Rewrite 规则。"""

from __future__ import annotations

import re
import time
from typing import Set

from ad_block_util import is_youtube_rewrite_rule, normalize_rewrite_body
from ad_filters import (
    fetch_combined_filters,
    iter_filter_rules,
    should_skip_scoped_options,
    split_rule_options,
)
from build_util import FACTORY_ROOT, RESULTANT_DIR, atomic_write, log

_TEMPLATE_DIR = FACTORY_ROOT / 'template'

_ACTION = 'reject'
_MAX_REWRITES = 8000
_ABP_REGEX_FLAGS_RE = re.compile(r'^[a-z]*$')


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


def _parse_abp_regex(pattern: str) -> tuple[str, str] | None:
    """ABP 正则格式 /regexp/flags；与路径过滤器 /foo/bar 区分。"""
    if not pattern.startswith('/') or pattern.count('/') < 2:
        return None
    last = pattern.rfind('/')
    flags = pattern[last + 1 :]
    if flags and not _ABP_REGEX_FLAGS_RE.fullmatch(flags):
        return None
    inner = pattern[1:last]
    if not inner or len(inner) < 3:
        return None
    return inner, flags


def _rewrite_prefix() -> str:
    return r'^https?:\/\/'


def _abp_line_to_rewrite(line: str) -> str | None:
    if '##' in line or '#@#' in line or '#?#' in line:
        return None

    pattern, opts = split_rule_options(line)
    if not pattern or should_skip_scoped_options(opts):
        return None

    # 完整 URL：|http(s)://host/path（不含通配与残缺域名）
    if pattern.startswith('|http://') or pattern.startswith('|https://'):
        url = pattern[1:]
        if url.endswith('^'):
            url = url[:-1]
        url = re.sub(r'^https?://', '', url)
        if not url or len(url) < 6 or '*' in url:
            return None
        if url.endswith('.') or url.count('.') < 1:
            return None
        return rf'{_rewrite_prefix()}{_wildcard_escape(url)} {_ACTION}'

    # 域名 + 路径：||host/path^（须含明确 host）
    if pattern.startswith('||'):
        body = pattern[2:]
        if body.endswith('^'):
            body = body[:-1]
        if '/' not in body:
            return None
        host, path = body.split('/', 1)
        if not host or not path or len(path) < 3:
            return None
        if '*' in host and host.count('.') < 1:
            return None
        return (
            rf'{_rewrite_prefix()}{_host_to_re(host)}\/{_wildcard_escape(path)} {_ACTION}'
        )

    # ABP 正则：仅保留以 ^https 开头的完整 URL 正则
    parsed = _parse_abp_regex(pattern)
    if parsed is not None:
        inner, _flags = parsed
        if inner.startswith('^https'):
            return f'{inner} {_ACTION}'
        return None

    # 不转换泛路径 /path、.com/path（在 ABP 为全站通用，在 SR 全局 Rewrite 极易误伤）
    return None


def _static_rewrite_keys() -> set[str]:
    static = normalize_rewrite_body(
        (_TEMPLATE_DIR / 'adblock_rewrite_static.txt').read_text(encoding='utf-8')
        if (_TEMPLATE_DIR / 'adblock_rewrite_static.txt').is_file()
        else ''
    )
    return {
        ln.strip()
        for ln in static.splitlines()
        if ln.strip() and not ln.strip().startswith('#')
    }


def build() -> dict:
    text = fetch_combined_filters()
    rewrites: Set[str] = set()
    skipped = 0
    dup_static = 0
    youtube_skipped = 0
    static_keys = _static_rewrite_keys()

    for line in iter_filter_rules(text):
        rewrite = _abp_line_to_rewrite(line)
        if rewrite is None:
            skipped += 1
            continue
        if is_youtube_rewrite_rule(rewrite):
            youtube_skipped += 1
            continue
        if rewrite in static_keys:
            dup_static += 1
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
    log(
        f'ad_rewrite: {len(rewrites)} lines '
        f'({skipped} not converted, {dup_static} dup static, '
        f'{youtube_skipped} youtube skipped)'
    )
    return {
        'rewrites': len(rewrites),
        'skipped': skipped,
        'dup_static': dup_static,
        'youtube_skipped': youtube_skipped,
    }


def main() -> int:
    build()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
