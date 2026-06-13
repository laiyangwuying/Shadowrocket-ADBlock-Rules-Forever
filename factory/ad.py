# -*- coding: utf-8 -*-
#
# 从 Cats-Team AdRules dns.txt 生成 conf 用广告列表：
# - ad.set          → DOMAIN-SET（域名 REJECT）
# - ad_host.set     → [Host] 解析到 0.0.0.0（接近 DNS 过滤）
# - ad_keyword.list → DOMAIN-KEYWORD（由 dns.txt 正则规则转换）

from __future__ import annotations

import re
import time
from typing import Set

from ad_block_util import is_dedicated_module_host
from ad_filters import (
    CATS_TEAM_DNS_URL,
    fetch_cats_team_dns,
    iter_filter_rules,
    should_skip_scoped_options,
    split_rule_options,
)
from build_util import RESULTANT_DIR, atomic_write, log, read_entries, write_list
from idna_util import drain_corrections, is_ip_host, normalize_hostname, write_corrections_log

_DOMAIN_RE = re.compile(
    r'^\.?[a-zA-Z0-9][-a-zA-Z0-9]{0,62}'
    r'(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})*\.[a-zA-Z0-9][-a-zA-Z0-9]{1,}$'
)
_REGEX_KEYWORD_RE = re.compile(r'^/\^(.+?)\\\.')
_KEYWORD_LITERAL_RE = re.compile(r'^[a-zA-Z0-9_-]{3,}$')
_HOST_UNSAFE_RE = re.compile(r'[/^:|]')


def _load_ignore() -> set[str]:
    path = RESULTANT_DIR / 'ad_ignore.list'
    if not path.is_file():
        return set()
    return set(read_entries(path))


def _strip_host(body: str) -> str:
    body = body.rstrip('^')
    body = re.sub(r':\d{2,5}$', '', body)
    return body


def _parse_row(
    row: str,
    domains: Set[str],
    host_patterns: Set[str],
    keywords: Set[str],
    ignore: set[str],
    stats: dict[str, int] | None = None,
) -> int:
    """解析一行；返回 1 表示因 IDNA 无效而跳过。"""
    if row.startswith('@@'):
        for collection in (domains, host_patterns, keywords):
            to_remove = [d for d in collection if d in row]
            for d in to_remove:
                collection.discard(d)
        return 0

    if not row or '##' in row or '#@#' in row or '#?#' in row:
        return 0

    if row.startswith('/'):
        m = _REGEX_KEYWORD_RE.match(row)
        if m:
            kw = m.group(1).replace('\\', '').strip()
            if _KEYWORD_LITERAL_RE.match(kw) and kw not in ignore:
                keywords.add(kw)
        return 0

    pattern, opts = split_rule_options(row)
    if not pattern.startswith('||'):
        return 0
    if should_skip_scoped_options(opts):
        if stats is not None:
            stats['scoped_skipped'] = stats.get('scoped_skipped', 0) + 1
        return 0
    if stats is not None:
        stats['pipe_eligible'] = stats.get('pipe_eligible', 0) + 1

    body = _strip_host(pattern[2:])
    if not body or '/' in body:
        return 0

    if body.startswith('.'):
        body = body[1:]

    if '*' in body:
        if body.endswith('.*'):
            return 0
        if not _HOST_UNSAFE_RE.search(body.replace('*', '')):
            host_patterns.add(body)
        return 0

    if _HOST_UNSAFE_RE.search(body):
        return 0
    if body in ignore:
        return 0

    normalized = normalize_hostname(body, source='ad')
    if normalized is None:
        return 1
    if is_dedicated_module_host(normalized):
        if stats is not None:
            stats['dedicated_skipped'] = stats.get('dedicated_skipped', 0) + 1
        return 0

    if is_ip_host(normalized):
        domains.add(normalized)
    elif '.' in normalized and _DOMAIN_RE.match(normalized):
        domains.add(normalized)
    return 0


def _write_plain_set(path, header: str, items: Set[str]) -> int:
    lines = sorted(items)
    body = header.rstrip('\n') + '\n' + '\n'.join(lines) + '\n'
    atomic_write(path, body)
    return len(lines)


def build() -> dict:
    ignore = _load_ignore()
    rule = fetch_cats_team_dns()

    domains: Set[str] = set()
    host_patterns: Set[str] = set()
    keywords: Set[str] = set()
    idna_skipped = 0
    dns_rule_lines = 0
    parse_stats: dict[str, int] = {}

    for row in iter_filter_rules(rule):
        dns_rule_lines += 1
        idna_skipped += _parse_row(
            row, domains, host_patterns, keywords, ignore, parse_stats
        )

    domains = {d for d in domains if not is_dedicated_module_host(d)}
    stamp = time.strftime('%Y-%m-%d %H:%M:%S')
    header_common = (
        f'# Cats-Team AdRules dns.txt @ {stamp}\n'
        f'# source: {CATS_TEAM_DNS_URL}'
    )

    domain_count = _write_plain_set(
        RESULTANT_DIR / 'ad.set',
        header_common + '\n# format: one hostname per line (DOMAIN-SET)',
        domains,
    )
    wildcard_hosts = sorted(f'{pattern} = 0.0.0.0' for pattern in host_patterns)
    atomic_write(
        RESULTANT_DIR / 'ad_host_wildcard.set',
        header_common + '\n# dns.txt 通配符 → [Host] 解析拦截\n'
        + '\n'.join(wildcard_hosts)
        + ('\n' if wildcard_hosts else ''),
    )
    keyword_count = write_list(
        RESULTANT_DIR / 'ad_keyword.list',
        header_common + '\n# from dns.txt /^keyword\\./ regex rules',
        keywords,
    )

    # 兼容旧引用与 build_summary 统计
    legacy_header = header_common + '\n# legacy ad.list mirror of ad.set'
    write_list(RESULTANT_DIR / 'ad.list', legacy_header, domains)

    write_corrections_log(
        str(RESULTANT_DIR / 'idna_corrections.log'),
        drain_corrections(),
        append=False,
    )
    log(
        f'ad: {domain_count} domains, {len(host_patterns)} host wildcards, '
        f'{keyword_count} keywords, {idna_skipped} idna-skipped'
    )
    pipe_eligible = parse_stats.get('pipe_eligible', 0)
    dedicated_skipped = parse_stats.get('dedicated_skipped', 0)
    scoped_skipped = parse_stats.get('scoped_skipped', 0)
    coverage_gap = max(
        0,
        pipe_eligible
        - domain_count
        - len(host_patterns)
        - dedicated_skipped
        - idna_skipped,
    )
    return {
        'domains': domain_count,
        'host_patterns': len(host_patterns),
        'keywords': keyword_count,
        'idna_skipped': idna_skipped,
        'dns_rule_lines': dns_rule_lines,
        'pipe_eligible': pipe_eligible,
        'dedicated_skipped': dedicated_skipped,
        'scoped_skipped': scoped_skipped,
        'coverage_gap': coverage_gap,
    }


def main() -> int:
    build()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
