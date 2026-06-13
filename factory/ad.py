# -*- coding: utf-8 -*-
#
# 从 Cats-Team AdRules dns.txt 生成 conf 用广告列表：
# - ad.set                 → DOMAIN-SET（||domain^、||host^）
# - ad_host_wildcard.set   → [Host]（||.domain^ → *.domain；||* 通配符）
# - ad_keyword.list        → DOMAIN-KEYWORD（/^keyword\./ 正则）

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Set

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


def to_domain_set_line(domain: str) -> str:
    """AdGuard `||domain^` / `||host^` → DOMAIN-SET `.domain`（自身 + 全部子域）。"""
    if is_ip_host(domain):
        return domain
    bare = domain.lower().strip('.')
    return f'.{bare}'


def to_subdomain_only_host_pattern(domain: str) -> str:
    """AdGuard `||.domain^` → [Host] `*.domain`（仅子域，不含根域）。"""
    bare = domain.lower().strip('.')
    return f'*.{bare}'


def read_host_wildcard_patterns(path: str | Path | None = None) -> set[str]:
    """从 ad_host_wildcard.set 解析 `pattern = 0.0.0.0` 左侧通配符。"""
    file_path = Path(path or RESULTANT_DIR / 'ad_host_wildcard.set')
    if not file_path.is_file():
        return set()
    patterns: set[str] = set()
    for raw in file_path.read_text(encoding='utf-8').splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        patterns.add(line.split('=', 1)[0].strip().lower())
    return patterns


def domain_set_covers(host: str, entries: set[str]) -> bool:
    """请求域名是否被 ad.set 中任一条 DOMAIN-SET 规则覆盖。"""
    h = host.lower().strip('.')
    if not h:
        return False
    if h in entries or f'.{h}' in entries:
        return True
    for entry in entries:
        if not entry.startswith('.'):
            continue
        suffix = entry[1:]
        if h == suffix or h.endswith('.' + suffix):
            return True
    return False


def host_wildcard_covers(host: str, patterns: set[str]) -> bool:
    """请求域名是否被 `*.suffix` 覆盖（不含 suffix 根域本身）。"""
    h = host.lower().strip('.')
    if not h:
        return False
    for pat in patterns:
        if not pat.startswith('*.'):
            continue
        suffix = pat[2:]
        if h == suffix:
            continue
        if h.endswith('.' + suffix):
            return True
    return False


def dns_rule_covers(host: str, ad_set: set[str], host_wildcards: set[str]) -> bool:
    return domain_set_covers(host, ad_set) or host_wildcard_covers(host, host_wildcards)


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
    host_subdomain_only: Set[str],
    host_patterns: Set[str],
    keywords: Set[str],
    ignore: set[str],
    stats: dict[str, int] | None = None,
) -> int:
    """解析一行；返回 1 表示因 IDNA 无效而跳过。"""
    if row.startswith('@@'):
        for collection in (domains, host_subdomain_only, host_patterns, keywords):
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

    pipe_body = pattern[2:]
    subdomain_only = pipe_body.startswith('.')
    body = _strip_host(pipe_body)
    if subdomain_only:
        body = body.lstrip('.')

    if not body or '/' in body:
        return 0

    if '*' in body:
        if body.endswith('.*'):
            return 0
        if not _HOST_UNSAFE_RE.search(body.replace('*', '')):
            host_patterns.add(body)
            if stats is not None:
                stats['wildcard_hosts'] = stats.get('wildcard_hosts', 0) + 1
        return 0

    if _HOST_UNSAFE_RE.search(body):
        return 0
    if body in ignore:
        return 0

    normalized = normalize_hostname(body, source='ad')
    if normalized is None:
        return 1

    if is_ip_host(normalized):
        domains.add(normalized)
        if stats is not None:
            stats['ip_hosts'] = stats.get('ip_hosts', 0) + 1
        return 0

    if '.' not in normalized or not _DOMAIN_RE.match(normalized):
        return 0

    if subdomain_only:
        host_subdomain_only.add(to_subdomain_only_host_pattern(normalized))
        if stats is not None:
            stats['subdomain_only'] = stats.get('subdomain_only', 0) + 1
        return 0

    domains.add(normalized)
    if stats is not None:
        stats['suffix_hosts'] = stats.get('suffix_hosts', 0) + 1
    return 0


def _write_plain_set(path, header: str, items: Set[str]) -> int:
    lines = sorted(to_domain_set_line(item) for item in items)
    body = header.rstrip('\n') + '\n' + '\n'.join(lines) + '\n'
    atomic_write(path, body)
    return len(lines)


def _write_host_wildcard_set(
    path: Path,
    header: str,
    subdomain_only: Set[str],
    wildcards: Set[str],
) -> int:
    lines: list[str] = [header.rstrip('\n')]
    if subdomain_only:
        lines.append('# AdGuard ||.domain^ → *.domain（仅子域，不含根域）')
        lines.extend(f'{pat} = 0.0.0.0' for pat in sorted(subdomain_only))
    if wildcards:
        lines.append('# dns.txt 通配符 ||*...^')
        lines.extend(f'{pat} = 0.0.0.0' for pat in sorted(wildcards))
    body = '\n'.join(lines) + ('\n' if len(lines) > 1 else '')
    atomic_write(path, body)
    return len(subdomain_only) + len(wildcards)


def build() -> dict:
    ignore = _load_ignore()
    rule = fetch_cats_team_dns()

    domains: Set[str] = set()
    host_subdomain_only: Set[str] = set()
    host_patterns: Set[str] = set()
    keywords: Set[str] = set()
    idna_skipped = 0
    dns_rule_lines = 0
    parse_stats: dict[str, int] = {}

    for row in iter_filter_rules(rule):
        dns_rule_lines += 1
        idna_skipped += _parse_row(
            row,
            domains,
            host_subdomain_only,
            host_patterns,
            keywords,
            ignore,
            parse_stats,
        )

    stamp = time.strftime('%Y-%m-%d %H:%M:%S')
    header_common = (
        f'# Cats-Team AdRules dns.txt @ {stamp}\n'
        f'# source: {CATS_TEAM_DNS_URL}'
    )

    domain_count = _write_plain_set(
        RESULTANT_DIR / 'ad.set',
        header_common
        + '\n# ||domain^ / ||host^ → .domain（DOMAIN-SET，自身+子域）',
        domains,
    )
    host_line_count = _write_host_wildcard_set(
        RESULTANT_DIR / 'ad_host_wildcard.set',
        header_common,
        host_subdomain_only,
        host_patterns,
    )
    keyword_count = write_list(
        RESULTANT_DIR / 'ad_keyword.list',
        header_common + '\n# from dns.txt /^keyword\\./ regex rules',
        keywords,
    )

    legacy_header = header_common + '\n# legacy ad.list mirror of ad.set'
    write_list(
        RESULTANT_DIR / 'ad.list',
        legacy_header,
        {to_domain_set_line(item) for item in domains},
    )

    write_corrections_log(
        str(RESULTANT_DIR / 'idna_corrections.log'),
        drain_corrections(),
        append=False,
    )
    suffix_n = parse_stats.get('suffix_hosts', 0)
    subonly_n = parse_stats.get('subdomain_only', 0)
    wildcard_n = parse_stats.get('wildcard_hosts', 0)
    log(
        f'ad: {domain_count} DOMAIN-SET ({suffix_n} ||host^), '
        f'{subonly_n} subdomain-only Host, {wildcard_n} wildcard Host, '
        f'{keyword_count} keywords, {idna_skipped} idna-skipped'
    )
    pipe_eligible = parse_stats.get('pipe_eligible', 0)
    scoped_skipped = parse_stats.get('scoped_skipped', 0)
    coverage_gap = max(
        0,
        pipe_eligible
        - domain_count
        - len(host_subdomain_only)
        - len(host_patterns)
        - idna_skipped,
    )
    return {
        'domains': domain_count,
        'host_patterns': host_line_count,
        'host_subdomain_only': len(host_subdomain_only),
        'keywords': keyword_count,
        'idna_skipped': idna_skipped,
        'dns_rule_lines': dns_rule_lines,
        'pipe_eligible': pipe_eligible,
        'scoped_skipped': scoped_skipped,
        'coverage_gap': coverage_gap,
        'suffix_hosts': suffix_n,
        'subdomain_only': subonly_n,
        'wildcard_hosts': wildcard_n,
    }


def main() -> int:
    build()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
