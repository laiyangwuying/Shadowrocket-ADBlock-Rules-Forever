# -*- coding: utf-8 -*-
#
# Cats-Team dns.txt → Shadowrocket 规则（AdGuard DNS 语法）：
#   ||domain^     → ad.set `.domain`（自身+子域）
#   ||.domain^    → ad_host `*.domain`（仅子域）
#   IP host       → ad.set `host`（精确，不含子域）
#   /regex/       → ad_keyword（简单 /^kw\./）或跳过复杂正则
#   @@...         → 按文件顺序解除对应拦截

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Set

from ad_filters import (
    CATS_TEAM_DNS_URL,
    fetch_cats_team_dns,
    iter_dns_lines,
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
_HOSTS_FILE_RE = re.compile(
    r'^(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s+(?P<host>\S+)$'
)


@dataclass
class DnsOutputs:
    suffix_domains: Set[str] = field(default_factory=set)
    exact_hosts: Set[str] = field(default_factory=set)
    ip_hosts: Set[str] = field(default_factory=set)
    host_subdomain_only: Set[str] = field(default_factory=set)
    host_patterns: Set[str] = field(default_factory=set)
    keywords: Set[str] = field(default_factory=set)
    stats: dict[str, int] = field(default_factory=dict)
    idna_skipped: int = 0
    dns_rule_lines: int = 0


def to_domain_set_line(domain: str) -> str:
    """AdGuard `||domain^` / `||host^` → DOMAIN-SET `.domain`（自身 + 全部子域）。"""
    if is_ip_host(domain):
        return domain
    bare = domain.lower().strip('.')
    return f'.{bare}'


def to_exact_domain_set_line(domain: str) -> str:
    """AdGuard `127.0.0.1 domain` → DOMAIN-SET 精确行（不含子域）。"""
    return domain.lower().strip('.')


def to_subdomain_only_host_pattern(domain: str) -> str:
    """AdGuard `||.domain^` → [Host] `*.domain`（仅子域，不含根域）。"""
    bare = domain.lower().strip('.')
    return f'*.{bare}'


def read_host_wildcard_patterns(path: str | Path | None = None) -> set[str]:
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
    h = host.lower().strip('.')
    if not h:
        return False
    if h in entries:
        return True
    if f'.{h}' in entries:
        return True
    for entry in entries:
        if not entry.startswith('.'):
            continue
        suffix = entry[1:]
        if h == suffix or h.endswith('.' + suffix):
            return True
    return False


def host_wildcard_covers(host: str, patterns: set[str]) -> bool:
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


def ad_set_lines(outputs: DnsOutputs) -> set[str]:
    lines = {to_domain_set_line(d) for d in outputs.suffix_domains}
    lines.update(to_exact_domain_set_line(h) for h in outputs.exact_hosts)
    lines.update(outputs.ip_hosts)
    return {line.lower() for line in lines}


def _load_ignore() -> set[str]:
    path = RESULTANT_DIR / 'ad_ignore.list'
    if not path.is_file():
        return set()
    return set(read_entries(path))


def _strip_host(body: str) -> str:
    body = body.rstrip('^')
    body = re.sub(r':\d{2,5}$', '', body)
    return body


def _bump(stats: dict[str, int] | None, key: str, n: int = 1) -> None:
    if stats is not None:
        stats[key] = stats.get(key, 0) + n


def _remove_suffix_coverage(host: str, outputs: DnsOutputs) -> None:
    h = host.lower().strip('.')
    for d in list(outputs.suffix_domains):
        if d == h or d.endswith('.' + h):
            outputs.suffix_domains.discard(d)
    for d in list(outputs.exact_hosts):
        if d == h or d.endswith('.' + h):
            outputs.exact_hosts.discard(d)


def _parse_regex_row(
    row: str,
    keywords: Set[str],
    ignore: set[str],
    stats: dict[str, int] | None,
    *,
    subtract: bool = False,
) -> int:
    m = _REGEX_KEYWORD_RE.match(row)
    if m:
        kw = m.group(1).replace('\\', '').strip()
        if _KEYWORD_LITERAL_RE.match(kw) and kw not in ignore:
            if subtract:
                keywords.discard(kw)
            else:
                keywords.add(kw)
                _bump(stats, 'regex_keywords')
            return 0
    if not subtract:
        _bump(stats, 'regex_skipped')
    return 0


def _parse_hosts_file_row(
    row: str,
    outputs: DnsOutputs,
    ignore: set[str],
    *,
    subtract: bool = False,
) -> int:
    m = _HOSTS_FILE_RE.match(row)
    if not m:
        return 0
    host = m.group('host')
    if host in ignore:
        return 0
    normalized = normalize_hostname(host, source='ad')
    if normalized is None:
        return 1
    if is_ip_host(normalized):
        return 0
    if '.' not in normalized or not _DOMAIN_RE.match(normalized):
        return 0
    if subtract:
        outputs.exact_hosts.discard(normalized)
        _bump(outputs.stats, 'exceptions')
    else:
        outputs.exact_hosts.add(normalized)
        outputs.suffix_domains.discard(normalized)
        _bump(outputs.stats, 'exact_hosts')
    return 0


def _parse_pipe_row(
    row: str,
    outputs: DnsOutputs,
    ignore: set[str],
    *,
    subtract: bool = False,
) -> int:
    pattern, opts = split_rule_options(row)
    if not pattern.startswith('||'):
        return 0
    if should_skip_scoped_options(opts):
        if not subtract:
            _bump(outputs.stats, 'scoped_skipped')
        return 0
    if not subtract:
        _bump(outputs.stats, 'pipe_eligible')

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
            if subtract:
                outputs.host_patterns.discard(body)
            else:
                outputs.host_patterns.add(body)
                _bump(outputs.stats, 'wildcard_hosts')
        return 0

    if _HOST_UNSAFE_RE.search(body):
        return 0
    if body in ignore:
        return 0

    normalized = normalize_hostname(body, source='ad')
    if normalized is None:
        return 1

    if is_ip_host(normalized):
        if subtract:
            outputs.ip_hosts.discard(normalized)
        else:
            outputs.ip_hosts.add(normalized)
            _bump(outputs.stats, 'ip_hosts')
        return 0

    if '.' not in normalized or not _DOMAIN_RE.match(normalized):
        return 0

    if subdomain_only:
        pat = to_subdomain_only_host_pattern(normalized)
        if subtract:
            outputs.host_subdomain_only.discard(pat)
            _bump(outputs.stats, 'exceptions')
        else:
            outputs.host_subdomain_only.add(pat)
            _bump(outputs.stats, 'subdomain_only')
        return 0

    if subtract:
        outputs.suffix_domains.discard(normalized)
        outputs.exact_hosts.discard(normalized)
        _remove_suffix_coverage(normalized, outputs)
        _bump(outputs.stats, 'exceptions')
    else:
        outputs.suffix_domains.add(normalized)
        outputs.exact_hosts.discard(normalized)
        _bump(outputs.stats, 'suffix_hosts')
    return 0


def _process_dns_row(
    row: str,
    outputs: DnsOutputs,
    ignore: set[str],
) -> int:
    if row.startswith('@@'):
        inner = row[2:].strip()
        if inner.startswith('/'):
            return _parse_regex_row(
                inner, outputs.keywords, ignore, outputs.stats, subtract=True
            )
        if _HOSTS_FILE_RE.match(inner):
            return _parse_hosts_file_row(inner, outputs, ignore, subtract=True)
        return _parse_pipe_row(inner, outputs, ignore, subtract=True)

    if row.startswith('/'):
        return _parse_regex_row(row, outputs.keywords, ignore, outputs.stats)

    if _HOSTS_FILE_RE.match(row):
        return _parse_hosts_file_row(row, outputs, ignore)

    if '##' in row or '#@#' in row or '#?#' in row:
        return 0

    return _parse_pipe_row(row, outputs, ignore)


def collect_dns_outputs(text: str, *, ignore: set[str] | None = None) -> DnsOutputs:
    ignore = ignore or _load_ignore()
    outputs = DnsOutputs()
    for row in iter_dns_lines(text):
        outputs.dns_rule_lines += 1
        outputs.idna_skipped += _process_dns_row(row, outputs, ignore)
    return outputs


def _write_plain_set(path: Path, header: str, outputs: DnsOutputs) -> int:
    lines = sorted(to_domain_set_line(d) for d in outputs.suffix_domains)
    lines.extend(
        sorted(
            to_exact_domain_set_line(h)
            for h in outputs.exact_hosts
            if h not in outputs.suffix_domains
        )
    )
    lines.extend(sorted(outputs.ip_hosts))
    body = header.rstrip('\n') + '\n' + '\n'.join(lines) + '\n'
    atomic_write(path, body)
    return len(lines)


def _write_host_wildcard_set(path: Path, header: str, outputs: DnsOutputs) -> int:
    lines: list[str] = [header.rstrip('\n')]
    if outputs.host_subdomain_only:
        lines.append('# AdGuard ||.domain^ → *.domain（仅子域，不含根域）')
        lines.extend(
            f'{pat} = 0.0.0.0' for pat in sorted(outputs.host_subdomain_only)
        )
    if outputs.host_patterns:
        lines.append('# dns.txt 通配符 ||*...^')
        lines.extend(f'{pat} = 0.0.0.0' for pat in sorted(outputs.host_patterns))
    body = '\n'.join(lines) + ('\n' if len(lines) > 1 else '')
    atomic_write(path, body)
    return len(outputs.host_subdomain_only) + len(outputs.host_patterns)


def build() -> dict:
    outputs = collect_dns_outputs(fetch_cats_team_dns())
    stamp = time.strftime('%Y-%m-%d %H:%M:%S')
    header_common = (
        f'# Cats-Team AdRules dns.txt @ {stamp}\n'
        f'# source: {CATS_TEAM_DNS_URL}'
    )

    domain_count = _write_plain_set(
        RESULTANT_DIR / 'ad.set',
        header_common
        + '\n# ||domain^→.domain | IP host→exact | 127.0.0.1 host→exact',
        outputs,
    )
    host_line_count = _write_host_wildcard_set(
        RESULTANT_DIR / 'ad_host_wildcard.set',
        header_common,
        outputs,
    )
    keyword_count = write_list(
        RESULTANT_DIR / 'ad_keyword.list',
        header_common + '\n# /regex/ 中可转为 DOMAIN-KEYWORD 的简单规则',
        outputs.keywords,
    )

    write_list(
        RESULTANT_DIR / 'ad.list',
        header_common + '\n# legacy ad.list mirror of ad.set',
        ad_set_lines(outputs),
    )

    write_corrections_log(
        str(RESULTANT_DIR / 'idna_corrections.log'),
        drain_corrections(),
        append=False,
    )

    st = outputs.stats
    log(
        f'ad: {domain_count} DOMAIN-SET '
        f'({st.get("suffix_hosts", 0)} ||^, {st.get("exact_hosts", 0)} hosts, '
        f'{st.get("ip_hosts", 0)} IP), '
        f'{st.get("subdomain_only", 0)} ||.^ Host, '
        f'{st.get("wildcard_hosts", 0)} wildcard Host, '
        f'{st.get("exceptions", 0)} @@ exceptions, '
        f'{keyword_count} keywords, {outputs.idna_skipped} idna-skipped'
    )
    pipe_eligible = st.get('pipe_eligible', 0)
    coverage_gap = max(
        0,
        pipe_eligible
        - len(outputs.suffix_domains)
        - len(outputs.host_subdomain_only)
        - len(outputs.host_patterns)
        - outputs.idna_skipped,
    )
    return {
        'domains': domain_count,
        'host_patterns': host_line_count,
        'host_subdomain_only': len(outputs.host_subdomain_only),
        'keywords': keyword_count,
        'idna_skipped': outputs.idna_skipped,
        'dns_rule_lines': outputs.dns_rule_lines,
        'pipe_eligible': pipe_eligible,
        'scoped_skipped': st.get('scoped_skipped', 0),
        'coverage_gap': coverage_gap,
        'suffix_hosts': st.get('suffix_hosts', 0),
        'exact_hosts': st.get('exact_hosts', 0),
        'subdomain_only': st.get('subdomain_only', 0),
        'wildcard_hosts': st.get('wildcard_hosts', 0),
        'exceptions': st.get('exceptions', 0),
    }


def main() -> int:
    build()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
