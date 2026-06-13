# -*- coding: utf-8 -*-
#
# Cats-Team dns.txt → Shadowrocket 规则（AdGuard DNS 语法）：
#   ||domain^     → RULE-SET DOMAIN-SUFFIX,domain,REJECT
#   ||.domain^    → RULE-SET DOMAIN-WILDCARD,*.domain,REJECT + [Host]
#   IP host       → RULE-SET DOMAIN,host,REJECT（精确）
#   /regex/       → ad_keyword；@@ 按文件顺序解除

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
from sr_policy import REJECT_EXTS

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


def to_rule_set_suffix(domain: str) -> str:
    """AdGuard `||domain^` → DOMAIN-SUFFIX（匹配自身及全部子域）。"""
    return f'DOMAIN-SUFFIX,{domain.lower().strip(".")},REJECT{REJECT_EXTS}'


def to_rule_set_exact(domain: str) -> str:
    """AdGuard `127.0.0.1 domain` → DOMAIN（仅精确匹配）。"""
    return f'DOMAIN,{domain.lower().strip(".")},REJECT{REJECT_EXTS}'


def to_rule_set_ip(ip: str) -> str:
    host = ip.split('/')[0]
    if ':' in host:
        return f'IP-CIDR,{ip if "/" in ip else ip + "/128"},REJECT,no-resolve{REJECT_EXTS}'
    return f'IP-CIDR,{ip if "/" in ip else ip + "/32"},REJECT,no-resolve{REJECT_EXTS}'


def to_rule_set_wildcard(pattern: str) -> str:
    return f'DOMAIN-WILDCARD,{pattern.lower()},REJECT{REJECT_EXTS}'


def to_subdomain_only_host_pattern(domain: str) -> str:
    """AdGuard `||.domain^` → [Host] `*.domain`（仅子域，不含根域）。"""
    bare = domain.lower().strip('.')
    return f'*.{bare}'


def suffix_rule_covers(host: str, suffix_domains: set[str]) -> bool:
    """等同 Shadowrocket DOMAIN-SUFFIX 语义。"""
    h = host.lower().strip('.')
    if not h:
        return False
    for suffix in suffix_domains:
        s = suffix.lower().strip('.')
        if h == s or h.endswith('.' + s):
            return True
    return False


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


def load_rule_set_coverage(
    path: str | Path | None = None,
) -> tuple[set[str], set[str], set[str]]:
    """解析 ad.rule-set → (suffix_domains, exact_hosts, wildcards)。"""
    file_path = Path(path or RESULTANT_DIR / 'ad.rule-set')
    suffix_domains: set[str] = set()
    exact_hosts: set[str] = set()
    wildcards: set[str] = set()
    if not file_path.is_file():
        return suffix_domains, exact_hosts, wildcards
    for raw in file_path.read_text(encoding='utf-8').splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        parts = [p.strip() for p in line.split(',')]
        if len(parts) < 2:
            continue
        kind, value = parts[0].upper(), parts[1].lower()
        if kind == 'DOMAIN-SUFFIX':
            suffix_domains.add(value)
        elif kind == 'DOMAIN':
            exact_hosts.add(value)
        elif kind == 'DOMAIN-WILDCARD':
            wildcards.add(value)
    return suffix_domains, exact_hosts, wildcards


def dns_outputs_covers(
    host: str,
    suffix_domains: set[str],
    exact_hosts: set[str],
    wildcards: set[str],
) -> bool:
    h = host.lower().strip('.')
    if h in exact_hosts:
        return True
    if suffix_rule_covers(h, suffix_domains):
        return True
    return host_wildcard_covers(h, wildcards)


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


def rule_set_lines(outputs: DnsOutputs) -> list[str]:
    lines: list[str] = []
    for domain in sorted(outputs.suffix_domains):
        lines.append(to_rule_set_suffix(domain))
    for host in sorted(outputs.exact_hosts):
        if host not in outputs.suffix_domains:
            lines.append(to_rule_set_exact(host))
    for ip in sorted(outputs.ip_hosts):
        lines.append(to_rule_set_ip(ip))
    for pat in sorted(outputs.host_subdomain_only):
        lines.append(to_rule_set_wildcard(pat))
    for pat in sorted(outputs.host_patterns):
        lines.append(to_rule_set_wildcard(pat))
    return lines


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


def _write_rule_set(path: Path, header: str, outputs: DnsOutputs) -> int:
    lines = rule_set_lines(outputs)
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

    rule_count = _write_rule_set(
        RESULTANT_DIR / 'ad.rule-set',
        header_common
        + '\n# ||domain^→DOMAIN-SUFFIX | hosts→DOMAIN | ||.^→DOMAIN-WILDCARD',
        outputs,
    )
    # 兼容统计：纯域名列表
    write_list(
        RESULTANT_DIR / 'ad.set',
        header_common + '\n# legacy domain list (conf 使用 ad.rule-set)',
        outputs.suffix_domains | outputs.exact_hosts | outputs.ip_hosts,
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
        header_common + '\n# legacy mirror of ad.set',
        outputs.suffix_domains | outputs.exact_hosts | outputs.ip_hosts,
    )

    write_corrections_log(
        str(RESULTANT_DIR / 'idna_corrections.log'),
        drain_corrections(),
        append=False,
    )

    st = outputs.stats
    log(
        f'ad: {rule_count} RULE-SET lines '
        f'({st.get("suffix_hosts", 0)} DOMAIN-SUFFIX, {st.get("exact_hosts", 0)} DOMAIN, '
        f'{st.get("ip_hosts", 0)} IP, {st.get("subdomain_only", 0)} ||.^ wildcard, '
        f'{st.get("wildcard_hosts", 0)} ||* wildcard), '
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
        'domains': rule_count,
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
