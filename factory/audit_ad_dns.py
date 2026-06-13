# -*- coding: utf-8 -*-
"""审计 dns.txt 明文 || 规则是否按 AdGuard 语义写入 ad.set / Host 通配符。"""

from __future__ import annotations

from ad import (
    _DOMAIN_RE,
    _load_ignore,
    _strip_host,
    domain_set_covers,
    host_wildcard_covers,
    read_host_wildcard_patterns,
    to_domain_set_line,
    to_subdomain_only_host_pattern,
)
from ad_filters import fetch_cats_team_dns, iter_filter_rules, should_skip_scoped_options, split_rule_options
from build_util import RESULTANT_DIR, log, read_entries
from idna_util import is_ip_host, normalize_hostname


def _is_plain_pipe_pattern(pattern: str) -> bool:
    if not pattern.startswith('||'):
        return False
    body = _strip_host(pattern[2:])
    return bool(body) and '*' not in body and '/' not in body and '|' not in body


def _audit_rules() -> tuple[dict[str, int], list[tuple[str, str]]]:
    ignore = _load_ignore()
    ad_set = {entry.lower() for entry in read_entries(RESULTANT_DIR / 'ad.set')}
    host_wildcards = read_host_wildcard_patterns()
    counts = {
        'suffix_hosts': 0,
        'subdomain_only': 0,
        'ip_hosts': 0,
    }
    missing: list[tuple[str, str]] = []

    for row in iter_filter_rules(fetch_cats_team_dns()):
        if row.startswith('@@') or row.startswith('/'):
            continue
        pattern, opts = split_rule_options(row)
        if not pattern.startswith('||'):
            continue
        if should_skip_scoped_options(opts):
            continue
        if not _is_plain_pipe_pattern(pattern):
            continue

        subdomain_only = pattern[2:].startswith('.')
        body = _strip_host(pattern[2:])
        if subdomain_only:
            body = body.lstrip('.')
        if not body or body in ignore:
            continue

        normalized = normalize_hostname(body, source='audit_ad_dns')
        if normalized is None:
            continue
        if not is_ip_host(normalized) and (
            '.' not in normalized or not _DOMAIN_RE.match(normalized)
        ):
            continue

        if subdomain_only:
            counts['subdomain_only'] += 1
            pat = to_subdomain_only_host_pattern(normalized)
            if pat not in host_wildcards:
                missing.append((row, pat))
            continue

        if is_ip_host(normalized):
            counts['ip_hosts'] += 1
            if normalized.lower() not in ad_set:
                missing.append((row, normalized))
            continue

        counts['suffix_hosts'] += 1
        if not domain_set_covers(normalized, ad_set):
            missing.append((row, to_domain_set_line(normalized)))

    return counts, missing


def audit(*, max_log: int = 20) -> dict:
    counts, missing = _audit_rules()
    total = sum(counts.values())
    result = {
        'expected_plain_hosts': total,
        'missing_count': len(missing),
        'missing_samples': missing[:max_log],
        **counts,
    }
    if missing:
        log(f'audit_ad_dns: {len(missing)} dns.txt rules not reflected in outputs')
        for row, detail in missing[:max_log]:
            log(f'  missing: {detail} <- {row}')
        if len(missing) > max_log:
            log(f'  ... and {len(missing) - max_log} more')
    else:
        log(
            f'audit_ad_dns: ok, {total} plain || rules '
            f'({counts["suffix_hosts"]} DOMAIN-SET, '
            f'{counts["subdomain_only"]} subdomain-only Host, '
            f'{counts["ip_hosts"]} IP)'
        )
    return result


def main() -> int:
    result = audit()
    return 1 if result['missing_count'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
