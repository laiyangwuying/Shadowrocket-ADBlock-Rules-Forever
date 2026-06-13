# -*- coding: utf-8 -*-
"""审计 dns.txt 是否按 AdGuard DNS 语法正确写入 ad.set / Host 通配符。"""

from __future__ import annotations

from ad import (
    _load_ignore,
    ad_set_lines,
    collect_dns_outputs,
    read_host_wildcard_patterns,
)
from ad_filters import fetch_cats_team_dns
from build_util import RESULTANT_DIR, log, read_entries


def audit(*, max_log: int = 20) -> dict:
    expected = collect_dns_outputs(fetch_cats_team_dns(), ignore=_load_ignore())
    ad_set = {entry.lower() for entry in read_entries(RESULTANT_DIR / 'ad.set')}
    host_wildcards = read_host_wildcard_patterns()
    expected_lines = ad_set_lines(expected)

    missing: list[tuple[str, str]] = []
    if expected_lines != ad_set:
        for line in sorted(expected_lines - ad_set)[:max_log]:
            missing.append(('expected in ad.set', line))
        for line in sorted(ad_set - expected_lines)[:max_log]:
            missing.append(('unexpected in ad.set', line))

    for pat in sorted(expected.host_subdomain_only):
        if pat not in host_wildcards:
            missing.append(('||.domain^', pat))

    for pat in sorted(expected.host_patterns):
        if pat not in host_wildcards:
            missing.append(('||wildcard^', pat))

    counts = {
        'suffix_hosts': expected.stats.get('suffix_hosts', 0),
        'exact_hosts': expected.stats.get('exact_hosts', 0),
        'ip_hosts': expected.stats.get('ip_hosts', 0),
        'subdomain_only': len(expected.host_subdomain_only),
        'exceptions': expected.stats.get('exceptions', 0),
        'regex_keywords': expected.stats.get('regex_keywords', 0),
        'regex_skipped': expected.stats.get('regex_skipped', 0),
    }
    total = counts['suffix_hosts'] + counts['exact_hosts'] + counts['ip_hosts']
    result = {
        'expected_plain_hosts': total,
        'missing_count': len(missing),
        'missing_samples': missing[:max_log],
        **counts,
    }
    if missing:
        log(f'audit_ad_dns: {len(missing)} dns.txt output mismatches')
        for row, detail in missing[:max_log]:
            log(f'  missing: {detail} <- {row}')
        if len(missing) > max_log:
            log(f'  ... and {len(missing) - max_log} more')
    else:
        log(
            f'audit_ad_dns: ok, {total} block rules '
            f'({counts["suffix_hosts"]} ||^ suffix, {counts["exact_hosts"]} hosts exact, '
            f'{counts["ip_hosts"]} IP, {counts["subdomain_only"]} ||.^, '
            f'{counts["exceptions"]} @@, {counts["regex_keywords"]} regex-kw)'
        )
    return result


def main() -> int:
    result = audit()
    return 1 if result['missing_count'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
