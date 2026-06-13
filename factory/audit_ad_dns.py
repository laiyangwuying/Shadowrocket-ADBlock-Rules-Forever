# -*- coding: utf-8 -*-
"""审计 dns.txt 是否按 AdGuard DNS 语法正确写入 ad.rule-set / Host 通配符。"""

from __future__ import annotations

from ad import (
    _load_ignore,
    collect_dns_outputs,
    read_host_wildcard_patterns,
    rule_set_lines,
)
from ad_filters import fetch_cats_team_dns
from build_util import RESULTANT_DIR, log


def _read_rule_set_lines(path) -> set[str]:
    lines: set[str] = set()
    if not path.is_file():
        return lines
    for raw in path.read_text(encoding='utf-8').splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        lines.add(line)
    return lines


def audit(*, max_log: int = 20) -> dict:
    expected = collect_dns_outputs(fetch_cats_team_dns(), ignore=_load_ignore())
    actual = _read_rule_set_lines(RESULTANT_DIR / 'ad.rule-set')
    host_wildcards = read_host_wildcard_patterns()
    expected_lines = set(rule_set_lines(expected))

    missing: list[tuple[str, str]] = []
    if expected_lines != actual:
        for line in sorted(expected_lines - actual)[:max_log]:
            missing.append(('expected in ad.rule-set', line))
        for line in sorted(actual - expected_lines)[:max_log]:
            missing.append(('unexpected in ad.rule-set', line))

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
    total = len(expected_lines)
    result = {
        'expected_rule_set_lines': total,
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
            f'audit_ad_dns: ok, {total} RULE-SET lines '
            f'({counts["suffix_hosts"]} DOMAIN-SUFFIX, {counts["exact_hosts"]} DOMAIN, '
            f'{counts["ip_hosts"]} IP, {counts["subdomain_only"]} ||.^, '
            f'{counts["exceptions"]} @@, {counts["regex_keywords"]} regex-kw)'
        )
    return result


def main() -> int:
    result = audit()
    return 1 if result['missing_count'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
