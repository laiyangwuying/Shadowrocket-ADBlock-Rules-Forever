# -*- coding: utf-8 -*-
"""审计 dns.txt 明文 || 规则是否完整写入 ad.set。"""

from __future__ import annotations

from ad import _DOMAIN_RE, _load_ignore, _strip_host
from ad_filters import fetch_cats_team_dns, iter_filter_rules, should_skip_scoped_options, split_rule_options
from build_util import RESULTANT_DIR, log, read_entries
from idna_util import is_ip_host, normalize_hostname


def _is_plain_pipe_pattern(pattern: str) -> bool:
    if not pattern.startswith('||'):
        return False
    body = _strip_host(pattern[2:])
    return bool(body) and '*' not in body and '/' not in body and '|' not in body


def _eligible_plain_hosts() -> tuple[list[str], list[tuple[str, str]]]:
    ignore = _load_ignore()
    expected: list[str] = []
    missing: list[tuple[str, str]] = []
    ad_set = {entry.lower() for entry in read_entries(RESULTANT_DIR / 'ad.set')}

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

        body = _strip_host(pattern[2:])
        if not body or body.startswith('.') or body in ignore:
            continue

        normalized = normalize_hostname(body, source='audit_ad_dns')
        if normalized is None:
            continue
        if not is_ip_host(normalized) and (
            '.' not in normalized or not _DOMAIN_RE.match(normalized)
        ):
            continue

        expected.append(normalized)
        if normalized.lower() not in ad_set:
            missing.append((row, normalized))

    return expected, missing


def audit(*, max_log: int = 20) -> dict:
    expected, missing = _eligible_plain_hosts()
    result = {
        'expected_plain_hosts': len(expected),
        'missing_count': len(missing),
        'missing_samples': missing[:max_log],
    }
    if missing:
        log(f'audit_ad_dns: {len(missing)} plain dns.txt hosts missing from ad.set')
        for row, host in missing[:max_log]:
            log(f'  missing: {host} <- {row}')
        if len(missing) > max_log:
            log(f'  ... and {len(missing) - max_log} more')
    else:
        log(
            f'audit_ad_dns: ok, {len(expected)} plain || hosts covered in ad.set'
        )
    return result


def main() -> int:
    result = audit()
    return 1 if result['missing_count'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
