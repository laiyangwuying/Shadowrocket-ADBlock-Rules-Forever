#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""统一构建入口：vendor 拉取 → ad/gfw 并行 → 生成 conf。"""

from __future__ import annotations

import argparse
import sys
import time

from build_util import RESULTANT_DIR, atomic_write, log, read_entries, run_parallel

import ad
import ad_cats_team
import ad_module
import audit_ad_dns
import build_confs
import fetch_vendor_modules
import gfwlist
import vendor_scripts
import lazy_deploy
import qr_figure

_AD_COVERAGE_GAP_THRESHOLD = 500


def _coverage_gap(ad_stats: dict) -> int:
    return ad_stats.get('coverage_gap', 0)


def _write_build_summary(stats: dict, elapsed: float) -> None:
    ad = stats.get('ad') or {}
    bc = stats.get('build_confs') or {}
    vs = stats.get('vendor_scripts') or {}
    lines = [
        f'# build time: {time.strftime("%Y-%m-%d %H:%M:%S")}',
        f'total_sec: {elapsed:.1f}',
        f'vendor_sec: {stats.get("vendor_sec", 0):.1f}',
        f'vendor_scripts_sec: {stats.get("vendor_scripts_sec", 0):.1f}',
        f'parallel_sec: {stats.get("parallel_sec", 0):.1f}',
        f'confs: {bc.get("confs", 0)}',
        f'ad entries: {ad.get("domains", 0)}',
        f'ad host wildcards: {ad.get("host_patterns", 0)}',
        f'ad keywords: {ad.get("keywords", 0)}',
        f'ad idna skipped: {ad.get("idna_skipped", 0)}',
        f'ad dns rule lines: {ad.get("dns_rule_lines", 0)}',
        f'ad pipe eligible: {ad.get("pipe_eligible", 0)}',
        f'ad scoped skipped: {ad.get("scoped_skipped", 0)}',
        f'ad coverage gap: {_coverage_gap(ad)}',
        f'ad dns audit missing: {(stats.get("audit_ad_dns") or {}).get("missing_count", 0)}',
        f'manual_reject skipped (in rule-set): {bc.get("manual_reject_skipped", 0)}',
        f'cats-team rewrite: {(stats.get("ad_cats_team") or {}).get("rewrites", 0)}',
        f'gfw entries: {(stats.get("gfwlist") or {}).get("rules", 0)}',
        f'vendor_scripts mapped: {vs.get("mapped", 0)}',
        f'vendor_scripts modules rewritten: {vs.get("modules_rewritten", 0)}',
        f'vendor_scripts local files: {vs.get("local_scripts", 0)}',
    ]
    existing = RESULTANT_DIR / 'build_summary.txt'
    if existing.is_file():
        extra = [
            line
            for line in existing.read_text(encoding='utf-8').splitlines()
            if line.startswith('rule_set_url:')
        ]
        lines.extend(extra)
    atomic_write(existing, '\n'.join(lines) + '\n')


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Shadowrocket 规则构建')
    parser.add_argument(
        '--serial',
        action='store_true',
        help='禁用 ad/gfw 并行（调试用）',
    )
    args = parser.parse_args(argv)

    t0 = time.perf_counter()
    stats: dict = {}

    log('=== build start ===')

    log('[vendor] start')
    t_v = time.perf_counter()
    fetch_vendor_modules.main()
    stats['vendor_sec'] = time.perf_counter() - t_v
    log(f'[vendor] done in {stats["vendor_sec"]:.1f}s')

    log('[vendor_scripts] start')
    t_s = time.perf_counter()
    stats['vendor_scripts'] = vendor_scripts.build()
    stats['vendor_scripts_sec'] = time.perf_counter() - t_s
    log(f'[vendor_scripts] done in {stats["vendor_scripts_sec"]:.1f}s')

    if args.serial:
        stats['ad'] = ad.build()
        stats['gfwlist'] = gfwlist.build()
    else:
        log('[ad+gfwlist] parallel start')
        t_p = time.perf_counter()
        parallel = run_parallel({'ad': ad.build, 'gfwlist': gfwlist.build})
        stats.update(parallel)
        stats['parallel_sec'] = time.perf_counter() - t_p
        log(f'[ad+gfwlist] parallel done in {stats["parallel_sec"]:.1f}s')

    stats['audit_ad_dns'] = audit_ad_dns.audit()
    audit_missing = stats['audit_ad_dns'].get('missing_count', 0)

    stats['ad_cats_team'] = ad_cats_team.build()
    stats['ad_module'] = ad_module.build()
    stats['build_confs'] = build_confs.build()
    stats['lazy'] = lazy_deploy.publish()
    stats['qr_figure'] = qr_figure.build()

    gap = _coverage_gap(stats.get('ad') or {})
    if gap > _AD_COVERAGE_GAP_THRESHOLD:
        log(
            f'WARNING: ad.rule-set coverage gap {gap} exceeds threshold '
            f'{_AD_COVERAGE_GAP_THRESHOLD}'
        )

    elapsed = time.perf_counter() - t0
    _write_build_summary(stats, elapsed)
    log(f'=== build finished in {elapsed:.1f}s ===')
    if audit_missing:
        log(f'ERROR: ad.rule-set missing {audit_missing} dns.txt outputs')
        return 1
    return 1 if gap > _AD_COVERAGE_GAP_THRESHOLD else 0


if __name__ == '__main__':
    raise SystemExit(main())
