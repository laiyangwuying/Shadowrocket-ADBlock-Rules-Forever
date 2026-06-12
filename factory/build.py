#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""统一构建入口：vendor 拉取 → ad/gfw 并行 → 生成 conf。"""

from __future__ import annotations

import argparse
import sys
import time

from build_util import log, run_parallel

import ad
import ad_cats_team
import ad_module
import build_confs
import fetch_vendor_modules
import gfwlist
import lazy_deploy
import qr_figure


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

    stats['ad_cats_team'] = ad_cats_team.build()
    stats['ad_module'] = ad_module.build()
    stats['build_confs'] = build_confs.build()
    stats['lazy'] = lazy_deploy.publish()
    stats['qr_figure'] = qr_figure.build()

    elapsed = time.perf_counter() - t0
    log(f'=== build finished in {elapsed:.1f}s ===')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
