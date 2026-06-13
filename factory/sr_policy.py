# -*- coding: utf-8 -*-
"""Shadowrocket 规则策略与扩展参数（对齐 LOWERTOP 使用手册）。"""

from __future__ import annotations

# pre-matching：REJECT 预匹配，优先于常规规则链，低开销拦截
REJECT_EXTS = ',pre-matching'

_POLICY_MAP = {
    'reject': 'REJECT',
    'proxy': 'PROXY',
    'direct': 'DIRECT',
}


def normalize_policy(kind: str) -> str:
    return _POLICY_MAP.get(kind.strip().lower(), kind.strip().upper())


def is_reject_policy(kind: str) -> bool:
    return normalize_policy(kind) == 'REJECT'


def policy_suffix(kind: str) -> str:
    return REJECT_EXTS if is_reject_policy(kind) else ''
