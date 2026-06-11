# -*- coding: utf-8 -*-
"""
IDNA 检查与修正：将 Unicode 域名规范为 ASCII（punycode），并校验标签合法性。
供 ad.py / gfwlist.py / build_confs.py 共用。
"""

from __future__ import annotations

import re
from typing import Optional

_IPV4_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?$')
_IPV6_RE = re.compile(
    r'^(([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|'
    r'([0-9A-Fa-f]{1,4}:){1,7}:|'
    r'([0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|'
    r'([0-9A-Fa-f]{1,4}:){1,5}(:[0-9A-Fa-f]{1,4}){1,2}|'
    r'([0-9A-Fa-f]{1,4}:){1,4}(:[0-9A-Fa-f]{1,4}){1,3}|'
    r'([0-9A-Fa-f]{1,4}:){1,3}(:[0-9A-Fa-f]{1,4}){1,4}|'
    r'([0-9A-Fa-f]{1,4}:){1,2}(:[0-9A-Fa-f]{1,4}){1,5}|'
    r'[0-9A-Fa-f]{1,4}:((:[0-9A-Fa-f]{1,4}){1,6})|'
    r':((:[0-9A-Fa-f]{1,4}){1,7}|:)|'
    r'fe80:(:[0-9A-Fa-f]{0,4}){0,4}%[0-9A-Za-z]+|'
    r'::(ffff(:0{1,4})?:)?((25[0-5]|(2[0-4]|1?\d)?\d)\.){3}'
    r'(25[0-5]|(2[0-4]|1?\d)?\d)|'
    r'([0-9A-Fa-f]{1,4}:){1,4}:'
    r'((25[0-5]|(2[0-4]|1?\d)?\d)\.){3}(25[0-5]|(2[0-4]|1?\d)?\d))'
    r'(/(?:\d{1,3}))?$'
)
_ASCII_HOST_RE = re.compile(r'^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$')

_corrections: list[tuple[str, str, str]] = []


def is_ip_host(host: str) -> bool:
    body = host.split('/')[0]
    if _IPV4_RE.match(body):
        return True
    if ':' in body and _IPV6_RE.match(body):
        return True
    return False


def _normalize_label(label: str) -> Optional[str]:
    if not label:
        return None
    if len(label) > 63:
        return None
    try:
        if label.isascii():
            if not _ASCII_HOST_RE.match(label):
                return None
            # 已是 punycode 时 decode→encode 做规范化
            if label.lower().startswith('xn--'):
                decoded = label.encode('ascii').decode('idna')
                return decoded.encode('idna').decode('ascii')
            return label.lower()
        return label.encode('idna').decode('ascii')
    except (UnicodeError, UnicodeDecodeError, IndexError):
        return None


def normalize_hostname(hostname: str, *, source: str = '') -> Optional[str]:
    """
    将主机名规范为 DNS 可用的 ASCII 形式。
    支持可选前导点（后缀规则）；IP 地址原样返回。
    """
    if not hostname or not str(hostname).strip():
        return None

    host = str(hostname).strip().rstrip('.')
    if not host:
        return None

    leading_dot = ''
    if host.startswith('.'):
        leading_dot = '.'
        host = host[1:]
        if not host:
            return None

    if is_ip_host(host):
        return leading_dot + host

    labels = host.split('.')
    ascii_labels: list[str] = []
    for label in labels:
        normalized = _normalize_label(label)
        if normalized is None:
            return None
        ascii_labels.append(normalized)

    result = leading_dot + '.'.join(ascii_labels)
    if source and _should_log_correction(hostname, result):
        _corrections.append((source, hostname, result))
    return result


def normalize_list_entry(entry: str, full_mark: str = 'FULL:', *, source: str = '') -> Optional[str]:
    """规范化 gfw / manual 列表条目（可含 FULL: 前缀）。"""
    is_full = entry.startswith(full_mark)
    body = entry[len(full_mark):] if is_full else entry
    if '/' in body:
        body = body.split('/')[0]

    normalized = normalize_hostname(body, source=source)
    if normalized is None:
        return None
    if not re.match(r'^\.?[\w.-]+$', normalized):
        return None
    return (full_mark + normalized) if is_full else normalized


def _should_log_correction(before: str, after: str) -> bool:
    """仅记录 Unicode→punycode 或 punycode 规范化，忽略空白/尾点修剪。"""
    if before == after:
        return False
    stripped = before.strip().rstrip('.')
    if stripped == after:
        return False
    if not stripped.isascii():
        return True
    if 'xn--' in stripped.lower():
        return stripped.lower() != after
    return False


def drain_corrections() -> list[tuple[str, str, str]]:
    items = list(_corrections)
    _corrections.clear()
    return items


def write_corrections_log(path: str, items: list[tuple[str, str, str]], *, append: bool = True) -> None:
    if not items:
        return
    mode = 'a' if append else 'w'
    with open(path, mode, encoding='utf-8') as fp:
        for src, old, new in items:
            fp.write(f'[{src}] {old} -> {new}\n')
