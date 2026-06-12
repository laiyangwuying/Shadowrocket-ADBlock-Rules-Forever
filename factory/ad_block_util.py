# -*- coding: utf-8 -*-
"""AdBlock 模块 / conf 尾部 URL Rewrite 拼装与规范化。"""

from __future__ import annotations

import re
from pathlib import Path

_SECTION_RE = re.compile(r'^\[(URL Rewrite|MITM|Script|Rule)\]\s*$', re.I)
_HOSTNAME_RE = re.compile(r'^hostname\s*=', re.I)


def clean_text_newlines(text: str) -> str:
    """vendor .module 常见 \\r\\r\\n，统一为 Unix 换行。"""
    return text.replace('\r\n', '\n').replace('\r', '')


def _compact_rewrite_spacing(lines: list[str]) -> list[str]:
    """注释与规则之间不留空行；连续空行最多保留一行。"""
    out: list[str] = []
    for i, line in enumerate(lines):
        if line != '':
            out.append(line)
            continue
        prev = out[-1] if out else ''
        nxt = lines[i + 1] if i + 1 < len(lines) else ''
        if prev.lstrip().startswith('#') and nxt.lstrip().startswith('^'):
            continue
        if out and out[-1] == '':
            continue
        out.append('')
    while out and out[0] == '':
        out.pop(0)
    while out and out[-1] == '':
        out.pop()
    return out


def normalize_rewrite_body(text: str) -> str:
    """去掉段落标记与 hostname 行，合并多余空行。"""
    if not text:
        return ''
    kept: list[str] = []
    for raw in clean_text_newlines(text).splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            kept.append('')
            continue
        if _SECTION_RE.match(stripped) or _HOSTNAME_RE.match(stripped):
            continue
        kept.append(line)
    return '\n'.join(_compact_rewrite_spacing(kept))


def extract_rewrite_body_from_module(text: str) -> str:
    """从 .module 文本截取 [URL Rewrite] 与 [MITM] 之间的规则体（不含段标记）。"""
    lines = clean_text_newlines(text).splitlines()
    start = end = None
    for i, line in enumerate(lines):
        tag = line.strip()
        if tag == '[URL Rewrite]' and start is None:
            start = i + 1
        elif tag == '[MITM]' and start is not None:
            end = i
            break
    if start is None:
        return normalize_rewrite_body(text)
    chunk = '\n'.join(lines[start:end if end is not None else len(lines)])
    return normalize_rewrite_body(chunk)


def parse_mitm_hostname_value(line: str) -> str:
    """`hostname = %APPEND% a,b` → `a,b`。"""
    raw = line.strip()
    if '=' in raw:
        raw = raw.split('=', 1)[1].strip()
    if raw.upper().startswith('%APPEND%'):
        raw = raw[8:].strip()
    return raw


def merge_rewrite_bodies(*parts: str) -> str:
    """合并多段 Rewrite 规则，按行去重（保留注释与空行结构）。"""
    seen: set[str] = set()
    out: list[str] = []

    def _append_blank() -> None:
        if out and out[-1] != '':
            out.append('')

    for part in parts:
        body = normalize_rewrite_body(part)
        if not body:
            continue
        if out:
            _append_blank()
        for line in body.splitlines():
            stripped = line.strip()
            if not stripped:
                _append_blank()
                continue
            if stripped.startswith('#'):
                out.append(line)
                continue
            if stripped in seen:
                continue
            seen.add(stripped)
            out.append(line)

    while out and out[-1] == '':
        out.pop()
    return '\n'.join(out)


def rewrite_lines_from_list_file(path: Path) -> list[str]:
    """读取 ad_rewrite.list：跳过文件头注释，返回规则行。"""
    if not path.is_file():
        return []
    lines: list[str] = []
    for raw in path.read_text(encoding='utf-8').splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        lines.append(line)
    return lines
