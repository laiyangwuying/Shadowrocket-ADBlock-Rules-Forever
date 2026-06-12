# -*- coding: utf-8 -*-
"""AdBlock 模块 / conf 尾部 URL Rewrite 拼装与规范化。"""

from __future__ import annotations

import re
from pathlib import Path

_SECTION_RE = re.compile(r'^\[(URL Rewrite|MITM|Script|Rule)\]\s*$', re.I)
_HOSTNAME_RE = re.compile(r'^hostname\s*=', re.I)


def _dedicated_index():
    from dedicated_modules import default_module_index

    return default_module_index()


def _normalize_rewrite_for_match(line: str) -> str:
    """Shadowrocket Rewrite 中域名常为 youtube\\.com 形式。"""
    return line.replace(r'\.', '.').replace(r'\/', '/').lower()


def _rewrite_pattern_only(line: str) -> str:
    pat = line.strip()
    for suffix in (' reject', ' reject-200', ' - reject', ' - reject-200'):
        if pat.lower().endswith(suffix):
            return pat[: -len(suffix)].strip()
    if ' $' in pat:
        return pat.split(' $', 1)[0].strip()
    if ' _ ' in pat:
        return pat.split(' _ ', 1)[0].strip()
    return pat


def is_dedicated_module_host(host: str) -> bool:
    """host 是否由 module/ 专用模块负责（构建 AdBlock 时须剔除）。"""
    return _dedicated_index().is_protected_host(host)


def is_dedicated_module_rewrite(line: str) -> bool:
    """Rewrite 是否与 module/ 专用模块策略重复或冲突。"""
    return _dedicated_index().is_dedicated_rewrite(line)


def is_dedicated_module_abp_rule(line: str) -> bool:
    """ABP 规则是否 targeting 专用模块已覆盖的域名。"""
    return _dedicated_index().is_dedicated_abp_rule(line)


# 兼容旧调用名
is_youtube_protected_host = is_dedicated_module_host
is_youtube_blocked_rewrite = is_dedicated_module_rewrite
is_youtube_abp_rule = is_dedicated_module_abp_rule
is_youtube_rewrite_rule = is_dedicated_module_rewrite


def strip_dedicated_module_rewrite_body(text: str) -> str:
    """剔除 module/ 专用模块已覆盖的 Rewrite 与相关注释。"""
    if not text:
        return ''
    index = _dedicated_index()
    kept: list[str] = []
    for raw in text.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            if kept and kept[-1] != '':
                kept.append('')
            continue
        if stripped.startswith('#'):
            if index.comment_mentions_dedicated_domain(stripped):
                continue
            kept.append(line)
            continue
        if is_dedicated_module_rewrite(line):
            continue
        kept.append(line)
    return '\n'.join(_compact_rewrite_spacing(kept))


strip_youtube_rewrite_body = strip_dedicated_module_rewrite_body


def finalize_adblock_rewrite_lines(lines: list[str]) -> tuple[list[str], int]:
    """AdBlock.module 最终 Pass：剔除专用模块已覆盖的 Rewrite。"""
    kept: list[str] = []
    removed = 0
    index = _dedicated_index()
    for raw in lines:
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            if kept and kept[-1] != '':
                kept.append('')
            continue
        if stripped.startswith('#'):
            if index.comment_mentions_dedicated_domain(stripped):
                removed += 1
                continue
            kept.append(line)
            continue
        if is_dedicated_module_rewrite(line):
            removed += 1
            continue
        kept.append(line)
    return _compact_rewrite_spacing(kept), removed


def count_dedicated_module_rewrite_leaks(text: str) -> int:
    """构建后校验：统计仍与专用模块 / googlevideo 冲突的 Rewrite 行数。"""
    from dedicated_modules import _matches_core_googlevideo_probe

    count = 0
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith('#'):
            continue
        lowered = stripped.lower()
        if (
            _matches_core_googlevideo_probe(stripped)
            or 'googlevideo' in lowered
            or 'youtube-nocookie' in lowered
            or 'youtubekids' in lowered
        ):
            count += 1
    return count


count_googlevideo_rewrite_lines = count_dedicated_module_rewrite_leaks


def _mitm_part_covered(part: str) -> bool:
    from dedicated_modules import _host_matches_token

    index = _dedicated_index()
    sample = part.replace('?', 'x').replace('*', 'probe')
    if index.is_protected_host(sample):
        return True
    lowered = part.lower()
    for marker in index.domain_markers:
        if '.' in marker and marker in lowered:
            return True
    for token in index.host_tokens:
        if _host_matches_token(sample, token):
            return True
    return False


def filter_dedicated_module_mitm_hosts(hosts: str) -> str:
    """从 AdBlock MITM 列表剔除专用模块已声明的 hostname。"""
    kept = [p for p in (x.strip() for x in hosts.split(',')) if p and not _mitm_part_covered(p)]
    return ','.join(kept)


filter_youtube_mitm_hosts = filter_dedicated_module_mitm_hosts


def dedicated_module_sources_summary() -> str:
    index = _dedicated_index()
    return ', '.join(index.sources) if index.sources else '(none)'


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
    index = _dedicated_index()
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
                if index.comment_mentions_dedicated_domain(stripped):
                    continue
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
