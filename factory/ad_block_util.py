# -*- coding: utf-8 -*-
"""AdBlock 模块 / conf 尾部 URL Rewrite 拼装与规范化。"""

from __future__ import annotations

import re
from pathlib import Path

_SECTION_RE = re.compile(r'^\[(URL Rewrite|MITM|Script|Rule)\]\s*$', re.I)
_HOSTNAME_RE = re.compile(r'^hostname\s*=', re.I)

# YouTube 去广告由 module/YouTubeAd.sgmodule 单独负责，AdBlock 不得触碰。
YOUTUBE_PROTECTED_SUFFIXES = frozenset({
    'youtube.com',
    'googlevideo.com',
    'youtubei.googleapis.com',
    'youtube.googleapis.com',
    'youtube-nocookie.com',
    'youtubekids.com',
    'ytimg.com',
    'ggpht.com',
    'gvt1.com',
})
_YOUTUBE_COMMENT_RE = re.compile(
    r'googlevideo|youtube|ytimg|ggpht|gvt1|Youtube\+\+',
    re.I,
)
_YOUTUBE_RULE_MARKERS = tuple(YOUTUBE_PROTECTED_SUFFIXES)
# Rewrite 规则中出现以下特征即视为 YouTube 生态，构建期整行删除
_YOUTUBE_REWRITE_ECOSYSTEM_RE = re.compile(
    r'googlevideo|youtubei|ytimg|ggpht|gvt1|youtubee\.|\.youtube\.|youtube\.com',
    re.I,
)
# 与 YouTubeAd.sgmodule 同款的 googlevideo 去广告 Rewrite，不得进入 AdBlock
_YOUTUBE_AD_SIGNATURE_RE = re.compile(
    r'dclk_video_ads|videoplayback\\\?|initplayback|ctier=L|googlevideo\.com',
    re.I,
)
# 构建期探测：凡能命中下列正常播放 URL 的 Rewrite 一律剔除
YOUTUBE_PLAYBACK_PROBE_URLS = (
    'https://rr5---sn-a5meknsy.googlevideo.com/videoplayback?expire=1&ei=abc',
    'https://rr5---sn-a5meknsy.googlevideo.com/initplayback?source=youtube&c=IOS&oad=5500',
    'https://rr5---sn-a5mekn6s.googlevideo.com/initplayback?source=youtube&c=IOS&oad=5500',
    'https://www.youtube.com/watch?v=dQw4w9WgXcQ',
    'https://youtubei.googleapis.com/youtubei/v1/player?prettyPrint=false',
)
# 典型 googlevideo CDN 主机（含 rr5---sn-* 子域）
GOOGLEVIDEO_HOST_PROBES = (
    'rr5---sn-a5meknsy.googlevideo.com',
    'rr5---sn-a5mekn6s.googlevideo.com',
    'redirector.googlevideo.com',
)


def _normalize_rewrite_for_match(line: str) -> str:
    """Shadowrocket Rewrite 中域名常为 youtube\\.com 形式。"""
    return line.replace(r'\.', '.').replace(r'\/', '/').lower()


def is_youtube_protected_host(host: str) -> bool:
    h = host.lower().strip().rstrip('.')
    if not h:
        return False
    for suffix in YOUTUBE_PROTECTED_SUFFIXES:
        if h == suffix or h.endswith('.' + suffix):
            return True
    return False


def is_youtube_rewrite_rule(line: str) -> bool:
    stripped = line.strip()
    if not stripped or stripped.startswith('#'):
        return False
    normalized = _normalize_rewrite_for_match(stripped)
    if _YOUTUBE_REWRITE_ECOSYSTEM_RE.search(normalized):
        return True
    return any(marker in normalized for marker in _YOUTUBE_RULE_MARKERS)


def is_youtube_abp_rule(line: str) -> bool:
    """ABP 网络规则在转换前剔除 YouTube 相关域名，避免漏网或误转换。"""
    lowered = line.lower().strip()
    if not lowered or lowered.startswith('!') or lowered.startswith('@@'):
        return False
    if _YOUTUBE_REWRITE_ECOSYSTEM_RE.search(lowered):
        return True
    return any(marker in lowered for marker in _YOUTUBE_RULE_MARKERS)


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


def is_youtube_ad_signature_rewrite(line: str) -> bool:
    """剔除与 YouTubeAd.sgmodule 同款的 googlevideo 策略，避免双模块叠加误伤。"""
    stripped = line.strip()
    if not stripped or stripped.startswith('#'):
        return False
    return bool(_YOUTUBE_AD_SIGNATURE_RE.search(stripped))


def matches_youtube_playback_probe(line: str) -> bool:
    """构建期用典型播放 URL 探测，防止 Cats-Team 转换出误伤规则。"""
    stripped = line.strip()
    if not stripped or stripped.startswith('#'):
        return False
    pat = _rewrite_pattern_only(stripped)
    for url in YOUTUBE_PLAYBACK_PROBE_URLS:
        try:
            if re.search(pat, url, re.I):
                return True
        except re.error:
            return False
    return False


def matches_googlevideo_host_probe(line: str) -> bool:
    """凡能命中 googlevideo CDN 子域（含 rr5---sn-*）的 Rewrite 一律剔除。"""
    stripped = line.strip()
    if not stripped or stripped.startswith('#'):
        return False
    pat = _rewrite_pattern_only(stripped)
    for host in GOOGLEVIDEO_HOST_PROBES:
        url = f'https://{host}/'
        try:
            if re.search(pat, url, re.I):
                return True
        except re.error:
            return False
    return False


def is_youtube_blocked_rewrite(line: str) -> bool:
    return (
        is_youtube_rewrite_rule(line)
        or is_youtube_ad_signature_rewrite(line)
        or matches_youtube_playback_probe(line)
        or matches_googlevideo_host_probe(line)
    )


def finalize_adblock_rewrite_lines(lines: list[str]) -> tuple[list[str], int]:
    """AdBlock.module 最终 Pass：剔除一切 YouTube/googlevideo Rewrite。"""
    kept: list[str] = []
    removed = 0
    for raw in lines:
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            if kept and kept[-1] != '':
                kept.append('')
            continue
        if stripped.startswith('#'):
            if _YOUTUBE_COMMENT_RE.search(stripped):
                removed += 1
                continue
            kept.append(line)
            continue
        if is_youtube_blocked_rewrite(line):
            removed += 1
            continue
        kept.append(line)
    return _compact_rewrite_spacing(kept), removed


def count_googlevideo_rewrite_lines(text: str) -> int:
    """构建后校验：统计仍含 googlevideo 的 Rewrite 行数（应为 0）。"""
    count = 0
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith('#'):
            continue
        normalized = _normalize_rewrite_for_match(stripped)
        if _YOUTUBE_REWRITE_ECOSYSTEM_RE.search(normalized):
            count += 1
        elif is_youtube_blocked_rewrite(stripped):
            count += 1
    return count


def strip_youtube_rewrite_body(text: str) -> str:
    """剔除 YouTube/googlevideo Rewrite 与相关注释（避免与 YouTubeAd.sgmodule 冲突）。"""
    if not text:
        return ''
    kept: list[str] = []
    for raw in text.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            if kept and kept[-1] != '':
                kept.append('')
            continue
        if stripped.startswith('#'):
            if _YOUTUBE_COMMENT_RE.search(stripped):
                continue
            kept.append(line)
            continue
        if is_youtube_blocked_rewrite(line):
            continue
        kept.append(line)
    return '\n'.join(_compact_rewrite_spacing(kept))


def filter_youtube_mitm_hosts(hosts: str) -> str:
    parts = [p.strip() for p in hosts.split(',') if p.strip()]
    kept = [p for p in parts if not is_youtube_protected_host(p.replace('*', ''))]
    return ','.join(kept)


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
            if is_youtube_blocked_rewrite(line):
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
