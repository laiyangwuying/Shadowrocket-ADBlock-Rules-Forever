# -*- coding: utf-8 -*-
"""扫描 module/ 专用模块，供 AdBlock 构建时剔除重复策略与域名。"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

ADBLOCK_MODULE_NAME = 'AdBlock.module'
_SECTION_RE = re.compile(r'^\[(URL Rewrite|MITM|Script|Rule)\]\s*$', re.I)
_HOSTNAME_RE = re.compile(r'^hostname\s*=', re.I)


def _clean_text_newlines(text: str) -> str:
    return text.replace('\r\n', '\n').replace('\r', '')


def _normalize_rewrite_for_match(line: str) -> str:
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


def _parse_mitm_hostname_value(line: str) -> str:
    raw = line.strip()
    if '=' in raw:
        raw = raw.split('=', 1)[1].strip()
    if raw.upper().startswith('%APPEND%'):
        raw = raw[8:].strip()
    return raw

_RULE_DOMAIN_RE = re.compile(r'DOMAIN(?:-SUFFIX)?,([^,\)]+)', re.I)
_SCRIPT_PATTERN_RE = re.compile(r'pattern\s*=\s*([^,\s]+)', re.I)
_DOMAIN_LIKE_RE = re.compile(
    r'([a-z0-9][-a-z0-9]*(?:\.[a-z0-9][-a-z0-9]*){1,})',
    re.I,
)


def _normalize_pattern_key(line: str) -> str:
    return _rewrite_pattern_only(line).strip().lower()


def _extract_domains_from_text(text: str) -> set[str]:
    normalized = _normalize_rewrite_for_match(text)
    found: set[str] = set()
    for match in _DOMAIN_LIKE_RE.finditer(normalized):
        domain = match.group(1).lower().rstrip('.')
        if '.' not in domain or len(domain) < 4:
            continue
        if domain.replace('.', '').isdigit():
            continue
        found.add(domain)
    return found


def _host_matches_token(host: str, token: str) -> bool:
    host = host.lower().strip().rstrip('.')
    if ':' in host and host.count(':') == 1:
        host = host.split(':', 1)[0]

    token = token.strip().lower()
    if not token:
        return False
    if token.startswith('-'):
        token = token[1:]
    if ':' in token and token.count(':') == 1:
        token = token.split(':', 1)[0]

    if '*' not in token and '?' not in token:
        return host == token or host.endswith('.' + token)

    if token.startswith('*.'):
        suffix = token[2:].rstrip('.*')
        return host == suffix or host.endswith('.' + suffix)

    if token.endswith('.*'):
        prefix = token[:-2]
        return host.startswith(prefix) or f'.{prefix}.' in f'.{host}.'

    regex = '^' + re.escape(token).replace(r'\*', '.*').replace(r'\?', '.') + '$'
    try:
        return bool(re.match(regex, host))
    except re.error:
        return False


@dataclass
class DedicatedModuleIndex:
    """module/ 内除 AdBlock 外专用模块的策略索引。"""

    sources: tuple[str, ...] = ()
    rewrite_patterns: frozenset[str] = field(default_factory=frozenset)
    host_tokens: tuple[str, ...] = ()
    host_suffixes: frozenset[str] = field(default_factory=frozenset)
    host_literals: frozenset[str] = field(default_factory=frozenset)
    domain_markers: frozenset[str] = field(default_factory=frozenset)
    probe_urls: tuple[str, ...] = ()

    def is_protected_host(self, host: str) -> bool:
        h = host.lower().strip().rstrip('.')
        if not h:
            return False
        if ':' in h and h.count(':') == 1:
            h = h.split(':', 1)[0]

        if h in self.host_literals:
            return True
        for suffix in self.host_suffixes:
            if h == suffix or h.endswith('.' + suffix):
                return True
        for token in self.host_tokens:
            if _host_matches_token(h, token):
                return True
        return self._domain_marker_covers(h)

    def _domain_marker_covers(self, domain: str) -> bool:
        domain = domain.lower()
        if domain in self.domain_markers:
            return True
        for suffix in self.host_suffixes:
            if domain == suffix or domain.endswith('.' + suffix):
                return True
        return False

    def is_dedicated_rewrite(self, line: str) -> bool:
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            return False

        pattern_key = _normalize_pattern_key(stripped)
        if pattern_key in self.rewrite_patterns:
            return True

        domains = _extract_domains_from_text(stripped)
        if domains:
            return any(
                self._domain_marker_covers(domain) or self.is_protected_host(domain)
                for domain in domains
            )

        pat = _rewrite_pattern_only(stripped)
        for url in self.probe_urls:
            try:
                if re.search(pat, url, re.I):
                    return True
            except re.error:
                return False
        return False

    def is_dedicated_abp_rule(self, line: str) -> bool:
        lowered = line.lower().strip()
        if not lowered or lowered.startswith('!') or lowered.startswith('@@'):
            return False

        if lowered.startswith('||'):
            host_part = lowered[2:].split('^', 1)[0].split('/', 1)[0].split('$', 1)[0]
            host_part = host_part.split(':', 1)[0]
            if self.is_protected_host(host_part) or self._domain_marker_covers(host_part):
                return True

        for marker in self.domain_markers:
            if '.' not in marker:
                continue
            if marker in lowered:
                host_part = lowered[2:].split('^', 1)[0].split('/', 1)[0].split('$', 1)[0]
                if marker in host_part or host_part.endswith('.' + marker):
                    return True
        return False

    def comment_mentions_dedicated_domain(self, comment: str) -> bool:
        lowered = _normalize_rewrite_for_match(comment)
        if 'googlevideo' in lowered:
            return True
        for suffix in self.host_suffixes:
            if suffix in lowered:
                return True
        for marker in self.domain_markers:
            if '.' in marker and marker in lowered:
                return True
        return False


def _ingest_host_token(
    token: str,
    host_tokens: list[str],
    host_suffixes: set[str],
    host_literals: set[str],
    domain_markers: set[str],
) -> None:
    raw = token.strip()
    if not raw:
        return
    host_tokens.append(raw)
    t = raw.lower().lstrip('-')
    if ':' in t and t.count(':') == 1:
        t = t.split(':', 1)[0]

    if t.startswith('*.'):
        suffix = t[2:].rstrip('.*')
        if suffix:
            host_suffixes.add(suffix)
            domain_markers.add(suffix)
        return

    if '*' in t or '?' in t:
        core = re.sub(r'[*?]+', ' ', t).strip()
        for part in core.split():
            if '.' in part:
                domain_markers.add(part.strip('.'))
        return

    host_literals.add(t)
    domain_markers.add(t)


def _build_probe_urls(
    host_suffixes: set[str],
    host_literals: set[str],
) -> list[str]:
    probes: list[str] = []
    for suffix in sorted(host_suffixes):
        probes.append(f'https://test.{suffix}/')
        if suffix.endswith('googlevideo.com'):
            probes.append(
                f'https://rr5---sn-test.{suffix}/initplayback?source=youtube&oad=1'
            )
    for host in sorted(host_literals)[:300]:
        probes.append(f'https://{host}/')
    return probes


def _parse_module_file(path: Path) -> tuple[str, dict[str, list[str]]]:
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for raw in _clean_text_newlines(path.read_text(encoding='utf-8', errors='replace')).splitlines():
        line = raw.strip()
        if not line or line.startswith('#!'):
            continue
        section_match = _SECTION_RE.match(line)
        if section_match:
            current = section_match.group(1).lower()
            sections.setdefault(current, [])
            continue
        if current:
            sections[current].append(line)
    name = path.name
    for raw in _clean_text_newlines(path.read_text(encoding='utf-8', errors='replace')).splitlines():
        if raw.startswith('#!name'):
            name = raw.split('=', 1)[-1].strip() or path.name
            break
    return name, sections


def build_dedicated_module_index(module_dir: Path) -> DedicatedModuleIndex:
    rewrite_patterns: set[str] = set()
    host_tokens: list[str] = []
    host_suffixes: set[str] = set()
    host_literals: set[str] = set()
    domain_markers: set[str] = set()
    sources: list[str] = []

    for path in sorted(module_dir.iterdir()):
        if path.name == ADBLOCK_MODULE_NAME:
            continue
        if path.suffix not in ('.module', '.sgmodule'):
            continue
        if not path.is_file():
            continue

        mod_name, sections = _parse_module_file(path)
        sources.append(f'{path.name}({mod_name})')

        for line in sections.get('url rewrite', []):
            if line.startswith('#'):
                continue
            rewrite_patterns.add(_normalize_pattern_key(line))
            domain_markers.update(_extract_domains_from_text(line))

        for line in sections.get('mitm', []):
            if not line.lower().startswith('hostname'):
                continue
            hosts = _parse_mitm_hostname_value(line)
            for token in hosts.split(','):
                _ingest_host_token(token, host_tokens, host_suffixes, host_literals, domain_markers)

        for line in sections.get('script', []):
            match = _SCRIPT_PATTERN_RE.search(line)
            if not match:
                continue
            pattern = match.group(1)
            domain_markers.update(_extract_domains_from_text(pattern))
            for domain in _extract_domains_from_text(pattern):
                host_literals.add(domain)

        for line in sections.get('rule', []):
            for match in _RULE_DOMAIN_RE.finditer(line):
                token = match.group(1).strip()
                _ingest_host_token(token, host_tokens, host_suffixes, host_literals, domain_markers)

    probe_urls = _build_probe_urls(host_suffixes, host_literals)
    return DedicatedModuleIndex(
        sources=tuple(sources),
        rewrite_patterns=frozenset(rewrite_patterns),
        host_tokens=tuple(host_tokens),
        host_suffixes=frozenset(host_suffixes),
        host_literals=frozenset(host_literals),
        domain_markers=frozenset(domain_markers),
        probe_urls=tuple(probe_urls),
    )


@lru_cache(maxsize=4)
def get_dedicated_module_index(module_dir: str) -> DedicatedModuleIndex:
    return build_dedicated_module_index(Path(module_dir))


def default_module_index() -> DedicatedModuleIndex:
    module_dir = Path(__file__).resolve().parent.parent / 'module'
    return get_dedicated_module_index(str(module_dir))
