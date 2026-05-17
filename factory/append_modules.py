# -*- coding: utf-8 -*-
"""
读取 append_urls.txt 中的 URL，按顺序抓取 Surge 风格模块；失败则使用 append_cache 下缓存。
将 [URL Rewrite] / [MITM] hostname / [Script] 合并进 Shadowrocket 的 sr_foot；sr_ad_only 在末尾追加等价块。
"""

from __future__ import annotations

import hashlib
import os
import re
import sys
import time
from typing import Callable
from urllib.parse import urlparse

import requests

APPEND_LIST = os.path.join(os.path.dirname(__file__), 'append_urls.txt')
CACHE_DIR = os.path.join(os.path.dirname(__file__), 'append_cache')

USER_AGENT = (
    'Mozilla/5.0 (compatible; Shadowrocket-ADBlock-Rules-Forever/append; +https://github.com/)'
)

SECTION_HEADER = re.compile(r'^\[([^\]]+)\]\s*$')
_RE_HOSTNAME = re.compile(r'^(\s*hostname\s*=\s*)(.+?)\s*$', re.MULTILINE | re.IGNORECASE)


def strip_bom(s: str) -> str:
    if s.startswith('\ufeff'):
        return s[1:]
    return s


def url_cache_path(url: str) -> str:
    h = hashlib.sha256(url.strip().encode('utf-8')).hexdigest()
    slug = urlparse(url).netloc.replace(':', '_') or 'unknown_host'
    return os.path.join(CACHE_DIR, f'{slug}-{h[:10]}.cached')


def read_append_urls(path: str) -> list[str]:
    if not os.path.isfile(path):
        return []
    out: list[str] = []
    with open(path, 'r', encoding='utf-8') as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith('#'):
                continue
            out.append(line)
    return out


FACTORY_ROOT = os.path.realpath(os.path.dirname(APPEND_LIST))


def load_local(spec_path: str, logger: Callable[[str], None]) -> str | None:
    """local:vendor/foo.module → 相对于 factory 目录。"""
    rel = spec_path.split(':', 1)[1].strip().lstrip('/')
    cand = os.path.realpath(os.path.join(FACTORY_ROOT, rel))
    if cand != FACTORY_ROOT and not cand.startswith(FACTORY_ROOT + os.sep):
        logger(f'append_modules: local: path escapes factory/: {spec_path!r}')
        return None
    if not os.path.isfile(cand):
        logger(f'append_modules: local: file not found: {cand}')
        return None
    with open(cand, encoding='utf-8', errors='replace') as lf:
        body = strip_bom(lf.read())
    logger(f'append_modules: loaded local:{rel} ({len(body)} chars)')
    return body


def fetch_or_cache(url: str, logger: Callable[[str], None]) -> str | None:
    os.makedirs(CACHE_DIR, exist_ok=True)
    cache_path = url_cache_path(url)
    headers = {'User-Agent': USER_AGENT, 'Accept': 'text/plain,text/*,*/*;q=0.8'}
    last_exc: Exception | None = None

    for attempt in range(1, 3):
        try:
            r = requests.get(
                url,
                headers=headers,
                timeout=(8, 22),
                allow_redirects=True,
            )
            r.raise_for_status()
            body = strip_bom(r.text)
            tmp = cache_path + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as wf:
                wf.write(body)
            os.replace(tmp, cache_path)
            if attempt > 1:
                logger(f'append_modules: fetch OK after retry → {url}')
            else:
                logger(f'append_modules: fetched OK → {url} (cache {cache_path})')
            return body
        except Exception as exc:
            last_exc = exc
            logger(f'append_modules: fetch attempt {attempt}/2 failed {url!r}: {exc}')
            if attempt < 2:
                time.sleep(5)

    logger(f'append_modules: fetch gave up ({last_exc}); checking cache...')
    if os.path.isfile(cache_path):
        with open(cache_path, 'r', encoding='utf-8') as cf:
            body = cf.read()
        logger(f'append_modules: using cache → {cache_path}')
        return body
    logger(f'append_modules: no cache for {url!r}, skipped')
    return None


def load_append_source(spec: str, logger: Callable[[str], None]) -> str | None:
    s = spec.strip()
    scheme = s.split(':', 1)[0].lower().strip()

    if scheme == 'local':
        return load_local(s, logger)

    if scheme in ('http', 'https'):
        return fetch_or_cache(s, logger)

    logger(f'append_modules: unknown entry (need https:// URL or local:path under factory/) → {s!r}')
    return None


def discard_shebang(text: str) -> str:
    lines = strip_bom(text).splitlines()
    i = 0
    while i < len(lines) and (lines[i].startswith('#!') or not lines[i].strip()):
        i += 1
    return '\n'.join(lines[i:])


def split_sections(raw: str) -> dict[str, str]:
    sections: dict[str, str] = {}
    current_key: str | None = None
    buf: list[str] = []
    for line in discard_shebang(raw).splitlines():
        m = SECTION_HEADER.match(line.strip())
        if m:
            if current_key is not None:
                sections[current_key] = '\n'.join(buf).strip('\n')
            current_key = m.group(1).strip()
            buf = []
        else:
            buf.append(line)
    if current_key is not None:
        sections[current_key] = '\n'.join(buf).strip('\n')
    return sections


def normalize_rewrite_line(line: str) -> str:
    s = line.rstrip()
    stripped = s.strip()
    if not stripped or stripped.startswith('#'):
        return line
    if '_ reject' in s or '_reject' in stripped.replace(' ', ''):
        return line

    m = re.match(r'^(.+?)\s+-\s+reject\s*$', stripped)
    if m:
        return m.group(1).rstrip() + ' _ reject-200'

    m2 = re.match(r'^(.+?)\s+-\s+(reject-img|reject-dict|img|dic|tinygif)\s*$', stripped)
    if m2:
        return m2.group(1).rstrip() + ' _ ' + m2.group(2)

    return line


def normalize_rewrite_body(body: str) -> str:
    return '\n'.join(normalize_rewrite_line(ln) for ln in body.splitlines())


def extract_hostname_csv(mitm_body: str) -> str | None:
    mm = _RE_HOSTNAME.search(mitm_body)
    if not mm:
        # 宽松：整块里找第一条 hostname=
        mm = _RE_HOSTNAME.search(mitm_body.replace('\r\n', '\n'))
    if not mm:
        return None
    h = mm.group(2).strip()
    h = re.sub(r'%\s*APPEND\s*%', '', h, flags=re.IGNORECASE).strip()
    h = re.sub(r'^,\s*|,\s*$', '', h).strip()
    return h


def merge_host_lists(*parts: str) -> str:
    seen: set[str] = set()
    out: list[str] = []
    for blob in parts:
        if not blob:
            continue
        for item in blob.split(','):
            t = item.strip()
            if not t or t in seen:
                continue
            seen.add(t)
            out.append(t)
    return ','.join(out)


def collect_from_modules(contents: list[str], logger: Callable[[str], None]) -> tuple[str, str, str]:
    rew_parts: list[str] = []
    host_parts: list[str] = []
    script_parts: list[str] = []

    ignored = {'Map Local', 'Rule', 'General', 'Host', 'Proxy', 'Proxy Group'}

    for i, raw in enumerate(contents):
        sec = split_sections(raw)
        for name in sorted(ignored & sec.keys()):
            logger(f'append_modules: chunk #{i + 1} — [{name}] ignored (not merged for SR)')

        if 'URL Rewrite' in sec:
            rew_parts.append(normalize_rewrite_body(sec['URL Rewrite']).strip())

        if 'MITM' in sec:
            hcsv = extract_hostname_csv(sec['MITM'])
            if hcsv:
                host_parts.append(hcsv)

        if 'Script' in sec and sec['Script'].strip():
            script_parts.append(sec['Script'].strip())

    rewrite_merged = '\n\n'.join(p for p in rew_parts if p).strip('\n')
    host_merged = merge_host_lists(*host_parts)
    script_merged = '\n\n'.join(script_parts).strip('\n')

    return rewrite_merged, host_merged, script_merged


def inject_into_sr_foot(foot_text: str, rewrite_extra: str, hostname_extra: str, script_extra: str) -> str:
    ft = foot_text
    if rewrite_extra:
        insertion = (
            '\n# === Appended from remote modules (append_urls.txt) ===\n'
            + rewrite_extra
            + '\n'
        )
        sep = '[MITM]'
        if sep in ft:
            a, b = ft.split(sep, 1)
            ft = a.rstrip() + '\n' + insertion + sep + b
        else:
            ft = ft.rstrip() + '\n' + insertion

    if hostname_extra:
        m = _RE_HOSTNAME.search(ft)
        if m:
            base = m.group(2).strip()
            merged = merge_host_lists(base, hostname_extra)
            ft = ft[: m.start(2)] + merged + ft[m.end(2) :]

    if script_extra:
        ft = (
            ft.rstrip()
            + '\n\n# === Appended scripts (remote modules, append_urls.txt) ===\n'
            + script_extra.rstrip()
            + '\n'
        )

    if not ft.endswith('\n'):
        ft += '\n'
    return ft


def trailing_block_sr_ad_only(rewrite_extra: str, hostname_extra: str, script_extra: str) -> str:
    chunks: list[str] = []
    if rewrite_extra:
        chunks.append(
            '[URL Rewrite]\n'
            '# === From append_urls.txt ===\n'
            + rewrite_extra
        )
    if hostname_extra:
        chunks.append(
            '[MITM]\n'
            'enable = true\n'
            'h2 = true\n'
            'hostname = '
            + hostname_extra
            + '\n'
        )
    if script_extra:
        chunks.append('[Script]\n' + script_extra)
    return ('\n\n'.join(chunks) + '\n') if chunks else ''


def gather_appended(logger: Callable[[str], None]) -> tuple[str, str, str, str]:
    """
    返回 (rewrite, hostname_csv, script_body, sr_ad_only_suffix)。
    sr_ad_only_suffix 含可选统计注释行。
    """
    urls = read_append_urls(APPEND_LIST)
    if not urls:
        logger('append_modules: append_urls.txt empty — skip')
        return '', '', '', ''

    bodies: list[str] = []
    for u in urls:
        chunk = load_append_source(u.strip(), logger)
        if chunk:
            bodies.append(chunk)

    logger(f'append_modules: resolved {len(bodies)} / {len(urls)} source(s)')

    if not bodies:
        logger(
            'append_modules: WARNING — append_urls.txt has entries but NOTHING was loaded '
            '(remote blocked + no append_cache/*.cached). Merge skipped. '
            'Fix: add `local:vendor/xxx.module` under factory/, or commit a .cached snapshot.'
        )
        return '', '', '', ''

    rew, host, scr = collect_from_modules(bodies, logger)
    if not (rew or host or scr):
        logger('append_modules: modules produced no mergeable sections — skip')
        return '', '', '', ''

    bits = []
    if rew:
        bits.append('rewrite %d lines' % rew.count('\n'))
    if host:
        bits.append('mitm ~%d hosts' % (host.count(',') + 1))
    if scr:
        bits.append('script block present')
    banner = '# append_modules: %s @ %s\n' % (', '.join(bits), time.strftime('%Y-%m-%d %H:%M:%S'))
    ad_only = banner + trailing_block_sr_ad_only(rew, host, scr)
    return rew, host, scr, ad_only


def apply_append_to_foot(foot_template: str, logger: Callable[[str], None]) -> tuple[str, str]:
    rew, host, scr, ad_only = gather_appended(logger)
    if not (rew or host or scr):
        return foot_template, ''
    injected = inject_into_sr_foot(foot_template, rew, host or '', scr or '')
    return injected, ad_only.rstrip('\n')


if __name__ == '__main__':
    rew, host, scr, ad = gather_appended(lambda m: print(m, file=sys.stderr))
    sys.stderr.write('--- summary ---\n')
    sys.stderr.write('rewrite chars: %d\n' % len(rew))
    sys.stderr.write('hostname csv chars: %d\n' % len(host))
    sys.stderr.write('script chars: %d\n' % len(scr))
    sys.stderr.write('sr_ad_only extra chars: %d\n' % len(ad))
