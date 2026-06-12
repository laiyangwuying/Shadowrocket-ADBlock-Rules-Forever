# -*- coding: utf-8 -*-

from __future__ import annotations

import re
import time
from functools import lru_cache
from pathlib import Path

from build_util import FACTORY_ROOT, RESULTANT_DIR, atomic_write, log, read_entries
from idna_util import drain_corrections, is_ip_host, normalize_hostname, write_corrections_log
from publish_urls import RELEASE_RAW_BASE

REPO_ROOT = FACTORY_ROOT.parent
TEMPLATE_DIR = FACTORY_ROOT / 'template'

CONFS_NAMES = [
    'sr_top500_banlist_ad',
    'sr_top500_banlist',
    'sr_top500_whitelist_ad',
    'sr_top500_whitelist',
    'sr_adb',
    'sr_direct_banad',
    'sr_proxy_banad',
    'sr_cnip', 'sr_cnip_ad',
    'sr_backcn', 'sr_backcn_ad',
    'sr_ad_only',
]

# 走代理为主的分流策略：启用「代理 UDP 拦截」与 APNS 优化
PROXY_ORIENTED_CONFS = frozenset({
    'sr_top500_banlist_ad',
    'sr_top500_banlist',
    'sr_top500_whitelist_ad',
    'sr_top500_whitelist',
    'sr_adb',
    'sr_proxy_banad',
    'sr_cnip',
    'sr_cnip_ad',
})

# 含去广告 MITM / URL Rewrite 尾部（sr_foot_ad.txt）
AD_FOOT_CONFS = frozenset(
    n for n in CONFS_NAMES if n.endswith('_ad') or n in ('sr_adb', 'sr_proxy_banad', 'sr_direct_banad')
)

# 方案 A：仅 FINAL 非全代理的配置需要按域名 UDP 降级（其余由 FINAL,PROXY+UDP 兜底）
STREAMING_UDP_CONFS = frozenset({
    'sr_direct_banad',
    'sr_backcn_ad',
    'sr_adb',
})

@lru_cache(maxsize=16)
def _tpl(name: str) -> str:
    return (TEMPLATE_DIR / name).read_text(encoding='utf-8')


def _assemble_prefix(conf_name: str) -> str:
    if conf_name == 'sr_ad_only':
        return ''
    parts = [_tpl('sr_head.txt')]
    if conf_name in PROXY_ORIENTED_CONFS:
        parts.append(_tpl('sr_head_rules_proxy_udp.txt'))
    if conf_name in STREAMING_UDP_CONFS:
        parts.append(_tpl('sr_head_rules_streaming.txt'))
    if conf_name in PROXY_ORIENTED_CONFS:
        parts.append(_tpl('sr_head_rules_apns.txt'))
    return ''.join(parts)


def _assemble_suffix(conf_name: str) -> str:
    if conf_name == 'sr_ad_only':
        return ''
    if conf_name in AD_FOOT_CONFS:
        return _tpl('sr_foot_ad.txt')
    return _tpl('sr_foot_basic.txt')


def _rule_line_from_plain_entry(content: str, kind: str) -> str | None:
    if not content:
        return None

    prefix = 'DOMAIN-SUFFIX'
    if content.startswith('FULL:'):
        prefix = 'DOMAIN'
        content = content[5:].strip()
    if not content:
        return None

    if not is_ip_host(content) and ('.' in content or not content.isascii()):
        normalized = normalize_hostname(content, source='build_confs')
        if normalized is None:
            return None
        content = normalized

    if is_ip_host(content):
        prefix = 'IP-CIDR'
        host = content.split('/')[0]
        if ':' in host:
            if '/' not in content:
                content += '/128'
        elif '/' not in content:
            content += '/32'
    elif '.' not in content and len(content) > 1:
        prefix = 'DOMAIN-KEYWORD'

    return f'{prefix},{content},{kind}\n'


def _rules_string_from_file(path: str | Path, kind: str) -> str:
    lines_out: list[str] = []
    for raw in Path(path).read_text(encoding='utf-8').splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith('#'):
            lines_out.append(line + '\n')
            continue
        rule = _rule_line_from_plain_entry(line, kind)
        if rule:
            lines_out.append(rule)
    return ''.join(lines_out)


def _merged_gfw_rules_string(kind: str) -> str:
    ret: list[str] = []
    full_hosts: set[str] = set()
    suffix_raw: set[str] = set()

    for rel in ('resultant/gfw.list', 'manual_gfwlist.txt'):
        path = FACTORY_ROOT / rel
        for raw in path.read_text(encoding='utf-8').splitlines():
            line = raw.strip()
            if not line:
                continue
            if line.startswith('#'):
                ret.append(line + '\n')
                continue
            if line.startswith('FULL:'):
                h = line[5:].strip()
                if h:
                    full_hosts.add(h)
            else:
                suffix_raw.add(line)

    for h in sorted(full_hosts):
        rule = _rule_line_from_plain_entry('FULL:' + h, kind)
        if rule:
            ret.append(rule)
    for line in sorted(suffix_raw):
        rule = _rule_line_from_plain_entry(line, kind)
        if rule:
            ret.append(rule)
    return ''.join(ret)


def build() -> dict:
    values = {
        'build_time': time.strftime('%Y-%m-%d %H:%M:%S'),
        'top500_proxy': _rules_string_from_file(RESULTANT_DIR / 'top500_proxy.list', 'Proxy'),
        'top500_direct': _rules_string_from_file(RESULTANT_DIR / 'top500_direct.list', 'Direct'),
        'ad': _rules_string_from_file(RESULTANT_DIR / 'ad.list', 'Reject'),
        'manual_direct': _rules_string_from_file(FACTORY_ROOT / 'manual_direct.txt', 'Direct'),
        'manual_proxy': _rules_string_from_file(FACTORY_ROOT / 'manual_proxy.txt', 'Proxy'),
        'manual_reject': _rules_string_from_file(FACTORY_ROOT / 'manual_reject.txt', 'Reject'),
        'gfwlist': _merged_gfw_rules_string('Proxy'),
    }

    written: list[str] = []
    for conf_name in CONFS_NAMES:
        values['release_update_url'] = RELEASE_RAW_BASE + conf_name + '.conf'
        body = (TEMPLATE_DIR / f'{conf_name}.txt').read_text(encoding='utf-8')
        template = _assemble_prefix(conf_name) + body + _assemble_suffix(conf_name)

        for mark in set(re.findall(r'{{(.+?)}}', template)):
            if mark in values:
                template = template.replace('{{' + mark + '}}', values[mark])

        atomic_write(REPO_ROOT / f'{conf_name}.conf', template)
        written.append(conf_name)

    write_corrections_log(
        str(RESULTANT_DIR / 'idna_corrections.log'),
        drain_corrections(),
        append=True,
    )

    summary = (
        f'# build time: {values["build_time"]}\n'
        f'confs: {len(written)}\n'
        f'ad entries: {len(read_entries(RESULTANT_DIR / "ad.list"))}\n'
        f'gfw entries: {len(read_entries(RESULTANT_DIR / "gfw.list"))}\n'
    )
    atomic_write(RESULTANT_DIR / 'build_summary.txt', summary)

    log(f'build_confs: wrote {len(written)} conf files')
    return {'confs': len(written)}


def main() -> int:
    build()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
