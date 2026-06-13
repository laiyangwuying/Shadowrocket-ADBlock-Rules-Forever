# -*- coding: utf-8 -*-
"""按 LOWERTOP Shadowrocket 使用手册审计构建产物合规性。"""

from __future__ import annotations

from pathlib import Path

from build_util import FACTORY_ROOT, RESULTANT_DIR, log
from publish_urls import AD_RULE_SET_URL
from sr_policy import REJECT_EXTS

REPO_ROOT = FACTORY_ROOT.parent
MODULE_DIR = REPO_ROOT / 'module'
AD_CONF_NAMES = [
    'sr_top500_banlist_ad',
    'sr_top500_whitelist_ad',
    'sr_adb',
    'sr_direct_banad',
    'sr_proxy_banad',
    'sr_cnip_ad',
    'sr_backcn_ad',
    'sr_ad_only',
]


def _issues_from_conf(path: Path) -> list[str]:
    issues: list[str] = []
    text = path.read_text(encoding='utf-8')
    if 'DOMAIN-SET' in text and 'ad.set' in text:
        issues.append(f'{path.name}: 仍引用 DOMAIN-SET/ad.set，应改用 RULE-SET/ad.rule-set')
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith('#'):
            continue
        if s.startswith('RULE-SET,') and AD_RULE_SET_URL in s:
            if f'REJECT{REJECT_EXTS}' not in s:
                issues.append(f'{path.name}: 广告 RULE-SET 缺少 pre-matching')
        if s.startswith('DOMAIN-KEYWORD,') and ',REJECT' in s.upper():
            if REJECT_EXTS not in s:
                issues.append(f'{path.name}: DOMAIN-KEYWORD REJECT 缺少 pre-matching: {s[:80]}')
    if '[General]' in text and 'always-reject-url-rewrite = true' not in text:
        issues.append(f'{path.name}: 缺少 always-reject-url-rewrite（模块 REJECT 需配置模式外生效）')
    return issues


def _issues_from_rule_set(path: Path) -> list[str]:
    issues: list[str] = []
    if not path.is_file():
        issues.append('ad.rule-set: 文件不存在')
        return issues
    bad = 0
    for raw in path.read_text(encoding='utf-8').splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('.') or not line.startswith('DOMAIN'):
            if not line.startswith('IP-CIDR'):
                bad += 1
                if bad <= 3:
                    issues.append(f'ad.rule-set: 非 RULE-SET 行格式: {line[:80]}')
            continue
        if ',REJECT' not in line:
            issues.append(f'ad.rule-set: 非 REJECT 策略: {line[:80]}')
        elif REJECT_EXTS not in line:
            issues.append(f'ad.rule-set: 缺少 pre-matching: {line[:80]}')
        if line.startswith('DOMAIN-SUFFIX,') or line.startswith('DOMAIN,'):
            pass
        elif line.startswith('DOMAIN-WILDCARD,') or line.startswith('IP-CIDR'):
            pass
        else:
            issues.append(f'ad.rule-set: 未知规则类型: {line[:80]}')
    return issues


def _issues_from_modules() -> list[str]:
    issues: list[str] = []
    for path in sorted(MODULE_DIR.glob('*.module')) + sorted(MODULE_DIR.glob('*.sgmodule')):
        text = path.read_text(encoding='utf-8', errors='replace')
        if '[MITM]' not in text:
            continue
        mitm = text.split('[MITM]', 1)[1].split('[', 1)[0]
        if 'hostname' in mitm.lower() and '%APPEND%' not in mitm.upper():
            issues.append(f'{path.name}: [MITM] hostname 未使用 %APPEND%，可能覆盖其他模块')
    return issues


def _issues_from_head_template() -> list[str]:
    path = FACTORY_ROOT / 'template' / 'sr_head.txt'
    text = path.read_text(encoding='utf-8')
    required = (
        'always-reject-url-rewrite = true',
        'udp-policy-not-supported-behaviour = REJECT',
        'bypass-system = true',
    )
    return [f'sr_head.txt: 缺少 {item}' for item in required if item not in text]


def audit(*, max_log: int = 15) -> dict:
    issues: list[str] = []
    issues.extend(_issues_from_head_template())
    issues.extend(_issues_from_rule_set(RESULTANT_DIR / 'ad.rule-set'))
    for name in AD_CONF_NAMES:
        conf = REPO_ROOT / f'{name}.conf'
        if conf.is_file():
            issues.extend(_issues_from_conf(conf))
    issues.extend(_issues_from_modules())

    result = {
        'issue_count': len(issues),
        'issues': issues[:max_log],
    }
    if issues:
        log(f'audit_sr: {len(issues)} compliance issue(s)')
        for item in issues[:max_log]:
            log(f'  - {item}')
        if len(issues) > max_log:
            log(f'  ... and {len(issues) - max_log} more')
    else:
        log('audit_sr: ok (RULE-SET/pre-matching/MITM %APPEND%/General 参数)')
    return result


def main() -> int:
    return 1 if audit()['issue_count'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
