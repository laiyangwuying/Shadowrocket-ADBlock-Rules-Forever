# -*- coding: utf-8 -*-

import re
import time

# confs names in template/ and ../
# except sr_head and sr_foot
confs_names = [
    'sr_top500_banlist_ad',
    'sr_top500_banlist',
    'sr_top500_whitelist_ad',
    'sr_top500_whitelist',
    'sr_adb',
    'sr_direct_banad',
    'sr_proxy_banad',
    'sr_cnip', 'sr_cnip_ad',
    'sr_backcn', 'sr_backcn_ad',
    'sr_ad_only'
]


def _rule_line_from_plain_entry(content: str, kind: str) -> str | None:
    """
    将 gfw.manual 列表中的一条（可无 FULL: 前缀）转为一条 SR 规则行。
    FULL:主机名 → DOMAIN（先于 DOMAIN-SUFFIX 匹配更稳妥）。
    """
    if not content:
        return None
    prefix = 'DOMAIN-SUFFIX'
    if content.startswith('FULL:'):
        prefix = 'DOMAIN'
        content = content[5:]
    if not content:
        return None

    if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', content):
        prefix = 'IP-CIDR'
        if '/' not in content:
            content += '/32'
    elif re.match(
        r'((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?',
        content,
    ):
        prefix = 'IP-CIDR'
        if '/' not in content:
            content += '/128'
    elif '.' not in content and len(content) > 1:
        prefix = 'DOMAIN-KEYWORD'

    return prefix + ',%s,%s\n' % (content, kind)


def getRulesStringFromFile(path, kind):
    file = open(path, 'r', encoding='utf-8')
    contents = file.readlines()
    ret = ''

    for content in contents:
        content = content.strip('\r\n')
        if not len(content):
            continue

        if content.startswith('#'):
            ret += content + '\n'
        else:
            ln = _rule_line_from_plain_entry(content, kind)
            if ln:
                ret += ln

    return ret


def getMergedGfwRulesString(kind: str) -> str:
    """
    合并 gfw.list 与 manual_gfwlist：注释按文件顺序保留；
    规则先输出全部 FULL:（生成 DOMAIN），再输出其余（多为 DOMAIN-SUFFIX），便于优先匹配精确主机名。
    """
    ret = ''
    full_hosts: set[str] = set()
    suffix_raw: list[str] = []
    for path in ('resultant/gfw.list', 'manual_gfwlist.txt'):
        with open(path, 'r', encoding='utf-8') as fp:
            for raw in fp:
                line = raw.strip('\r\n')
                if not line:
                    continue
                if line.startswith('#'):
                    ret += line + '\n'
                    continue
                if line.startswith('FULL:'):
                    h = line[5:].strip()
                    if h:
                        full_hosts.add(h)
                else:
                    suffix_raw.append(line)

    for h in sorted(full_hosts):
        ln = _rule_line_from_plain_entry('FULL:' + h, kind)
        if ln:
            ret += ln
    for line in sorted(set(suffix_raw)):
        ln = _rule_line_from_plain_entry(line, kind)
        if ln:
            ret += ln
    return ret


# get head / foot（直接使用模板，不再合并 append_urls / vendor 模块）
str_head = open('template/sr_head.txt', 'r', encoding='utf-8').read()
with open('template/sr_foot.txt', 'r', encoding='utf-8') as _ff:
    str_foot = _ff.read()


# make values
values = {}

values['build_time'] = time.strftime("%Y-%m-%d %H:%M:%S")

values['top500_proxy']  = getRulesStringFromFile('resultant/top500_proxy.list', 'Proxy')
values['top500_direct'] = getRulesStringFromFile('resultant/top500_direct.list', 'Direct')

values['ad'] = getRulesStringFromFile('resultant/ad.list', 'Reject')

values['manual_direct'] = getRulesStringFromFile('manual_direct.txt', 'Direct')
values['manual_proxy']  = getRulesStringFromFile('manual_proxy.txt', 'Proxy')
values['manual_reject'] = getRulesStringFromFile('manual_reject.txt', 'Reject')

values['gfwlist'] = getMergedGfwRulesString('Proxy')


# make confs
# release 分支上的 raw（与 Actions 发布的 Pages/默认下载一致）
RELEASE_RAW_BASE = (
    'https://raw.githubusercontent.com/laiyangwuying/'
    'Shadowrocket-ADBlock-Rules-Forever/refs/heads/release/'
)

for conf_name in confs_names:
    values['release_update_url'] = RELEASE_RAW_BASE + conf_name + '.conf'

    file_template = open('template/'+conf_name+'.txt', 'r', encoding='utf-8')
    template = file_template.read()
  
    if conf_name != 'sr_ad_only':
        template = str_head + template + str_foot
    # sr_ad_only：仅规则段（template/sr_ad_only.txt），不带 head/foot
    file_output = open('../'+conf_name+'.conf', 'w', encoding='utf-8')

    # 【修正 1】改为非贪婪匹配 `.+?`，防止多变量同行时串行
    marks = re.findall(r'{{(.+?)}}', template)

    for mark in marks:
        # 【修正 2】安全检查：只有当标记存在于 values 字典中才执行替换，否则静默保留，彻底避免 KeyError 崩溃
        if mark in values:
            template = template.replace('{{'+mark+'}}', values[mark])

    file_output.write(template)
