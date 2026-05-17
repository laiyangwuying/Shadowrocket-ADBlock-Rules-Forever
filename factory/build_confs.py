# -*- coding: utf-8 -*-

import re
import sys
import time

from append_modules import apply_append_to_foot


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
            prefix = 'DOMAIN-SUFFIX'
            if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', content):
                prefix = 'IP-CIDR'
                if '/' not in content:
                    content += '/32'
            elif re.match(r'((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?', content):
                prefix = 'IP-CIDR'
                if '/' not in content:
                    content += '/128'
            elif '.' not in content and len(content) > 1:
                prefix = 'DOMAIN-KEYWORD'

            ret += prefix + ',%s,%s\n' % (content, kind)

    return ret


def _append_log(message: str) -> None:
    print(message, file=sys.stderr)


# get head and foot（sr_foot 合并 append_urls.txt 抓取的远端模块片段）
str_head = open('template/sr_head.txt', 'r', encoding='utf-8').read()
with open('template/sr_foot.txt', 'r', encoding='utf-8') as _ff:
    _foot_src = _ff.read()
str_foot, sr_ad_only_extra = apply_append_to_foot(_foot_src, _append_log)


# make values
values = {}

values['build_time'] = time.strftime("%Y-%m-%d %H:%M:%S")

values['top500_proxy']  = getRulesStringFromFile('resultant/top500_proxy.list', 'Proxy')
values['top500_direct'] = getRulesStringFromFile('resultant/top500_direct.list', 'Direct')

values['ad'] = getRulesStringFromFile('resultant/ad.list', 'Reject')

values['manual_direct'] = getRulesStringFromFile('manual_direct.txt', 'Direct')
values['manual_proxy']  = getRulesStringFromFile('manual_proxy.txt', 'Proxy')
values['manual_reject'] = getRulesStringFromFile('manual_reject.txt', 'Reject')

values['gfwlist'] = getRulesStringFromFile('resultant/gfw.list', 'Proxy') \
                  + getRulesStringFromFile('manual_gfwlist.txt', 'Proxy')


# make confs
for conf_name in confs_names:
    file_template = open('template/'+conf_name+'.txt', 'r', encoding='utf-8')
    template = file_template.read()
  
    if conf_name != 'sr_ad_only':
        template = str_head + template + str_foot
    else:
        extra = sr_ad_only_extra.strip('\n')
        if extra:
            template = template.rstrip('\n') + '\n\n' + extra + '\n'

    file_output = open('../'+conf_name+'.conf', 'w', encoding='utf-8')

    # 【修正 1】改为非贪婪匹配 `.+?`，防止多变量同行时串行
    marks = re.findall(r'{{(.+?)}}', template)

    for mark in marks:
        # 【修正 2】安全检查：只有当标记存在于 values 字典中才执行替换，否则静默保留，彻底避免 KeyError 崩溃
        if mark in values:
            template = template.replace('{{'+mark+'}}', values[mark])

    file_output.write(template)
