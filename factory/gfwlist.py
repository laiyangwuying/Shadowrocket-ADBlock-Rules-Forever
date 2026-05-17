# -*- coding: utf-8 -*-

#
# 下载并解析最新版本的 GFWList
# 对于混合性质的网站，尽量走代理（忽略了所有的@@指令）
#
# resultant/gfw.list：full: 导出为 FULL:主机名 → build_confs 生成 DOMAIN（完整匹配）；其余为后缀 → DOMAIN-SUFFIX
# 数据源：github.com/Loyalsoldier/v2ray-rules-dat
#


import time
import requests
import re
import base64


unhandle_rules = []

# ruleType for raw or base64
def get_rule(rules_url, ruleType='raw'):
    success = False
    try_times = 0
    r = None
    while try_times < 5 and not success:
        r = requests.get(rules_url)
        if r.status_code != 200:
            time.sleep(1)
            try_times = try_times + 1
        else:
            success = True
            break

    if not success:
        raise Exception('error in request %s\n\treturn code: %d' % (rules_url, r.status_code) )

    if ruleType == 'base64':
        rule = base64.b64decode(r.text) \
                .decode("utf-8") \
                .replace('\\n', '\n')
    else:
        rule = r.text

    return rule


# 导出到 resultant/gfw.list：full: 前缀保留为条目 FULL:<hostname>，供生成 DOMAIN（精确）；否则为后缀 DOMAIN-SUFFIX。
_FULL_MARK = 'FULL:'


def clear_format(rule):
    rules = []

    for raw in rule.split('\n'):
        row = raw.strip()

        # 注释 / 例外 / GFWList 类规则：不导入为 SR 域名
        if (
            row == ''
            or row.startswith('!')
            or row.startswith('@@')
            or row.startswith('[AutoProxy')
            or row.lower().startswith('regexp:')
        ):
            continue

        # 清除前缀
        row = re.sub(r'^\|?https?://', '', row)
        row = re.sub(r'^\|\|', '', row)

        is_full_host = bool(re.match(r'(?i)^full:', row))
        if is_full_host:
            row = re.sub(r'(?i)^full:', '', row)
        elif re.match(r'(?i)^domain:', row):
            row = re.sub(r'(?i)^domain:', '', row)

        # 后缀类规则才去前导 .*；full 精确主机名保持不变
        if not is_full_host:
            row = row.lstrip('.*')

        # 清除后缀
        row = row.rstrip('/^*')

        # 去掉前缀后若以 regexp: 开头则丢弃（SR 无此类型）
        if row == '' or row.lower().startswith('regexp:'):
            continue

        rules.append(_FULL_MARK + row if is_full_host else row)

    return rules


def filtrate_rules(rules, excludes=[]):
    ret = []

    for rule in rules:
        rule0 = rule

        body = rule[len(_FULL_MARK) :] if rule.startswith(_FULL_MARK) else rule

        # only hostname
        if '/' in body:
            split_ret = body.split('/')
            body = split_ret[0]

        if not re.match(r'^[\w.-]+$', body):
            unhandle_rules.append(rule0)
            continue

        is_full_match = rule.startswith(_FULL_MARK)
        canonical = _FULL_MARK + body if is_full_match else body

        if body in excludes:
            continue
        skip_flag = 0
        for exclude in excludes:
            if re.search(exclude, body):
                skip_flag = 1
                break
        if skip_flag == 0:
            ret.append(canonical)


    ret = list(set(ret))
    ret.sort()

    return ret

def getURLs(url):
    r = requests.get(url)
    return r.text.split("\n")[:-1]

# main
#rule = get_rule(rules_url='https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt', ruleType='base64')
# 从 https://github.com/Johnshall/cn-blocked-domain 中获取GFWList的补充
# rule += get_rule('https://raw.githubusercontent.com/Johnshall/cn-blocked-domain/release/domains.txt')
rule = get_rule('https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/gfw.txt')
rule += get_rule('https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/proxy-list.txt')

rules = clear_format(rule)

excludes = []
with open('manual_gfwlist_excludes.txt', 'r', encoding='utf-8') as f:
    for line in f.readlines():
        if line[0] == "#" or line == "\n":
            continue
        excludes.append(line.strip())

rules = filtrate_rules(rules, excludes)

# 双源合并后再去重；sorted 保证输出稳定（filtrate_rules 内已 set 一次，此处覆盖两文件合并后的重复项）
rules = sorted(set(rules))

open('resultant/gfw.list', 'w', encoding='utf-8') \
    .write('\n'.join(rules))

open('resultant/gfw_unhandle.log', 'w', encoding='utf-8') \
    .write('\n'.join(unhandle_rules))
