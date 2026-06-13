# 规则文件开发说明

这里是规则文件的生成车间，欢迎访问。


## 规则模板

`template/` 目录下为规则模板，`build_confs.py` 脚本运行时会按照模板生成规则文件。

每个规则对应一个模板，不过 `sr_head.txt` 和 `sr_foot.txt` 是例外，这两个文件是所有模板的公共的头部和尾部。


## 手工配置的文件

**manual_direct.txt**

列表，手动编写。记录走直连的域名或 IP。

**manual_proxy.txt**

列表，手动编写。记录走代理的域名或 IP。

**manual_reject.txt**

列表，手动编写。记录需要屏蔽的域名或 IP。

**manual_gfwlist_excludes.txt**

列表，手动编写。记录 gfwlist 误杀的域名或 IP。

**manual_gfwlist.txt**

GFWList 不能无损转换为 SR 规则，所以这里是对 GFWList 的补充。


## 代码及自动生成的文件

**resultant/top500_direct.list**

域名列表，静态备份（2022-05）。原由 `top500.py` 自动生成，因排名数据源失效已不再更新。

**resultant/top500_proxy.list**

域名列表，静态备份（2022-05）。原由 `top500.py` 自动生成，因排名数据源失效已不再更新。

**top500.py**

脚本已停用（站长之家 top500 源不可用）。保留代码供日后恢复；当前构建直接使用 `resultant/top500_*.list` 静态文件。

-----------------------------------

**resultant/ad.rule-set**

广告规则集，由 `ad.py` 从 Cats-Team dns.txt 生成；每行含规则类型，conf 通过 `RULE-SET` 引用。

**resultant/ad.set**

legacy 域名列表（纯域名，无规则类型），仅供统计与旧引用。

**resultant/ad.list**

legacy 镜像，与 `ad.set` 内容一致。

**ad.py**

脚本，从 [Cats-Team AdRules dns.txt](https://github.com/Cats-Team/AdRules/blob/main/dns.txt) 按 **AdGuard DNS 语法** 构建：

| dns.txt | 含义 | 输出 |
|---------|------|------|
| `\|\|domain^` | 域及全部子域 | `ad.rule-set` → `DOMAIN-SUFFIX,domain,REJECT` |
| `\|\|.domain^` | 仅子域（不含根域） | `ad_host` → `*.domain` |
| `127.0.0.1 domain` | 仅精确域（不含子域） | `ad.rule-set` → `DOMAIN,domain,REJECT` |
| `@@...` | 解除对应拦截 | 按文件顺序从集合中移除 |
| `/regex/` | 正则 | 简单 `/^kw\./` → `DOMAIN-KEYWORD` |
| `!` / `#` | 注释 | 跳过 |

构建后由 `audit_ad_dns.py` 校验。

-----------------------------------

**resultant/gfw.list**

域名列表，由 `gfwlist.py` 自动生成。包含 GFWList 所定义的需要走代理的网站。

**resultant/gfw_unhandle.log**

运行日志，由 `gfwlist.py` 自动生成。GFWList 不能无损转换为 SR 规则，这里记录着未能转换的 GFWList 规则。

每当该文件发生变化，需要对应修改 `manual_gfwlist.txt` 文件。

**gfwlist.py**

脚本。解译最新版本的 GFWList。
