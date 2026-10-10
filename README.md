# sec-tools-lab

五个安全小工具的实现：端口扫描、弱口令字典生成、SSH 检测、Web 登录检测、sqlmap tamper。
按「原理 → 用轮子 → 造轮子」的顺序从实训材料转化而来，每篇代码先有需求分析（`docs/`），再实现 MVP。

内容仅用于授权测试环境与安全学习。仓库不内置任何真实目标地址与泄露密码字典；字典由工具现场生成，示例统一指向 `127.0.0.1`。

---

## 工具链关系

**01 端口扫描器找门 → 02 字典生成器造钥匙 → 03/04 用钥匙试锁 → 05 在 WAF 在场时把注入打进去。**
02 的输出是 03/04 的 `--wordlist` 输入；01 的输出帮 03 确认 22 端口存活。05 是 sqlmap 插件，独立于前四个。

## 工具索引

| # | 工具 | 一句话 | 依赖 | 需求分析 |
|---|---|---|---|---|
| 01 | [port-scanner](port-scanner/) | TCP 全连接扫描（socket `connect_ex` + 短超时 + 多线程） | 纯标准库 | [docs/01](docs/01-端口扫描器-需求分析.md) |
| 02 | [dict-generator](dict-generator/) | 模板规则弱口令字典，生成器流式输出 + 预估防爆 | 纯标准库 | [docs/02](docs/02-字典生成器-需求分析.md) |
| 03 | [ssh-bruter](ssh-bruter/) | SSH 弱口令检测：认证方式预检 + 每次尝试新建连接 | paramiko | [docs/03](docs/03-SSH爆破-需求分析.md) |
| 04 | [web-login-bruter](web-login-bruter/) | 登录表单检测：自适应表单解析 + csrf token 两步走 + 判定校准 | 纯标准库 | [docs/04](docs/04-Web登录爆破-需求分析.md) |
| 05 | [sqlmap-tamper](sqlmap-tamper/) | 关键字双写 / 大小写混写 tamper + 语义等价独立验证 | sqlmap 环境使用 | [docs/05](docs/05-sqlmap-tamper-需求分析.md) |

## 统一约定

- Python 3.10+；除 03 的 paramiko 外全部标准库。
- CLI 一律 argparse（实训材料的 optparse 已废弃）；一切网络操作显式超时；结果支持 CSV / JSON 导出。
- 所有输入先校验再使用：端口范围、文件存在性、编码、超时上下界、并发上限。
- 验证类动作只读不破坏（POC 纪律）：证明漏洞存在即止，不做写操作。
- 跨工具公共逻辑收敛在 [`shared/`](shared/)：报告脱敏（`masking.py`）、JSON/CSV 导出（`report_io.py`）、字典读取（`wordlist.py`）。

## 技术栈

| 层 | 选型 |
|---|---|
| 语言 | Python 3.10+（仅 03 需要 3.7+ 即可，统一按 3.10 要求） |
| 并发 | `threading` + `ThreadPoolExecutor`（任务均为 I/O 密集） |
| 网络 | `socket` / `urllib`（04 全程标准库，未用 requests） |
| 第三方依赖 | 仅 `paramiko`（03 SSH 协议无法用标准库实现） |
| 测试 | 标准库 `unittest`，126 个用例 |

## 安装

```bash
git clone https://github.com/echobox862/sec-tools-lab.git
cd sec-tools-lab
pip install -r requirements.txt   # 仅安装 paramiko；其余工具无第三方依赖
```

可选：05 的语义验证需要一个本地 sqli-labs（Docker 镜像即可）；04 附带 `_mock_server.py` 本地测试服务，不依赖任何外部靶场。

## 仓库结构与测试

```
sec-tools-lab/
├─ shared/            # 公共模块：masking / report_io / wordlist
├─ docs/              # 需求分析（开发依据）
├─ tests/             # 标准库 unittest 测试套件
├─ port-scanner/      # 01
├─ dict-generator/    # 02
├─ ssh-bruter/        # 03
├─ web-login-bruter/  # 04（含 _mock_server.py 本地端到端测试服务）
└─ sqlmap-tamper/     # 05
```

测试：`python -m unittest discover -s tests`（126 用例，全部标准库实现；网络相关用例只依赖 127.0.0.1 回环与本机 socket，无需外部环境）。

## 快速开始

```bash
# 01 扫描本机
python port-scanner/scanner.py -H 127.0.0.1 -p 135,445,3389 -o report.csv

# 02 生成小字典
python dict-generator/dicgen.py --base admin --years 2024-2026 --tails 123 \
    --templates '{base}{year},{base}{tail}' -o pass.txt

# 03 SSH 检测（需 pip install paramiko）
python ssh-bruter/ssh_bruter.py -H 127.0.0.1 -u root -p pass.txt

# 04 登录表单检测（本地 DVWA）
python web-login-bruter/web_bruter.py --url http://127.0.0.1/dvwa/login.php \
    --username admin --wordlist pass.txt

# 05 tamper 自测 + 语义验证
python sqlmap-tamper/double_keywords.py
python sqlmap-tamper/verify.py --url http://127.0.0.1/sqli-labs/Less-8/ --param id \
    --tamper sqlmap-tamper/double_keywords.py
```

## 关于我

- 方向：**安全服务 / 渗透测试（Web 方向）**，西电网络空间安全 2027 届
- 复现笔记与判断框架：[security-portfolio](https://github.com/echobox862/security-portfolio)
- GitHub：[@echobox862](https://github.com/echobox862)
