# 03 SSH 爆破 · 需求分析

> 来源：`ssh暴力破解.pdf`（16 页）+ 实训精讲第 6 篇
> 学习主线：SSH 两种认证（密码 vs 密钥质询-应答）→ Metasploit ssh_login 模块的参数设计 → paramiko 自写

---

## 1. 核心业务对象与关键属性

### SshTarget（目标）

| 属性 | 类型 | 说明 | 校验 |
|---|---|---|---|
| `host` | str | IP 或域名 | 必填；先经 01 端口扫描确认 22 端口 open |
| `port` | int | 默认 22 | 1–65535 |
| `username` | str | 目标账号 | 必填（MVP 单用户；多用户对照字典 P2） |
| `timeout` | float | 连接超时，默认 5.0 | paramiko 的 banner_timeout / auth_timeout 同步使用 |

### AttemptResult（单次尝试）

| 属性 | 类型 | 说明 |
|---|---|---|
| `password` | str | 本轮候选密码 |
| `success` | bool | 是否登录成功 |
| `reason` | enum | `auth_fail`（密码错）/ `auth_disabled`（服务器禁用密码认证——**发现后立即整场终止**）/ `max_reached`（触发 MaxAuthTries 断开）/ `conn_error` / `timeout` |

### BruteReport（整场报告）

| 属性 | 说明 |
|---|---|
| `attempts` / `tried` | 计划/实际尝试数 |
| `found` | 命中的密码或 None |
| `stop_reason` | `found` / `exhausted` / `auth_disabled` / `max_attempts` / `user_abort` |
| `timeline` | 每次尝试的时间戳（分析速率用） |

## 2. 接口定义

```python
def detect_auth_methods(host: str, port: int, timeout: float) -> list[str]:
    """预检：读取服务器允许的认证方式。返回如 ['password'] 或 ['publickey']；
    若不含 password —— 直接终止并说明（密钥认证不可爆破：质询-应答机制没有可枚举的秘密）"""

def attempt(host: str, port: int, username: str, password: str,
            timeout: float) -> AttemptResult:
    """单次尝试。paramiko.SSHClient + AutoAddPolicy + connect(...)；
    每次尝试独立新建连接（应对 sshd MaxAuthTries 默认 6 的单连接失败上限）"""

def load_wordlist(path: str) -> Iterator[str]:
    """流式读取字典（一行一条），文件不存在/编码错误提前报错"""

def brute(target: SshTarget, wordlist_path: str, threads: int = 4,
          max_attempts: int = 1000, delay: float = 0.2) -> BruteReport:
    """主流程：预检 → 并发消费字典 → 命中即停；
    connection_lock 保护共享计数；delay 为轮内间隔（降低触发 fail2ban 概率）"""

CLI: python ssh_bruter.py -H <host> [-P 22] -u <user> -p <wordlist> \
     [--threads 4] [--max-attempts 1000] [--timeout 5]
```

## 3. 实现步骤与模块依赖顺序

```
第1步 load_wordlist     （无依赖，文件 IO 先行）
第2步 attempt           （依赖 paramiko；对本地/实验机单次验证）
第3步 detect_auth_methods（依赖2的连接层；在 main 前置调用）
第4步 brute             （依赖1+2+3；先单线程跑通，再上 Semaphore 并发）
第5步 报告与导出        （复用 01 的 CSV/JSON 约定）
第6步 CLI               （optparse → argparse 现代化改造）
```

关键设计决策（均出自实训材料与精讲补充）：
1. **每次尝试新建连接**——`MaxAuthTries`（默认 6）会在单连接内累计失败即断开，复用连接反而低效。
2. **AutoAddPolicy 必须写注释说明风险**——自动接受主机指纹 = 不校验服务器身份，存在中间人风险；学习环境可接受，代码里明示。
3. **`connection_lock` + max_attempts=1000 上限**——实训原设计；控制并发与总次数既保护目标也保护自己。

## 4. 边界条件与异常场景

| # | 场景 | 触发条件 | 预期行为 |
|---|---|---|---|
| 1 | 服务器仅密钥认证 | detect 返回不含 password | **开扫前终止**，输出「该目标禁用密码认证，爆破不可行」（这正是「加密保护传输、不保护认证强度」的反面：密钥认证连猜的入口都没有） |
| 2 | 字典文件不存在 | 路径错误 | 启动前校验，报错退出 |
| 3 | 字典编码错误 | GBK/二进制文件 | 按 UTF-8 读，异常行跳过并计数，结束时报「跳过 N 行」 |
| 4 | 触发 MaxAuthTries | 单连接多次失败 | 已按「每次新建连接」规避；若仍出现（reason=max_reached）计入统计 |
| 5 | fail2ban 封禁 | 连续 conn_error 且集中爆发 | 检测到连续 10 次 conn_error → 终止并提示「疑似被封禁」 |
| 6 | 网络超时 | timeout 触发 | 记 reason=timeout，不中断整场（偶发）；连续超时按场景 5 处理 |
| 7 | 空字典 / 字典耗尽 | 0 行或已全部尝试 | stop_reason=exhausted，正常报告 |
| 8 | 命中密码 | success=True | 立即停止分发新任务，等待在途线程结束后输出报告（**不在报告中明文展示密码全文，只展示前 2 位+长度**——展示友好与留证平衡） |
| 9 | SSH 版本不兼容 | SSH 9.x 禁用 ssh-rsa 协商失败 | 捕获认证协商异常，单独归类提示「算法协商失败≠端口不通」（精讲补充点） |
| 10 | Ctrl+C | 用户中断 | stop_reason=user_abort，输出 partial 报告 |
| 11 | 目标为 Windows | 无 SSH 服务 | 连接拒绝 → conn_error，提示用 01 确认端口 |
| 12 | 并发共享状态 | 多线程同时更新计数 | connection_lock 保证；计数器错乱为必须测试项 |

## 5. MVP 划分

**必须实现（P0）**：attempt 单次封装 / detect_auth_methods 预检 / 每次新建连接 / max_attempts 上限 / argparse 参数化（-H -P -u -p 全部参数化——实训材料「参数化是从脚本到工具的一步」）/ 报告导出。

**P1**：多线程（threads 默认 4，Semaphore 控制）；USER_PASS_FILE 对照字典模式（对应 msf 的 `USER_PASS_FILE`，即 Burp Pitchfork 思路）。

**暂时不做（P2）**：密钥/私钥文件爆破（密钥认证质询-应答不可枚举，做了无学习意义）；多用户并发；分布式；连接池复用。

## 6. 验收标准

- 对本地 Docker sshd（已知弱口令）跑 10 词字典：能命中并输出报告。
- 对 `PasswordAuthentication no` 的目标：预检阶段即终止并给出正确解释。
- 断网/关目标：连续错误归类 conn_error 并按规则终止。
- `--max-attempts 5` 生效：字典 100 词只尝试 5 次。
