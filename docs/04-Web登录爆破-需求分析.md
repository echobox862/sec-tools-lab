# 04 Web 登录爆破 · 需求分析

> 来源：`Python网站用户暴力破解.pdf`（16 页）+ 实训精讲第 6 篇
> 学习主线：爆破原理（字典驱动）→ csrf_token 障碍 → 单线程实现 → 自适应表单解析 + 多线程

---

## 1. 核心业务对象与关键属性

### LoginForm（登录表单描述——本工具的灵魂）

| 属性 | 类型 | 说明 |
|---|---|---|
| `url` | str | 登录提交地址 |
| `field_map` | dict[str,str] | **从页面自动提取**：input name → 当前 value（含全部 hidden 字段，如 `user_token`）。**不写死字段名**——实训核心设计：`BeautifulSoup.find_all('input')` 全量抓取后按 `type='text'`/`type='password'` 定位用户名/密码框，其余字段原样携带，脚本对表单变化自适应 |
| `success_marker` | str | 成功判定特征（默认自动校准，可 `--success-marker` 覆盖） |
| `fail_marker` | str | 失败判定特征（如 DVWA 的 `'Login failed'`） |
| `encoding` | str | 响应编码，强制 `req.encoding = 'UTF-8'`——实训高频坑：requests 猜错编码会导致中文页关键字匹配失败 |

### AttemptResult

| 属性 | 说明 |
|---|---|
| `password` | 本轮候选 |
| `outcome` | `success` / `fail` / `unknown`（两个 marker 都未命中——判定信号失效，需告警） |
| `status_code` / `redirect_to` | 状态码与重定向目标（成功常伴随 302 跳转） |

### BruteReport

同 03 的结构（attempts / found / stop_reason / timeline），另有 `marker_check`：开扫前自动校准记录。

## 2. 接口定义

```python
def fetch_form(session: requests.Session, url: str) -> LoginForm:
    """GET 登录页 → BeautifulSoup 解析 → 返回含全部字段（含 token）的 LoginForm"""

def build_payload(form: LoginForm, username: str, password: str) -> dict[str, str]:
    """复制 form.field_map（保留 token 等隐藏字段原值），仅替换用户名/密码两个字段"""

def attempt(session, form: LoginForm, username: str, password: str,
            refresh_token: bool) -> AttemptResult:
    """单次尝试。refresh_token=True 时先重新 GET 提取新 token 再 POST
    （应对 token 一次性使用/有时效的服务器策略——实训材料明确的服务器行为）"""

def calibrate(session, form, username, wrong_pwd) -> bool:
    """开扫前校准（链路校验）：提交一次确定错误的密码，验证请求链路与 fail_marker 可用。
    注意：实现为链路校验而非「一真一假信号区分校验」——爆破前拿不到真密码；
    marker 是否会把成功误判为失败，由运行期 unknown 连发终止兜底。
    可靠用法：--success-marker 显式指定成功页特征。"""

def brute(url, username, wordlist_path, threads=1, delay=0.2,
          refresh_token=True) -> BruteReport:
    """主流程；每线程独立 requests.Session（会话/Cookie 隔离，不共享）"""

CLI: python web_bruter.py --url <login_url> --username admin --wordlist pass.txt \
     [--threads 1] [--delay 0.2] [--fail-marker 'Login failed'] \
     [--success-marker ...] [--no-refresh-token]
```

## 3. 实现步骤与模块依赖顺序

```
第1步 fetch_form        （requests + BeautifulSoup；对本地 DVWA 先手工跑通）
第2步 build_payload     （依赖1；验证 hidden 字段被完整携带）
第3步 attempt           （依赖1+2；单线程，含 refresh_token 两步走）
第4步 calibrate         （依赖3；开扫前的链路校验闸门）
第5步 brute + 报告      （依赖4；先单线程，多线程为 P1）
第6步 CLI
```

**为什么 csrf_token 处理排在核心**：实训材料用一次失败讲透它——不提交 `user_token` 时服务器直接拒绝并返回 `CSRF token is incorrect`。**破解思路不是「破 token」，而是像浏览器一样「先 GET 取 token、再 POST 带上」**——每次尝试都是完整的「访问→提交」两步。

## 4. 边界条件与异常场景

| # | 场景 | 触发条件 | 预期行为 |
|---|---|---|---|
| 1 | 页面结构不符 | URL 不是登录页 / 无 form | fetch_form 报「未找到 input 字段」，提示人工确认 URL |
| 2 | token 每次轮换 | 服务器一次性 token | refresh_token=True 默认开启；每轮重新 GET |
| 3 | 判定信号失效 | 页面改版 / marker 不匹配 | outcome=unknown；连续 3 次 unknown → **终止并提示重新校准**（宁可停也不瞎跑） |
| 4 | 校准失败 | calibrate 阶段请求不可达或表单异常 | 拒绝开扫，输出失败原因供人工分析；marker 对成功页是否适用由 unknown 连发终止兜底 |
| 5 | 编码问题 | 响应实际为 UTF-8 但 requests 误判 | 强制 `req.encoding='UTF-8'`（实训原做法） |
| 6 | 账号锁定策略 | 目标连续失败锁定（同方言项目 5 次锁定逻辑） | delay 默认 0.2s + threads 默认 1；README 明示「目标可能有锁定策略，优先小字典」 |
| 7 | 出现验证码 | 响应含 captcha 特征 | 检测到常见验证码字段名（captcha/verify）→ 终止并提示「超出工具范围」 |
| 8 | 成功伴随重定向 | 302 → index.php | allow_redirects=False；以 Location + marker 双信号判定 |
| 9 | HTTPS 证书无效 | 自签名证书 | `verify=False` + 启动时显式警告（学习环境） |
| 10 | 限速响应 | HTTP 429 / 连续超时 | 指数退避（delay 翻倍，上限 10s），连续 5 次终止 |
| 11 | 空字典 | 0 行 | 启动前校验退出 |
| 12 | Session 串扰 | 多线程共享 Session | 明确禁止：每线程独立 Session（Cookie/CSRF 状态隔离） |
| 13 | KeyboardInterrupt | 中断 | 输出 partial 报告 |

## 5. MVP 划分

**必须实现（P0）**：fetch_form 自适应解析 / build_payload 隐藏字段透传 / attempt 两步走（GET token→POST）/ calibrate 校准闸门 / fail/success marker 可配置 / 单线程 + delay / argparse。

**P1**：多线程（每线程独立 Session）；cookie 字典/JSON 输入自定义字段映射（覆盖非标准表单）。

**暂时不做（P2）**：验证码识别（另一量级问题）、Headless 浏览器（Selenium/Playwright）、代理池、分布式、JS 渲染页面。

## 6. 验收标准

- 对本地 DVWA（admin/password）跑 10 词字典：命中；日志可见每轮 token 值不同。
- 对 token 固定的表单 `--no-refresh-token` 生效。
- 人为改错 fail-marker：3 次 unknown 后自动终止。
- 报告 CSV 含时间线与 outcome 分布。
