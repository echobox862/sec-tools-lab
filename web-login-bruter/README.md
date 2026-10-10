# web-login-bruter · Web 登录表单弱口令检测

> 需求分析：[docs/04-Web登录爆破-需求分析.md](../docs/04-Web登录爆破-需求分析.md)
> 仅用于本地 DVWA / 自建实验环境（`_mock_server.py` 是配套的本地测试服务）。

## 用法

```bash
python web_bruter.py --url http://127.0.0.1/dvwa/login.php \
    --username admin --wordlist pass.txt \
    [--fail-marker 'Login failed'] [--success-marker ...] [--delay 0.2] [-o report.json]
```

| 参数 | 说明 |
|---|---|
| `--url` | 登录提交地址，必填 |
| `--username` / `--wordlist` | 目标用户名与字典，必填 |
| `--fail-marker` | 失败页特征串（默认 `Login failed`，DVWA 适用） |
| `--success-marker` | 成功页特征串（可选，与 302 Location 双信号） |
| `--no-refresh-token` | token 固定的表单关闭每轮刷新 |
| `--insecure` | 自签名 HTTPS 跳过证书校验 |

## 实现要点（对应实训材料三个核心）

1. **自适应表单解析**：`html.parser` 全量收集 `<input>`，按 `type` 定位用户名/密码框，hidden 字段（含 csrf token）原样携带——不写死字段名，表单变了脚本不失效。
2. **token 两步走**：每轮先 GET 提取最新 token 再 POST（应对一次性/有时效 token；DVWA 实测场景）。
3. **判定校准闸门**：先提交一次错误密码确认链路，运行中连续 3 次无法判定即终止——判定信号是爆破脚本的「眼睛」，信号失效宁可停。

纯标准库实现（urllib + html.parser），无 requests/BeautifulSoup 依赖。
