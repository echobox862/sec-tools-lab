# ssh-bruter · SSH 弱口令检测

> 需求分析：[docs/03-SSH爆破-需求分析.md](../docs/03-SSH爆破-需求分析.md)  
> 仅用于授权测试环境与学习。

## 依赖

```bash
pip install paramiko
```

## 用法

```bash
python ssh_bruter.py -H <host> [-P 22] -u <user> -p <wordlist> \
    [--threads 4] [--max-attempts 1000] [--timeout 5] [--delay 0.2] [-o report.csv]
```

## 实现要点

- **开扫前预检**（`detect_auth_methods`）：读取服务器允许的认证方式，未启用密码认证直接终止——密钥质询-应答没有可枚举的秘密，爆破不成立。
- **每次尝试新建连接**：sshd `MaxAuthTries`（默认 6）会在单连接内累计失败即断开，复用连接反而低效。
- **上限与并发控制**：`--max-attempts`（默认 1000）+ `Semaphore` + 轮间 delay；连续 10 次连接错误判定为被封禁/目标下线，自动终止。
- **AutoAddPolicy 风险声明**：跳过主机指纹校验（中间人风险），学习环境可接受，代码内明示。
- **报告脱敏**：命中密码只展示前 2 位 + 长度。

## 已验证路径

- 字典文件不存在 / 非 UTF-8：启动前报错。
- 目标端口关闭：预检连接失败，明确报错。
- 命中即停，JSON/CSV 报告含完整时间线。
