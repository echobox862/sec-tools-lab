# tests · 单元测试

标准库 `unittest`，零第三方依赖。运行：

```bash
python -m unittest discover -s tests -v
```

## 文件与覆盖范围

| 文件 | 被测模块 | 用例数 | 覆盖 |
|---|---|---|---|
| `test_scanner.py` | port-scanner/scanner.py | 27 | parse_ports 正常/边界/异常 12 例、resolve_host 3 例、scan_port 真实 socket 三态 3 例、scan_host 汇总排序 3 例、导出往返 2 例、CLI 冒烟 1 例 |
| `test_dicgen.py` | dict-generator/dicgen.py | 29 | parse_year_range 8 例、模板校验 8 例（含审计 M1 回归：{} / 孤立花括号 / {0} / {base!r} / {base:>10} / {{}} 保留）、预估 2 例、generate 5 例、write_stream 5 例 |
| `test_ssh_bruter.py` | ssh-bruter/ssh_bruter.py | 24 | mask 4 例、load_wordlist 5 例、attempt/detect 对关闭端口 3 例（paramiko 缺失自动 skip）、brute 流控 5 例（conn_error 连发终止/耗尽/max_attempts/脱敏/报告结构）、CLI 校验 3 例 |
| `test_web_bruter.py` | web-login-bruter/web_bruter.py | 22 | FormParser 3 例、split_fields 3 例、build_payload 2 例、judge 判定 6 例、mask 3 例、mock 服务端到端 5 例（含一次性 token 证据）、小写 location 回归 2 例（审计 M2） |
| `test_tamper.py` | sqlmap-tamper/ 三个脚本 | 14 | 双写变形 8 例、大小写混写 5 例、verify.build_variants/check_semantics（mock 靶场）/load_tamper 6 例 |
| `test_shared.py` | shared/ 公共模块 | 10 | mask_password 边界 4 例（含非 ASCII 按字符截取）、export_report 分支 4 例、shared.load_wordlist 2 例 |

注：`test_scanner` 的 CLI 冒烟与 `test_ssh_bruter` 的 CLI 校验通过 subprocess 起真实进程，
断言退出码与 stderr 文案；`test_tamper` 与 `test_web_bruter` 用 `http.server` 在
`127.0.0.1:0` 起临时服务，无需外部环境。

## 网络相关用例的确定性设计

- **open 判定**：`setUpClass` 在 `127.0.0.1:0` 起真实监听 socket，端口由系统分配，绝不撞车。
- **closed 判定**：Windows 上「刚 close 的监听端口」可能短暂保持接受/超时（TIME_WAIT 行为），
  断言只锁定确定性结论「不可能 open」（closed 或 filtered 均通过）。
- **conn_error 判定**：`127.0.0.1:9`（discard 端口，本机无服务）连接被立即拒绝，无超时等待。
- **verify 语义等价**：mock 靶场按 query 参数返回 200/100 字节差异页，恒真/恒假长度差可精确断言。

## 已知特性（测试固化，非 bug）

- `generate` 对未使用的字段仍做笛卡尔积遍历（如 `{base}{tail}` 在 2 个 year 值下产出
  2 条相同记录），跨模板重复由 `write_stream` 的 dedupe 兜底。
- `estimate_count` 对空字段池按 1 保守高估——防爆闸门宁可高估。
- `tamper` 对 URL 编码片段（`%xx`）采取保守跳过：关键词前后紧邻数字/字母/`%` 时不替换。
- JSON 导出后 tuple 变 list（JSON 无元组类型），roundtrip 断言按此口径。
