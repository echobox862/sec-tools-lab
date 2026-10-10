# port-scanner · TCP 全连接端口扫描器

> 需求分析：[docs/01-端口扫描器-需求分析.md](../docs/01-端口扫描器-需求分析.md)
> 仅用于授权测试环境与学习，请勿对未授权目标使用。

## 用法

```bash
python scanner.py -H <host> -p <ports> [-t timeout] [--threads N] [-o out.csv|out.json]
```

| 参数 | 说明 |
|---|---|
| `-H --host` | 目标主机（IP 或域名），必填 |
| `-p --ports` | 端口描述：`22,80,443` / `1-1024` / 混合，必填 |
| `-t --timeout` | 单端口超时秒数，默认 1.0（0.1–10） |
| `--threads` | 并发数，默认 200（上限 1000） |
| `-o --output` | 导出 `.csv` / `.json` |

## 实现要点

- `connect_ex()` 代替 `connect()`：错误以返回码表达（0=开放），批量场景免去异常控制流。
- 结果三态：`open` / `closed`（明确拒绝）/ `filtered`（超时——**无法区分开放与被防火墙丢弃，报告会提示可信度**）。
- 线程池 + `Semaphore` 控制并发；Ctrl+C 输出已完成部分。

## 示例输出

```
=== 扫描报告 127.0.0.1 (127.0.0.1) ===
超时 0.5s | 用时 0.51s | open 2 / closed 0 / filtered 7 / 共 9
开放端口：135, 445
```
