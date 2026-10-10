#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
port-scanner · TCP 全连接端口扫描器（学习用 MVP）

原理：socket.connect_ex() 完整三次握手，返回码 0 即端口开放；
     短超时把「卡住」变成「快速失败」；I/O 密集任务多线程有效（GIL 在等待时释放）。

仅用于授权测试环境与学习。请勿对未授权目标使用。
"""
import argparse
import errno
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # 仓库根，供 import shared

from shared.report_io import export_report  # noqa: E402

BANNER = "[i] 仅用于授权测试环境与学习，请勿对未授权目标使用。"
MAX_THREADS = 1000
MAX_PORTS = 65535
# connect_ex 返回码 -> closed 的跨平台集合：
#   Windows winerror 10061（WSAECONNREFUSED）、Linux errno 111、macOS errno 61
_CLOSED_ERRNOS = (10061, 111, errno.ECONNREFUSED)


class ScanTargetError(ValueError):
    pass


def parse_ports(spec):
    """解析 '22,80,443' / '1-1024' / 混合写法 -> 排序去重端口列表。非法输入抛 ScanTargetError。"""
    if not spec or not spec.strip():
        raise ScanTargetError("端口描述为空，示例：22,80,443 或 1-1024")
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            raise ScanTargetError(f"端口描述存在空段：{spec!r}")
        if "-" in part:
            lo, _, hi = part.partition("-")
            try:
                lo, hi = int(lo), int(hi)
            except ValueError:
                raise ScanTargetError(f"端口范围格式非法：{part!r}")
            if not (1 <= lo <= 65535 and 1 <= hi <= 65535):
                raise ScanTargetError(f"端口超出 1-65535：{part!r}")
            if lo > hi:
                raise ScanTargetError(f"端口范围起止倒置：{part!r}")
            if hi - lo + 1 > MAX_PORTS:
                raise ScanTargetError(f"端口范围过大：{part!r}")
            ports.update(range(lo, hi + 1))
        else:
            try:
                p = int(part)
            except ValueError:
                raise ScanTargetError(f"端口不是数字：{part!r}")
            if not (1 <= p <= 65535):
                raise ScanTargetError(f"端口超出 1-65535：{p}")
            ports.add(p)
    if len(ports) > MAX_PORTS:
        raise ScanTargetError(f"端口总数 {len(ports)} 超过上限 {MAX_PORTS}")
    return sorted(ports)


def resolve_host(host):
    """域名/IP 统一解析为 IP；失败抛 ScanTargetError。"""
    host = host.strip()
    if not host:
        raise ScanTargetError("目标主机为空")
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        return infos[0][4][0]
    except socket.gaierror:
        raise ScanTargetError(f"DNS 解析失败：{host}")
    except OSError as e:
        raise ScanTargetError(f"地址解析异常：{host} ({e})")


def scan_port(ip, port, timeout):
    """单端口 TCP 全连接扫描。返回 (port, status, elapsed_ms)。
    status: open(返回码0) / closed(明确拒绝) / filtered(超时或不可达，无法区分开放还是被丢弃)"""
    start = time.monotonic()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        code = s.connect_ex((ip, port))
        elapsed_ms = (time.monotonic() - start) * 1000
        if code == 0:
            status = "open"
        elif code in _CLOSED_ERRNOS:
            status = "closed"
        else:
            status = "filtered"
        return port, status, round(elapsed_ms, 1)
    except OSError:
        # 超时 / 网络不可达等：目标级问题，标记 filtered 并由上层统计
        return port, "filtered", round((time.monotonic() - start) * 1000, 1)
    finally:
        s.close()


def scan_host(host, ports, timeout=1.0, max_threads=200):
    """多线程扫描。返回 report dict。

    线程模型：ThreadPoolExecutor 固定 workers 个线程消费任务队列——
    线程创建数受 max_workers 硬约束（全表 65535 端口也只创建 workers 个线程），
    替代早期「每端口一个线程」的无界创建。
    """
    ip = resolve_host(host)
    workers = max(1, min(max_threads, MAX_THREADS))
    results = []
    interrupted = False

    started = datetime.now()
    executor = ThreadPoolExecutor(max_workers=workers)
    try:
        futures = [executor.submit(scan_port, ip, p, timeout) for p in ports]
        # scan_port 内部已捕获全部 OSError，fut.result() 不会抛
        for future in as_completed(futures):
            results.append(future.result())
    except KeyboardInterrupt:
        interrupted = True
        print("\n[!] 用户中断，输出已完成部分", file=sys.stderr)
    finally:
        executor.shutdown(wait=not interrupted, cancel_futures=interrupted)

    summary = {"open": 0, "closed": 0, "filtered": 0, "total": len(results)}
    for _, status, _ in results:
        summary[status] += 1
    summary["elapsed_s"] = round((datetime.now() - started).total_seconds(), 2)
    if summary["total"] > 0 and summary["filtered"] == summary["total"]:
        summary["note"] = "全部 filtered：未收到任何响应，结果可信度低（目标可能不在线或被防火墙丢弃）"
    return {
        "host": host, "ip": ip, "timeout": timeout,
        "started_at": started.isoformat(timespec="seconds"),
        "results": sorted(results, key=lambda r: r[0]),
        "summary": summary,
    }


def export_csv(report, path):
    export_report(
        report, path,
        csv_header=["port", "status", "elapsed_ms"],
        csv_rows=([port, status, ms] for port, status, ms in report["results"]),
        message=f"[+] CSV 已写入 {path}")


def export_json(report, path):
    export_report(
        report, path,
        csv_header=None, csv_rows=None,
        message=f"[+] JSON 已写入 {path}")


def print_report(report):
    s = report["summary"]
    print(f"\n=== 扫描报告 {report['host']} ({report['ip']}) ===")
    print(f"超时 {report['timeout']}s | 用时 {s['elapsed_s']}s | "
          f"open {s['open']} / closed {s['closed']} / filtered {s['filtered']} / 共 {s['total']}")
    opens = [str(p) for p, st, _ in report["results"] if st == "open"]
    if opens:
        print(f"开放端口：{', '.join(opens)}")
    else:
        print("开放端口：无")
    if s.get("note"):
        print(f"[!] {s['note']}")


def build_parser():
    ap = argparse.ArgumentParser(
        prog="scanner.py",
        description="TCP 全连接端口扫描器（学习用，仅限授权目标）",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-H", "--host", required=True, help="目标主机（IP 或域名）")
    ap.add_argument("-p", "--ports", required=True,
                    help="端口描述：22,80,443 或 1-1024 或混合")
    ap.add_argument("-t", "--timeout", type=float, default=1.0,
                    help="单端口超时秒数（默认 1.0，范围 0.1-10）")
    ap.add_argument("--threads", type=int, default=200,
                    help=f"并发线程数（默认 200，上限 {MAX_THREADS}）")
    ap.add_argument("-o", "--output", help="结果导出路径：.csv 或 .json 后缀")
    return ap


def main(argv=None):
    print(BANNER)
    ap = build_parser()
    args = ap.parse_args(argv)

    try:
        if not (0.1 <= args.timeout <= 10.0):
            raise ScanTargetError(f"超时须在 0.1-10 秒之间：{args.timeout}")
        if not (1 <= args.threads <= MAX_THREADS):
            raise ScanTargetError(f"线程数须在 1-{MAX_THREADS} 之间：{args.threads}")
        ports = parse_ports(args.ports)
    except ScanTargetError as e:
        ap.error(str(e))

    try:
        report = scan_host(args.host, ports, args.timeout, args.threads)
    except ScanTargetError as e:
        print(f"[x] {e}", file=sys.stderr)
        return 3

    print_report(report)

    if args.output:
        lower = args.output.lower()
        try:
            if lower.endswith(".csv"):
                export_csv(report, args.output)
            elif lower.endswith(".json"):
                export_json(report, args.output)
            else:
                print("[!] 输出文件需 .csv 或 .json 后缀，已跳过导出", file=sys.stderr)
        except OSError as e:
            print(f"[x] 写出失败：{e}", file=sys.stderr)
            return 4
    return 0


if __name__ == "__main__":
    sys.exit(main())
