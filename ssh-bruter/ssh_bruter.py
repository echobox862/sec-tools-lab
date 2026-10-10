#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ssh-bruter · SSH 弱口令检测工具（学习用 MVP）

依赖：paramiko（第三方，唯一依赖；缺失时给出安装指引退出）。
要点：每次尝试独立新建连接（应对 sshd MaxAuthTries）；开扫前预检认证方式，
密码认证被禁用即终止（密钥质询-应答没有可枚举的秘密，爆破不成立）。

仅用于授权测试环境与学习。AutoAddPolicy 会跳过主机指纹校验（中间人风险），
学习环境可接受，生产环境不应使用。
"""
import argparse
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # 仓库根，供 import shared

try:
    import paramiko
except ImportError:
    print("[x] 缺少依赖 paramiko。安装：pip install paramiko", file=sys.stderr)
    sys.exit(5)

from shared.masking import mask_password  # noqa: E402
from shared.report_io import export_report  # noqa: E402
# WordlistError 为 re-export：shared.wordlist 抛的就是这个类，本模块导入路径保持稳定
from shared.wordlist import WordlistError, load_wordlist as _load_wordlist  # noqa: E402,F401

BANNER = ("[i] 仅用于授权测试环境与学习。注意：AutoAddPolicy 跳过主机指纹校验，"
          "存在中间人风险。")
MAX_ATTEMPTS_DEFAULT = 1000
MAX_THREADS = 20
CONN_ERROR_STOP = 10  # 连续连接错误达到该值即终止（疑似被封禁/目标下线）


def load_wordlist(path):
    """流式约定见 shared.wordlist.load_wordlist；本模块保留原函数名作为入口。"""
    return _load_wordlist(path)


def detect_auth_methods(host, port, timeout, username=""):
    """预检服务器允许的认证方式。返回 list[str]，连接失败抛 OSError。

    username 用于 auth_none 探测：部分 sshd 对空用户名直接断开，
    用实际待检测的用户名探测，结论才对本次任务有效。
    """
    transport = paramiko.Transport((host, port))
    transport.banner_timeout = timeout
    try:
        transport.start_client(timeout=timeout)
        try:
            transport.auth_none(username)
            # 极少见：未认证即通过
            return ["none"]
        except paramiko.BadAuthenticationType as e:
            return list(e.allowed_types)
    finally:
        transport.close()


def attempt(host, port, username, password, timeout):
    """单次尝试，每次新建连接。返回 (success, reason)。
    reason: ok / auth_fail / auth_disabled / max_reached / timeout / conn_error

    捕获顺序说明：TimeoutError（socket.timeout 的 3.10+ 别名）是 OSError 子类，
    必须先于 OSError 判断，否则超时会被误归为 conn_error。
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, port=port, username=username, password=password,
                       timeout=timeout, banner_timeout=timeout,
                       auth_timeout=timeout, allow_agent=False,
                       look_for_keys=False)
        return True, "ok"
    except paramiko.AuthenticationException:
        return False, "auth_fail"
    except paramiko.BadAuthenticationType:
        return False, "auth_disabled"
    except TimeoutError:
        return False, "timeout"
    except paramiko.SSHException as e:
        msg = str(e).lower()
        if "authentication" in msg and "tries" in msg:
            return False, "max_reached"
        return False, "conn_error"
    except (OSError, EOFError):
        return False, "conn_error"
    finally:
        client.close()


def brute(host, port, username, words, timeout, threads, max_attempts, delay):
    """主流程：预检 -> 并发消费字典 -> 命中即停。返回 report dict。

    线程模型：ThreadPoolExecutor 固定 threads 个 worker 消费候选队列——
    线程创建数受 max_workers 硬约束，替代早期「每候选一个线程」的无界创建。
    """
    report = {
        "host": host, "port": port, "username": username,
        "started_at": datetime.now().isoformat(timespec="seconds"),
        "attempts_planned": min(len(words), max_attempts),
        "tried": 0, "found": None, "stop_reason": "exhausted", "timeline": [],
    }
    results_lock = threading.Lock()
    stop = threading.Event()
    counter = {"conn_err_streak": 0}
    timeline = report["timeline"]

    def worker(pwd):
        # 总尝试上限由提交循环（len(futures) <= max_attempts）保证；
        # 此处只响应停止信号（命中/禁用认证/封禁判定/用户中断）
        if stop.is_set():
            return
        ok, reason = attempt(host, port, username, pwd, timeout)
        with results_lock:
            timeline.append({"n": len(timeline) + 1,
                             "password_masked": mask_password(pwd),
                             "success": ok, "reason": reason,
                             "ts": datetime.now().isoformat(timespec="seconds")})
            report["tried"] = len(timeline)  # 实际完成数，而非某个线程的序号
            # paramiko 5.x 对「连接拒绝」与「超时」都抛 TimeoutError，异常类型无法区分二者；
            # 二者同样指示目标不可达，故都计入封禁判定 streak
            if reason in ("conn_error", "timeout"):
                counter["conn_err_streak"] += 1
            else:
                counter["conn_err_streak"] = 0
            streak = counter["conn_err_streak"]
        if ok:
            with results_lock:
                report["found"] = pwd
                report["stop_reason"] = "found"
            stop.set()
            return
        if reason == "auth_disabled":
            with results_lock:
                report["stop_reason"] = "auth_disabled"
            stop.set()
            print("\n[x] 服务器禁用密码认证，爆破不成立，终止", file=sys.stderr)
            return
        if streak >= CONN_ERROR_STOP:
            with results_lock:
                report["stop_reason"] = "conn_errors"
            stop.set()
            print(f"\n[x] 连续 {streak} 次连接错误，疑似被封禁或目标下线，终止",
                  file=sys.stderr)
            return
        if delay:
            time.sleep(delay)

    print(f"[*] 开始：{username}@{host}:{port}，候选 {report['attempts_planned']}，"
          f"线程 {threads}，上限 {max_attempts}")
    executor = ThreadPoolExecutor(max_workers=max(1, min(threads, MAX_THREADS)))
    try:
        futures = []
        for pwd in words:
            if stop.is_set() or len(futures) >= max_attempts:
                break
            futures.append(executor.submit(worker, pwd))
        for future in as_completed(futures):
            future.result()  # worker 内部已捕获全部预期异常，此处仅为传播编程错误
    except KeyboardInterrupt:
        stop.set()
        report["stop_reason"] = "user_abort"
        print("\n[!] 用户中断", file=sys.stderr)
    finally:
        executor.shutdown(wait=not stop.is_set(), cancel_futures=stop.is_set())

    if report["found"]:
        print(f"\n[+] 命中：{username} / {mask_password(report['found'])}")
    else:
        print(f"\n[-] 未命中（stop_reason={report['stop_reason']}，"
              f"尝试 {report['tried']} 次）")
    return report


def mask(pwd):
    """报告展示用脱敏（实现见 shared.masking.mask_password，保留本模块入口）。"""
    return mask_password(pwd)


def export(report, path):
    export_report(
        report, path,
        csv_header=["n", "password_masked", "success", "reason", "ts"],
        csv_rows=([row["n"], row["password_masked"], row["success"],
                   row["reason"], row["ts"]] for row in report["timeline"]),
        message=f"[+] 报告已写入 {path}")


def build_parser():
    ap = argparse.ArgumentParser(
        prog="ssh_bruter.py",
        description="SSH 弱口令检测（学习用，仅限授权目标）",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-H", "--host", required=True, help="目标主机")
    ap.add_argument("-P", "--port", type=int, default=22, help="端口（默认 22）")
    ap.add_argument("-u", "--username", required=True, help="目标用户名")
    ap.add_argument("-p", "--wordlist", required=True, help="密码字典文件（UTF-8，一行一条；建议百万行以内，全量载入内存）")
    ap.add_argument("--timeout", type=float, default=5.0, help="连接超时秒（默认 5）")
    ap.add_argument("--threads", type=int, default=4,
                    help=f"并发数（默认 4，上限 {MAX_THREADS}；过高易触发防护）")
    ap.add_argument("--max-attempts", type=int, default=MAX_ATTEMPTS_DEFAULT,
                    help=f"总尝试上限（默认 {MAX_ATTEMPTS_DEFAULT}）")
    ap.add_argument("--delay", type=float, default=0.2, help="每轮间隔秒（默认 0.2）")
    ap.add_argument("-o", "--output", help="报告导出 .csv/.json")
    ap.add_argument("--skip-detect", action="store_true",
                    help="跳过认证方式预检（不推荐）")
    return ap


def main(argv=None):
    print(BANNER)
    ap = build_parser()
    args = ap.parse_args(argv)

    try:
        if not (1 <= args.port <= 65535):
            raise ValueError(f"端口超出 1-65535：{args.port}")
        if not (0.1 <= args.timeout <= 60):
            raise ValueError(f"超时须在 0.1-60 秒：{args.timeout}")
        if not (1 <= args.threads <= MAX_THREADS):
            raise ValueError(f"线程数须在 1-{MAX_THREADS}：{args.threads}")
        if args.max_attempts <= 0:
            raise ValueError(f"max-attempts 须为正整数：{args.max_attempts}")
        if args.delay < 0:
            raise ValueError(f"delay 不能为负：{args.delay}")
        words = load_wordlist(args.wordlist)
    except WordlistError as e:
        ap.error(str(e))
    except ValueError as e:
        ap.error(str(e))

    if not args.skip_detect:
        try:
            methods = detect_auth_methods(args.host, args.port, args.timeout,
                                          username=args.username)
        except (OSError, paramiko.SSHException) as e:
            print(f"[x] 预检连接失败：{e}", file=sys.stderr)
            return 3
        print(f"[*] 服务器允许的认证方式：{methods}")
        if "password" not in methods:
            print("[x] 目标未启用密码认证（密钥质询-应答不可枚举），爆破不成立",
                  file=sys.stderr)
            return 3

    report = brute(args.host, args.port, args.username, words,
                   args.timeout, args.threads, args.max_attempts, args.delay)
    if args.output:
        try:
            export(report, args.output)
        except (OSError, ValueError) as e:
            print(f"[x] 导出失败：{e}", file=sys.stderr)
            return 4
    return 0


if __name__ == "__main__":
    sys.exit(main())
