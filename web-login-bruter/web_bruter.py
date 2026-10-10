#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
web-login-bruter · Web 登录表单弱口令检测（学习用 MVP，纯标准库）

要点（对应实训材料）：
- 自适应表单解析：html.parser 全量收集 <input>，按 type 定位用户名/密码框，
  其余字段（含 csrf token）原样携带——不写死字段名。
- token 两步走：每轮先 GET 提取最新 token 再 POST（应对一次性/有时效 token）。
- 判定信号开扫前校准：一真一假两个密码验证 fail/success marker 可区分，
  连续 unknown 自动终止（宁可停也不瞎跑）。

仅用于授权测试环境与学习（示例目标：本地 DVWA / sqli-labs）。
"""
import argparse
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # 仓库根，供 import shared

from shared.masking import mask_password  # noqa: E402
from shared.report_io import export_report  # noqa: E402
from shared.wordlist import load_wordlist as _load_wordlist  # noqa: E402

BANNER = "[i] 仅用于授权测试环境与学习（本地 DVWA / 实验环境）。"
MAX_THREADS = 20
UNKNOWN_STOP = 3       # 连续 unknown 次数上限
CONN_ERROR_STOP = 10
MAX_BACKOFF_DELAY = 10.0


class FormParser(HTMLParser):
    """收集页面全部 <input> 的 name/type/value（自适应表单解析的核心）。"""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.inputs = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "input":
            d = {k.lower(): (v or "") for k, v in attrs}
            self.inputs.append({"name": d.get("name", ""),
                                "type": d.get("type", "text").lower(),
                                "value": d.get("value", "")})


class FormError(ValueError):
    pass


def http_fetch(url, data=None, headers=None, timeout=10.0, insecure=False,
               method=None, opener=None):
    """统一请求入口。返回 (status_code, headers, body_bytes)。

    headers 保留为 email.message.Message 对象——其 get() 对头名大小写不敏感
    （HTTP 头名本就不区分大小写；转成普通 dict 会丢失这一性质，
    导致小写 location 响应的重定向判定失效）。
    """
    op = opener if opener is not None else build_opener(insecure)
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        resp = op.open(req, timeout=timeout)
        body = resp.read()
        return resp.status, resp.headers, body
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read()
    # URLError 由上层捕获分类


def make_opener(insecure):
    """带 Cookie 的 opener；NoRedirect 不跟随 30x；insecure 时跳过证书校验。"""

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    handlers = [urllib.request.HTTPCookieProcessor(),
                NoRedirect()]
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    return urllib.request.build_opener(*handlers)


def fetch_form(opener, url, timeout, insecure):
    """GET 登录页并解析全部 input。返回 (fields, raw_len)。
    fields: [{name,type,value}]；找不到任何 input 抛 FormError。"""
    try:
        status, headers, body = http_fetch(url, timeout=timeout,
                                           insecure=insecure, opener=opener)
    except urllib.error.URLError as e:
        raise FormError(f"无法访问登录页：{e.reason}")
    html = body.decode("utf-8", errors="replace")
    parser = FormParser()
    parser.feed(html)
    named = [i for i in parser.inputs if i["name"]]
    if not named:
        raise FormError("页面中未找到任何带 name 的 <input>，请确认这是登录页")
    return named, len(html)


def split_fields(fields, username):
    """把字段分为 user_field / pass_field / others（hidden 等，原样携带）。"""
    user_field = pass_field = None
    others = []
    for f in fields:
        t = f["type"]
        if t == "text" and user_field is None:
            user_field = f["name"]
        elif t == "password" and pass_field is None:
            pass_field = f["name"]
        else:
            others.append(dict(f))
    if not user_field or not pass_field:
        raise FormError(f"表单缺少用户名或密码输入框（text={user_field}, "
                        f"password={pass_field}）")
    return user_field, pass_field, others


def build_payload(others, user_field, pass_field, username, password):
    """复制全部字段（token 等原样透传），仅替换用户名/密码。"""
    data = {f["name"]: f["value"] for f in others}
    data[user_field] = username
    data[pass_field] = password
    return data


def post_attempt(opener, url, payload, timeout, insecure, encoding="utf-8"):
    """POST 表单并返回 (status, location_redirect, html)。"""
    data = urllib.parse.urlencode(payload).encode("utf-8")
    headers = {"Content-Type": "application/x-www-form-urlencoded",
               "User-Agent": "sec-tools-lab/0.1 (learning)"}
    status, headers, body = http_fetch(url, data=data, headers=headers,
                                       timeout=timeout, insecure=insecure,
                                       opener=opener)
    html = body.decode(encoding, errors="replace")
    # Message.get 对头名大小写不敏感（审计 M2：小写 location 响应也要能取到）
    return status, headers.get("Location", ""), html


class AttemptResult:
    __slots__ = ("password", "outcome", "status", "redirect", "error")

    def __init__(self, password, outcome, status, redirect, error=""):
        # redirect 只放重定向地址；连接/解析失败的原因放 error，两个字段不混用
        self.password, self.outcome, self.status, self.redirect = \
            password, outcome, status, redirect
        self.error = error


def attempt(opener, form_url, fields, user_field, pass_field, username,
            password, timeout, insecure, encoding="utf-8", refresh_token=True):
    """单次尝试：refresh_token=True 时先 GET 取新 token 再 POST。
    统一返回 (AttemptResult, html, status, redirect)；连接/解析失败时
    outcome=conn_error、error 带原因，其余值为空。"""
    try:
        if refresh_token:
            fields, _ = fetch_form(opener, form_url, timeout, insecure)
        u_field, p_field, others = split_fields(fields, username)
        payload = build_payload(others, u_field, p_field, username, password)
        status, redirect, html = post_attempt(opener, form_url, payload,
                                              timeout, insecure, encoding)
    except (FormError, urllib.error.URLError, OSError) as e:
        return (AttemptResult(password, "conn_error", 0, "", error=str(e)),
                "", 0, "")
    return (AttemptResult(password, "pending", status, redirect),
            html, status, redirect)


def judge(html, status, redirect, fail_marker, success_marker):
    """按 marker 判定。返回 fail / success / unknown。"""
    if success_marker and success_marker in html:
        return "success"
    if success_marker and (success_marker in redirect):
        return "success"
    if fail_marker and fail_marker in html:
        return "fail"
    if status in (301, 302, 303, 307) and redirect and not success_marker:
        return "success"
    return "unknown"


def brute(opener, form_url, fields, username, words, fail_marker, success_marker,
          timeout, insecure, encoding, refresh_token, threads, delay):
    """主流程。MVP 单线程（threads>1 时用线程池语义但保持每线程独立 opener 的
    复杂度留到 P1；此处串行消费，保证正确性优先）。"""
    user_field, pass_field, _ = split_fields(fields, username)
    report = {"url": form_url, "username": username,
              "started_at": datetime.now().isoformat(timespec="seconds"),
              "tried": 0, "found": None, "stop_reason": "exhausted",
              "timeline": [], "marker_check": {}}

    # 校准闸门：提交一次错误密码，确认请求链路与 marker 可用
    print("[*] 校准判定信号（1 次错误密码）...")
    res, _, _, _ = attempt(opener, form_url, fields, user_field, pass_field,
                           username, "__calibrate_wrong_pwd__", timeout,
                           insecure, encoding, refresh_token)
    if res.outcome == "conn_error":
        report["stop_reason"] = "conn_error"
        print(f"[x] 校准请求失败：{res.error}", file=sys.stderr)
        return report
    report["marker_check"]["calibrate"] = res.status

    unknown_streak = conn_err = 0
    stop = False
    for i, pwd in enumerate(words, 1):
        if stop:
            break
        res, html, status, redirect = attempt(
            opener, form_url, fields, user_field, pass_field,
            username, pwd, timeout, insecure, encoding, refresh_token)
        if res.outcome == "conn_error":
            conn_err += 1
            report["timeline"].append({"n": i, "password_masked": mask(pwd),
                                       "outcome": "conn_error",
                                       "ts": datetime.now().isoformat(timespec="seconds")})
            if conn_err >= CONN_ERROR_STOP:
                report["stop_reason"] = "conn_errors"
                print(f"\n[x] 连续 {conn_err} 次连接错误，终止", file=sys.stderr)
                break
            time.sleep(min(delay * 2 ** min(conn_err, 4), MAX_BACKOFF_DELAY))
            continue
        conn_err = 0
        outcome = judge(html, status, redirect, fail_marker, success_marker)
        report["tried"] = i
        report["timeline"].append({"n": i, "password_masked": mask(pwd),
                                   "outcome": outcome,
                                   "ts": datetime.now().isoformat(timespec="seconds")})
        if outcome == "success":
            report["found"] = pwd
            report["stop_reason"] = "found"
            print(f"\n[+] 命中：{username} / {mask(pwd)}")
            break
        if outcome == "unknown":
            unknown_streak += 1
            if unknown_streak >= UNKNOWN_STOP:
                report["stop_reason"] = "unknown_marker"
                print(f"\n[x] 连续 {unknown_streak} 次无法判定，判定信号可能失效，"
                      f"终止并建议重新校准", file=sys.stderr)
                break
        else:
            unknown_streak = 0
        if delay:
            time.sleep(delay)
        print(f"\r[{i}/{len(words)}] tried={i} "
              f"last={outcome}", end="", flush=True)
    print()
    if not report["found"] and report["stop_reason"] == "exhausted":
        print(f"[-] 未命中（尝试 {report['tried']} 次）")
    return report


def mask(pwd):
    """报告展示用脱敏（实现见 shared.masking.mask_password，保留本模块入口）。"""
    return mask_password(pwd)


def export(report, path):
    export_report(
        report, path,
        csv_header=["n", "password_masked", "outcome", "ts"],
        csv_rows=([r["n"], r["password_masked"], r["outcome"], r["ts"]]
                  for r in report["timeline"]),
        message=f"[+] 报告已写入 {path}")


def build_parser():
    ap = argparse.ArgumentParser(
        prog="web_bruter.py",
        description="Web 登录表单弱口令检测（学习用，仅限本地 DVWA 等授权目标）",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", required=True, help="登录提交地址")
    ap.add_argument("--username", required=True, help="目标用户名")
    ap.add_argument("--wordlist", required=True,
                    help="字典文件（UTF-8，一行一条；建议百万行以内，全量载入内存）")
    ap.add_argument("--fail-marker", default="Login failed",
                    help="失败页特征串（默认 'Login failed'，DVWA 适用）")
    ap.add_argument("--success-marker", default="",
                    help="成功页特征串（可选；与 Location 重定向双信号）")
    ap.add_argument("--timeout", type=float, default=10.0, help="请求超时秒（默认 10）")
    ap.add_argument("--threads", type=int, default=1,
                    help=f"并发数（默认 1；MVP 上限 {MAX_THREADS}，>1 时校验后仍串行提示）")
    ap.add_argument("--delay", type=float, default=0.2, help="每轮间隔秒（默认 0.2）")
    ap.add_argument("--encoding", default="utf-8", help="响应解码（默认 utf-8）")
    ap.add_argument("--no-refresh-token", action="store_true",
                    help="不每轮刷新 token（token 固定的表单用）")
    ap.add_argument("--insecure", action="store_true",
                    help="跳过 HTTPS 证书校验（自签名学习环境）")
    ap.add_argument("-o", "--output", help="报告导出 .csv/.json")
    return ap


def main(argv=None):
    print(BANNER)
    ap = build_parser()
    args = ap.parse_args(argv)
    if args.threads > 1:
        print("[!] MVP 版按串行执行（正确性优先），threads 参数仅作校验", file=sys.stderr)

    try:
        if not (0.1 <= args.timeout <= 120):
            raise ValueError(f"超时须在 0.1-120 秒：{args.timeout}")
        if not (1 <= args.threads <= MAX_THREADS):
            raise ValueError(f"threads 须在 1-{MAX_THREADS}")
        if args.delay < 0:
            raise ValueError(f"delay 不能为负：{args.delay}")
        u = urllib.parse.urlparse(args.url)
        if u.scheme not in ("http", "https") or not u.netloc:
            raise ValueError(f"URL 非法（需 http/https + 主机）：{args.url}")
        words = _load_wordlist(args.wordlist)  # WordlistError ⊂ ValueError，统一处理
    except (ValueError, OSError) as e:
        ap.error(str(e))

    opener = make_opener(args.insecure)
    try:
        fields, raw_len = fetch_form(opener, args.url, args.timeout, args.insecure)
    except FormError as e:
        print(f"[x] {e}", file=sys.stderr)
        return 3
    print(f"[*] 表单解析：{len(fields)} 个 input 字段 -> "
          f"{[f['name'] for f in fields]}")

    try:
        report = brute(opener, args.url, fields, args.username, words,
                       args.fail_marker, args.success_marker, args.timeout,
                       args.insecure, args.encoding,
                       refresh_token=not args.no_refresh_token,
                       threads=args.threads, delay=args.delay)
    except FormError as e:
        print(f"[x] {e}", file=sys.stderr)
        return 3

    if args.output:
        try:
            export(report, args.output)
        except (OSError, ValueError) as e:
            print(f"[x] 导出失败：{e}", file=sys.stderr)
            return 4
    return 0


if __name__ == "__main__":
    sys.exit(main())
