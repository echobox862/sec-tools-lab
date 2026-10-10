#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dict-generator · 弱口令字典生成器（学习用 MVP）

依据「弱密码=人按习惯造的」规律（基础词 + 连接符 + 年份 + 数字尾巴），
模板规则与数据分离；生成器惰性产出，内存恒定；生成前先做总量预估防爆。

仅用于授权测试环境与学习。基础词请使用自己拥有或已授权的信息。
"""
import argparse
import hashlib
import itertools
import sys
from string import Formatter

BANNER = "[i] 仅用于授权测试环境与学习；基础词请使用自己拥有或已授权的信息。"
DEFAULT_LIMIT = 1000000
MAX_LINE = 64
KNOWN_FIELDS = {"base", "sep", "year", "tail"}


class RuleError(ValueError):
    pass


def parse_year_range(spec):
    """'2024-2026' 或 '2024,2025' 或空 -> 年份字符串列表。"""
    if not spec:
        return []
    years = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            raise RuleError(f"年份描述存在空段：{spec!r}")
        if "-" in part:
            lo, _, hi = part.partition("-")
            try:
                lo, hi = int(lo), int(hi)
            except ValueError:
                raise RuleError(f"年份范围格式非法：{part!r}")
            if lo > hi or hi - lo > 100:
                raise RuleError(f"年份范围非法：{part!r}")
            years.extend(str(y) for y in range(lo, hi + 1))
        else:
            if not part.isdigit():
                raise RuleError(f"年份不是数字：{part!r}")
            years.append(part)
    return years


def validate_templates(templates):
    """模板占位符校验：只允许 {base} {sep} {year} {tail} 四个字段。

    用 str.format 同源的 string.Formatter().parse 做校验，保证「校验通过必然可 format」：
    - 空占位 {} / 位置参数 {0} / 转换与格式说明 {base!r} {base:>10} —— 拒绝；
    - 孤立花括号（如 'a{b'）—— parse 阶段即抛 ValueError，转 RuleError；
    - 转义字面花括号 '{{' / '}}' —— 合法，保留（用于生成含 { 的口令）。
    """
    for tpl in templates:
        try:
            parsed = list(Formatter().parse(tpl))
        except ValueError as e:
            raise RuleError(f"模板花括号不配对（{tpl!r}）：{e}")
        for _, field, spec, conv in parsed:
            if field is not None and (field not in KNOWN_FIELDS or spec or conv):
                raise RuleError(f"模板含非法占位符 {{{field}}}（{tpl!r}），"
                                f"可用字段：{sorted(KNOWN_FIELDS)}")


def estimate_count(bases, seps, years, tails, templates):
    """笛卡尔积预估总产出量。"""
    per_tpl = max(len(bases), 1) * max(len(seps), 1) * \
        max(len(years), 1) * max(len(tails), 1)
    return per_tpl * len(templates)


def generate(bases, seps, years, tails, templates, limit):
    """惰性生成器：逐条产出，不物化到内存。超过 limit 截断。"""
    count = 0
    for tpl in templates:
        pool = [bases, seps, years, tails]
        for combo in itertools.product(*pool):
            base, sep, year, tail = combo
            word = tpl.format(base=base, sep=sep, year=year, tail=tail)
            if not word or len(word) > MAX_LINE:
                continue
            yield word
            count += 1
            if count >= limit:
                return


def write_stream(words, out_path, append=False, dedupe=True):
    """流式写入 + 可选去重（只存摘要指纹控制内存）。返回 (written, dup_skipped)。"""
    seen = set() if dedupe else None
    mode = "a" if append else "w"
    written = dup = 0
    with open(out_path, mode, encoding="utf-8", newline="\n") as f:
        for word in words:
            if seen is not None:
                fp = hashlib.md5(word.encode("utf-8")).digest()[:8]
                if fp in seen:
                    dup += 1
                    continue
                seen.add(fp)
            f.write(word + "\n")
            written += 1
    return written, dup


def build_parser():
    ap = argparse.ArgumentParser(
        prog="dicgen.py",
        description="弱口令字典生成器（学习用；基础词须为自有/授权信息）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="模板示例：'{base}{year},{base}{sep}{tail}' —— 逗号分隔多条，"
               "可用字段：base/sep/year/tail")
    ap.add_argument("--base", required=True,
                    help="基础词，逗号分隔（姓名拼音/公司名等自有信息）")
    ap.add_argument("--years", default="",
                    help="年份：2024-2026 或 2024,2025（默认空）")
    ap.add_argument("--seps", default="",
                    help="连接符，逗号分隔（默认空，即直连）")
    ap.add_argument("--tails", default="",
                    help="数字尾巴，逗号分隔（如 123,1234）")
    ap.add_argument("--templates", required=True,
                    help="组合模板，逗号分隔，如 '{base}{year},{base}{sep}{tail}'")
    ap.add_argument("--limit", type=int, default=DEFAULT_LIMIT,
                    help=f"单次最大产出条数（默认 {DEFAULT_LIMIT}）")
    ap.add_argument("-o", "--output", required=True, help="输出文件路径")
    ap.add_argument("--append", action="store_true", help="追加而非覆盖")
    ap.add_argument("--no-dedupe", action="store_true", help="关闭去重")
    ap.add_argument("--force", action="store_true",
                    help="预估超限仍强制生成")
    return ap


def main(argv=None):
    print(BANNER)
    ap = build_parser()
    args = ap.parse_args(argv)

    try:
        if args.limit <= 0:
            raise RuleError(f"limit 必须为正整数：{args.limit}")
        bases = [x.strip() for x in args.base.split(",") if x.strip()]
        if not bases:
            raise RuleError("至少提供一个非空基础词")
        for b in bases:
            if len(b) > MAX_LINE:
                raise RuleError(f"基础词过长（>{MAX_LINE}）：{b[:20]!r}...")
        seps = args.seps.split(",") if args.seps else [""]
        if "" in seps and len(seps) > 1:
            raise RuleError(f"seps 存在空段（{args.seps!r}）；需要「直连」组合时"
                            f"不传 --seps 即可（默认就是直连）")
        years = parse_year_range(args.years)
        tails = [x.strip() for x in args.tails.split(",") if x.strip()] if args.tails else [""]
        templates = [x.strip() for x in args.templates.split(",") if x.strip()]
        if not templates:
            raise RuleError("至少提供一个模板")
        validate_templates(templates)
    except RuleError as e:
        ap.error(str(e))

    est = estimate_count(bases, seps, years, tails, templates)
    print(f"[*] 预估总产出 {est} 条，limit {args.limit}")
    if est > args.limit and not args.force:
        print(f"[x] 预估超过 limit。如确认请加 --force（生成仍会在 {args.limit} 条截断）",
              file=sys.stderr)
        return 2

    gen = generate(bases, seps, years, tails, templates, args.limit)
    try:
        written, dup = write_stream(gen, args.output,
                                    append=args.append, dedupe=not args.no_dedupe)
    except OSError as e:
        print(f"[x] 写出失败：{e}", file=sys.stderr)
        return 4
    print(f"[+] 完成：写入 {written} 条 -> {args.output}"
          + (f"（去重跳过 {dup} 条）" if dup else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
