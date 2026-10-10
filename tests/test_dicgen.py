# -*- coding: utf-8 -*-
"""dict-generator/dicgen.py 的单元测试。

覆盖：parse_year_range、validate_templates、estimate_count、generate（正常/截断/
长词跳过/空产出）、write_stream（去重/追加/覆盖）。
"""
import _bootstrap  # noqa: F401
import os
import tempfile
import unittest
from pathlib import Path

from dicgen import (  # noqa: E402
    RuleError,
    estimate_count,
    generate,
    parse_year_range,
    validate_templates,
    write_stream,
)
import dicgen  # noqa: E402, F401  确保 bootstrap 生效后重复导入安全


class TestParseYearRange(unittest.TestCase):
    """parse_year_range：年份段与列表解析。"""

    def test_single_year(self):
        """目的：单个年份解析为单元素列表。"""
        self.assertEqual(parse_year_range("2024"), ["2024"])

    def test_range(self):
        """目的：范围展开为闭区间字符串序列。"""
        self.assertEqual(parse_year_range("2024-2026"), ["2024", "2025", "2026"])

    def test_comma_list(self):
        """目的：逗号列表原样保留。"""
        self.assertEqual(parse_year_range("2024,2026"), ["2024", "2026"])

    def test_empty_returns_empty(self):
        """目的：空输入返回空列表（允许不指定年份）。"""
        self.assertEqual(parse_year_range(""), [])

    def test_reversed_range_rejected(self):
        """目的：起止倒置拒绝。"""
        with self.assertRaises(RuleError):
            parse_year_range("2026-2024")

    def test_non_numeric_rejected(self):
        """目的：非数字年份拒绝。"""
        with self.assertRaises(RuleError):
            parse_year_range("abcd")

    def test_range_too_wide_rejected(self):
        """目的：跨度超过 100 年拒绝（防误用）。"""
        with self.assertRaises(RuleError):
            parse_year_range("1900-2100")

    def test_empty_segment_rejected(self):
        """目的：连续逗号空段拒绝。"""
        with self.assertRaises(RuleError):
            parse_year_range("2024,,2026")


class TestValidateTemplates(unittest.TestCase):
    """validate_templates：模板占位符白名单校验。"""

    def test_known_fields_pass(self):
        """目的：四个合法字段全部通过。"""
        validate_templates(["{base}{year}", "{base}{sep}{tail}"])

    def test_unknown_field_rejected(self):
        """目的：拼错字段（{passwrod}）报 RuleError 并指出可用字段。"""
        with self.assertRaises(RuleError) as ctx:
            validate_templates(["{passwrod}"])
        self.assertIn("passwrod", str(ctx.exception))

    def test_empty_segment_in_seps_rejected_by_cli(self):
        """目的：--seps 含空段时 CLI 报错退出（审计 Min-4），不再静默当作直连。"""
        import subprocess
        import sys
        script = Path(_bootstrap.ROOT) / "dict-generator" / "dicgen.py"
        r = subprocess.run(
            [sys.executable, str(script), "--base", "admin",
             "--seps", "a,,b", "--templates", "{base}{sep}",
             "-o", str(Path(tempfile.gettempdir()) / "segs_test.txt")],
            capture_output=True, text=True, timeout=30)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("空段", r.stderr)

    def test_no_placeholder_is_valid(self):
        """目的：无占位符的固定串也是合法模板。"""
        validate_templates(["固定密码123"])

    def test_empty_braces_rejected(self):
        """目的：空占位 {} 曾绕过旧正则校验并在 format 期抛 IndexError——
        必须在校验阶段拒绝（审计 M1 回归）。"""
        with self.assertRaises(RuleError):
            validate_templates(["x{}"])

    def test_lone_brace_rejected(self):
        """目的：孤立花括号 'a{b' 曾绕过旧正则校验并在 format 期抛 ValueError——
        必须在校验阶段拒绝（审计 M1 回归）。"""
        with self.assertRaises(RuleError):
            validate_templates(["a{b"])

    def test_positional_index_rejected(self):
        """目的：位置参数 {0} 拒绝（旧正则会放行，format 期崩溃）。"""
        with self.assertRaises(RuleError):
            validate_templates(["{base}{0}"])

    def test_conversion_and_format_spec_rejected(self):
        """目的：{base!r} 与 {base:>10} 会悄悄改变产出语义，拒绝。"""
        with self.assertRaises(RuleError):
            validate_templates(["{base!r}"])
        with self.assertRaises(RuleError):
            validate_templates(["{base:>10}"])

    def test_escaped_literal_braces_still_allowed(self):
        """目的：{{ }} 转义的字面花括号是合法模板（可生成含 { 的口令），不误伤。"""
        validate_templates(["a{{b}}"])


class TestEstimateCount(unittest.TestCase):
    """estimate_count：笛卡尔积总量预估。"""

    def test_full_product(self):
        """目的：2 词 × 2 符 × 3 年 × 2 尾 × 2 模板 = 48。"""
        n = estimate_count(["a", "b"], ["", "!"], ["2024", "2025", "2026"],
                           ["1", "2"], ["{base}{year}", "{base}{sep}{tail}"])
        self.assertEqual(n, 48)

    def test_empty_base_is_conservative(self):
        """目的：基础词为空时预估按保守高估处理（返回 1 而非 0）——
        防爆闸门宁可高估也不低估，实际产出会被 generate 的空词跳过逻辑拦下。"""
        self.assertEqual(estimate_count([], [""], [], [], ["{base}"]), 1)


class TestGenerate(unittest.TestCase):
    """generate：惰性产出的正常、截断、边界行为。"""

    def test_basic_combinations(self):
        """目的：模板按字段展开全部组合。已知特性：未使用的字段仍参与笛卡尔积
        （如 {base}{tail} 在 2 个 year 值下产出 2 条相同记录），跨模板重复由
        write_stream 的 dedupe 兜底，generate 层保持原始产出不去重。"""
        got = list(generate(["admin"], [""], ["2024", "2025"], ["123"],
                            ["{base}{year}", "{base}{tail}", "{base}{sep}{tail}"],
                            limit=100))
        self.assertEqual(got, ["admin2024", "admin2025"] + ["admin123"] * 4)

    def test_limit_truncates(self):
        """目的：产出超过 limit 时精确截断（防爆闸门）。"""
        got = list(generate(["a", "b", "c"], [""], ["1", "2", "3"], [""],
                            ["{base}{year}"], limit=5))
        self.assertEqual(len(got), 5)

    def test_overlong_word_skipped(self):
        """目的：超过 MAX_LINE 长度的单条产出被跳过。"""
        long_base = "x" * (dicgen.MAX_LINE + 1)
        got = list(generate([long_base], [""], [""], [""],
                            ["{base}"], limit=10))
        self.assertEqual(got, [])

    def test_empty_inputs_yield_nothing(self):
        """目的：任一字段池为空时无产出且不报错。"""
        got = list(generate([], [""], [""], [""], ["{base}"], limit=10))
        self.assertEqual(got, [])

    def test_is_generator_lazy(self):
        """目的：generate 返回生成器对象（惰性求值，不立即物化内存）。"""
        g = generate(["a"], [""], [""], [""], ["{base}"], limit=10)
        self.assertTrue(hasattr(g, "__next__"))


class TestWriteStream(unittest.TestCase):
    """write_stream：流式写入、去重、追加/覆盖模式。"""

    def test_write_and_dedupe(self):
        """目的：重复词按指纹去重，返回 (written, dup) 统计。"""
        with tempfile.TemporaryDirectory() as d:
            path = str(Path(d) / "d.txt")
            written, dup = write_stream(iter(["a", "a", "b"]), path)
            self.assertEqual((written, dup), (2, 1))
            with open(path, encoding="utf-8") as f:
                self.assertEqual(f.read().splitlines(), ["a", "b"])

    def test_no_dedupe_keeps_all(self):
        """目的：关闭去重时重复条目全部保留。"""
        with tempfile.TemporaryDirectory() as d:
            path = str(Path(d) / "d.txt")
            written, dup = write_stream(iter(["a", "a"]), path, dedupe=False)
            self.assertEqual((written, dup), (2, 0))

    def test_append_mode(self):
        """目的：append=True 在既有文件后追加而非覆盖。"""
        with tempfile.TemporaryDirectory() as d:
            path = str(Path(d) / "d.txt")
            write_stream(iter(["a"]), path)
            write_stream(iter(["b"]), path, append=True)
            with open(path, encoding="utf-8") as f:
                self.assertEqual(f.read().splitlines(), ["a", "b"])

    def test_overwrite_mode(self):
        """目的：默认模式覆盖旧文件。"""
        with tempfile.TemporaryDirectory() as d:
            path = str(Path(d) / "d.txt")
            write_stream(iter(["a", "b", "c"]), path)
            write_stream(iter(["z"]), path)
            with open(path, encoding="utf-8") as f:
                self.assertEqual(f.read().splitlines(), ["z"])

    def test_unwritable_path_raises_oserror(self):
        """目的：非法路径（目录不存在）抛 OSError 由 main 层转错误退出。"""
        bad = str(Path(tempfile.gettempdir()) / "no_such_dir_xyz" / "d.txt")
        with self.assertRaises(OSError):
            write_stream(iter(["a"]), bad)


if __name__ == "__main__":
    unittest.main()
