# -*- coding: utf-8 -*-
"""shared/ 公共模块的单元测试：mask_password 边界、export_report 格式分支与错误。"""
import _bootstrap  # noqa: F401
import json
import os
import tempfile
import unittest
from pathlib import Path

from shared.masking import mask_password  # noqa: E402
from shared.report_io import export_report  # noqa: E402
from shared.wordlist import load_wordlist  # noqa: E402


class TestMaskPassword(unittest.TestCase):
    """mask_password：脱敏边界。"""

    def test_long_password(self):
        """目的：常规密码保留前 2 位，其余打码并标注长度。"""
        self.assertEqual(mask_password("password123"), "pa*********(len=11)")

    def test_two_chars_no_stars(self):
        """目的：2 位密码无星号，仅长度标注。"""
        self.assertEqual(mask_password("ab"), "ab(len=2)")

    def test_empty(self):
        """目的：空密码显示 (empty)。"""
        self.assertEqual(mask_password(""), "(empty)")

    def test_unicode_password(self):
        """目的：非 ASCII 密码按字符（非字节）截取与计数——保留前 2 位字符。"""
        self.assertEqual(mask_password("密码测试"), "密码**(len=4)")


class TestExportReport(unittest.TestCase):
    """export_report：格式分支、后缀校验、消息透传。"""

    def setUp(self):
        self.report = {"k": "v", "timeline": [{"n": 1}]}

    def test_json_branch(self):
        """目的：.json 后缀走 JSON 序列化，内容与报告一致。"""
        with tempfile.TemporaryDirectory() as d:
            path = str(Path(d) / "r.json")
            export_report(self.report, path, csv_header=None, csv_rows=None,
                          message="[+] ok")
            with open(path, encoding="utf-8") as f:
                self.assertEqual(json.load(f), self.report)

    def test_csv_branch(self):
        """目的：.csv 后缀写表头与数据行，utf-8-sig 编码。"""
        with tempfile.TemporaryDirectory() as d:
            path = str(Path(d) / "r.csv")
            export_report(self.report, path, csv_header=["n"],
                          csv_rows=([1],), message="[+] ok")
            with open(path, encoding="utf-8-sig") as f:
                content = f.read()
        self.assertIn("n", content.splitlines()[0])
        self.assertIn("1", content.splitlines()[1])

    def test_invalid_suffix_rejected(self):
        """目的：非 .json/.csv 后缀抛 ValueError（由调用方 main 转错误退出）。"""
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                export_report(self.report, str(Path(d) / "r.txt"),
                              csv_header=[], csv_rows=[], message="x")

    def test_unwritable_path_raises_oserror(self):
        """目的：目录不存在的路径抛 OSError（不吞异常）。"""
        bad = str(Path(tempfile.gettempdir()) / "no_such_dir_xyz" / "r.json")
        with self.assertRaises(OSError):
            export_report(self.report, bad, csv_header=None, csv_rows=None,
                          message="x")


class TestSharedLoadWordlist(unittest.TestCase):
    """shared.wordlist.load_wordlist：与各工具入口行为一致。"""

    def test_reads_lines(self):
        """目的：多行字典按序读入。"""
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False,
                                         encoding="utf-8") as f:
            f.write("a\nb\n")
            path = f.name
        try:
            self.assertEqual(load_wordlist(path), ["a", "b"])
        finally:
            os.unlink(path)

    def test_missing_file_raises_wordlist_error(self):
        """目的：文件不存在抛 WordlistError（ValueError 子类，各工具 main 可统一捕获）。"""
        with self.assertRaises(ValueError):
            load_wordlist(str(Path(tempfile.gettempdir()) / "no_such_wl_xyz.txt"))


if __name__ == "__main__":
    unittest.main()
