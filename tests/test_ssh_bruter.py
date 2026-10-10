# -*- coding: utf-8 -*-
"""ssh-bruter/ssh_bruter.py 的单元测试。

无 paramiko 环境时自动跳过网络相关用例（unittest.skipUnless）。
覆盖：mask 脱敏、load_wordlist（正常/缺失/空文件/编码）、attempt 对关闭端口、
brute 主流程（conn_error 连发终止 / 正常耗尽）、CLI 参数校验冒烟。
"""
import _bootstrap  # noqa: F401
import os
import tempfile
import unittest
from pathlib import Path

try:
    import paramiko  # noqa: F401
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False

import ssh_bruter as sb  # noqa: E402
from ssh_bruter import (  # noqa: E402
    WordlistError,
    load_wordlist,
    mask,
)


class TestMask(unittest.TestCase):
    """mask：报告脱敏。"""

    def test_normal(self):
        """目的：保留前 2 位打码并标注长度。"""
        self.assertEqual(mask("password123"), "pa*********(len=11)")

    def test_short_two_chars(self):
        """目的：2 位密码无星号仅标长度。"""
        self.assertEqual(mask("ab"), "ab(len=2)")

    def test_one_char(self):
        """目的：1 位密码打码为 0 个星号 + 长度。"""
        self.assertEqual(mask("x"), "x(len=1)")

    def test_empty(self):
        """目的：空密码显示 (empty)。"""
        self.assertEqual(mask(""), "(empty)")


class TestLoadWordlist(unittest.TestCase):
    """load_wordlist：字典文件加载。"""

    def test_normal_load(self):
        """目的：多行文件全部读入，保留顺序。"""
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False,
                                         encoding="utf-8") as f:
            f.write("aaa\nbbb\nccc\n")
            path = f.name
        try:
            self.assertEqual(load_wordlist(path), ["aaa", "bbb", "ccc"])
        finally:
            os.unlink(path)

    def test_blank_lines_skipped(self):
        """目的：空行与纯空白行跳过（不作为候选密码）。"""
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False,
                                         encoding="utf-8") as f:
            f.write("aaa\n\n   \nbbb\n")
            path = f.name
        try:
            self.assertEqual(load_wordlist(path), ["aaa", "bbb"])
        finally:
            os.unlink(path)

    def test_missing_file(self):
        """目的：文件不存在抛 WordlistError。"""
        with self.assertRaises(WordlistError):
            load_wordlist(str(Path(tempfile.gettempdir()) / "no_such_wl_xyz.txt"))

    def test_empty_file(self):
        """目的：空文件抛 WordlistError（无候选可试）。"""
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False,
                                         encoding="utf-8") as f:
            f.write("\n\n")
            path = f.name
        try:
            with self.assertRaises(WordlistError):
                load_wordlist(path)
        finally:
            os.unlink(path)

    def test_trailing_whitespace_stripped(self):
        """目的：记录实际行为——仅剥离行尾换行，行内空白保留为密码的一部分
        （密码含首尾空格在现实中合法，不做隐式清洗）。"""
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False,
                                         encoding="utf-8") as f:
            f.write("  abc  \n")
            path = f.name
        try:
            self.assertEqual(load_wordlist(path), ["  abc  "])
        finally:
            os.unlink(path)


@unittest.skipUnless(HAS_PARAMIKO, "paramiko 未安装，跳过网络相关用例")
class TestAttemptAgainstClosedPort(unittest.TestCase):
    """attempt：对确定关闭的端口（本机未监听）验证错误分类。"""

    def test_closed_port_not_auth_fail(self):
        """目的：连接被拒绝不能归类为 auth_fail——区分「连不上」与「密码错」是判定正确性的基础。
        paramiko 5.x 对连接拒绝与超时统一抛 TimeoutError，故 reason 为 timeout（审计 M3 修复后的正确分类）。"""
        ok, reason = sb.attempt("127.0.0.1", 9, "root", "x", timeout=2)
        self.assertFalse(ok)
        self.assertEqual(reason, "timeout")

    def test_returns_boolean_reason_pair(self):
        """目的：返回结构为 (bool, str)。"""
        ok, reason = sb.attempt("127.0.0.1", 9, "root", "x", timeout=2)
        self.assertIsInstance(ok, bool)
        self.assertIsInstance(reason, str)


@unittest.skipUnless(HAS_PARAMIKO, "paramiko 未安装，跳过网络相关用例")
class TestDetectAuthMethodsClosedPort(unittest.TestCase):
    """detect_auth_methods：对关闭端口应抛连接类异常（OSError/SSHException）。"""

    def test_raises_on_closed_port(self):
        """目的：无法建立传输时抛异常（main 层捕获后以预检失败退出）。"""
        with self.assertRaises((OSError, paramiko.SSHException)):
            sb.detect_auth_methods("127.0.0.1", 9, timeout=2)


@unittest.skipUnless(HAS_PARAMIKO, "paramiko 未安装，跳过网络相关用例")
class TestBruteFlow(unittest.TestCase):
    """brute 主流程：无需真实 SSH 服务即可验证的流控行为。"""

    def test_all_conn_errors_triggers_stop(self):
        """目的：连续 CONN_ERROR_STOP 次连接失败（paramiko 5.x 下为 timeout 分类，
        同样计入封禁 streak）时以 conn_errors 终止——对应「疑似被封禁或目标下线」的保护逻辑。"""
        words = [f"pwd{i}" for i in range(12)]  # > CONN_ERROR_STOP(10)
        report = sb.brute("127.0.0.1", 9, "root", words,
                          timeout=2, threads=1, max_attempts=100, delay=0)
        self.assertEqual(report["stop_reason"], "conn_errors")
        self.assertLess(report["tried"], 12)
        self.assertIsNone(report["found"])

    def test_exhausted_when_few_words(self):
        """目的：词数少于终止阈值时全部尝试完，stop_reason=exhausted。"""
        words = ["a", "b", "c"]
        report = sb.brute("127.0.0.1", 9, "root", words,
                          timeout=2, threads=1, max_attempts=100, delay=0)
        self.assertEqual(report["stop_reason"], "exhausted")
        self.assertEqual(report["tried"], 3)
        self.assertEqual(len(report["timeline"]), 3)
        self.assertTrue(all(t["reason"] in ("conn_error", "timeout")
                            for t in report["timeline"]))

    def test_threads5_concurrent_bookkeeping(self):
        """目的：并发正确性（审计 Med-3）——threads=5 下 tried 与 timeline 一致、
        序号无重复、封禁 streak 在并发下仍然触发提前终止。"""
        words = [f"pwd{i}" for i in range(30)]
        report = sb.brute("127.0.0.1", 9, "root", words,
                          timeout=2, threads=5, max_attempts=100, delay=0)
        self.assertEqual(report["tried"], len(report["timeline"]))
        ns = [t["n"] for t in report["timeline"]]
        self.assertEqual(len(ns), len(set(ns)), "timeline 序号出现重复")
        self.assertEqual(ns, list(range(1, len(ns) + 1)), "序号不连续")
        self.assertLess(report["tried"], 30, "封禁 streak 未在并发下生效")
        self.assertEqual(report["stop_reason"], "conn_errors")

    def test_max_attempts_respected(self):
        """目的：max_attempts 截断长字典——上限闸门（实训 1000 次设计）生效。"""
        words = [f"pwd{i}" for i in range(50)]
        report = sb.brute("127.0.0.1", 9, "root", words,
                          timeout=2, threads=1, max_attempts=5, delay=0)
        self.assertLessEqual(report["tried"], 5)

    def test_timeline_masked(self):
        """目的：报告时间线中的密码是脱敏形式，不出现明文。"""
        words = ["secret123"]
        report = sb.brute("127.0.0.1", 9, "root", words,
                          timeout=2, threads=1, max_attempts=10, delay=0)
        for t in report["timeline"]:
            self.assertNotIn("secret123", t["password_masked"])
            self.assertIn("len=", t["password_masked"])

    def test_report_shape(self):
        """目的：报告字段完整（host/port/username/attempts_planned/started_at）。"""
        report = sb.brute("127.0.0.1", 9, "root", ["a"],
                          timeout=2, threads=1, max_attempts=1, delay=0)
        for key in ("host", "port", "username", "attempts_planned",
                    "started_at", "tried", "found", "stop_reason", "timeline"):
            self.assertIn(key, report)


class TestCliValidation(unittest.TestCase):
    """CLI 参数校验冒烟：非法值由 argparse 报错退出（不触网）。"""

    def _run(self, *extra):
        import subprocess
        import sys
        script = Path(_bootstrap.ROOT) / "ssh-bruter" / "ssh_bruter.py"
        wl = Path(tempfile.gettempdir()) / "wl_cli_test.txt"
        wl.write_text("x\n", encoding="utf-8")
        try:
            return subprocess.run(
                [sys.executable, str(script), "-H", "127.0.0.1", "-u", "root",
                 "-p", str(wl), *extra],
                capture_output=True, text=True, timeout=60)
        finally:
            wl.unlink(missing_ok=True)

    def test_invalid_port_rejected(self):
        """目的：端口 70000 被参数校验拒绝。"""
        r = self._run("-P", "70000")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("65535", r.stderr)

    def test_invalid_timeout_rejected(self):
        """目的：超时 0 秒被拒绝（须 0.1-60）。"""
        r = self._run("--timeout", "0")
        self.assertNotEqual(r.returncode, 0)

    def test_invalid_threads_rejected(self):
        """目的：线程数超上限被拒绝。"""
        r = self._run("--threads", "999")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("线程数", r.stderr)


if __name__ == "__main__":
    unittest.main()
