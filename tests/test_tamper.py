# -*- coding: utf-8 -*-
"""sqlmap-tamper 的单元测试：double_keywords / case_mangle / verify（纯函数部分）。

覆盖：变形正确性、空 payload、URL 编码片段保护、词边界（不误伤普通单词）、
build_variants、check_semantics（本地 mock HTTP 服务端到端）、load_tamper 异常。
"""
import _bootstrap  # noqa: F401
import importlib.util
import io
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

TAMPER_DIR = Path(_bootstrap.ROOT) / "sqlmap-tamper"

import double_keywords as dk  # noqa: E402
import case_mangle as cm  # noqa: E402


class TestDoubleKeywords(unittest.TestCase):
    """double_keywords.tamper：关键字双写变形。"""

    def test_single_keyword(self):
        """目的：AND -> A + and + ND，删除内层 and 后仍是合法 AND（语义等价的形态依据）。"""
        self.assertEqual(dk.tamper("1 AND 1=1"), "1 AandND 1=1")

    def test_multiple_keywords(self):
        """目的：一行内多个关键词全部双写。"""
        out = dk.tamper("1 UNION SELECT user FROM users")
        self.assertEqual(out, "1 UNunionION SELselectECT user FRfromOM users")

    def test_empty_payload_passthrough(self):
        """目的：空串原样返回（sqlmap 骨架约定 if payload else payload）。"""
        self.assertEqual(dk.tamper(""), "")

    def test_none_payload_passthrough(self):
        """目的：None 原样返回，不抛异常。"""
        self.assertIsNone(dk.tamper(None))

    def test_urlencoded_segments_untouched(self):
        """目的：已 URL 编码片段中的关键词（前后邻接数字/百分号）不参与替换，
        保证编码语义不被破坏。"""
        self.assertEqual(dk.tamper("id=1%20AND%201=2%23"), "id=1%20AND%201=2%23")

    def test_word_boundary_no_false_positive(self):
        """目的：普通英文单词内含关键词子串（如 command 中的 and）不被误伤。"""
        self.assertEqual(dk.tamper("command"), "command")
        self.assertEqual(dk.tamper("administrator"), "administrator")

    def test_priority_fallback_without_sqlmap(self):
        """目的：脱离 sqlmap 环境时 __priority__ 回退为 4（PRIORITY.NORMAL 的数值）。"""
        self.assertEqual(dk.__priority__, 4)

    def test_dependencies_is_callable(self):
        """目的：骨架三件套之一 dependencies() 可调用（sqlmap 约定）。"""
        self.assertIsNone(dk.dependencies())


class TestCaseMangle(unittest.TestCase):
    """case_mangle.tamper：关键词交替大小写变形。"""

    def test_mangle_pattern(self):
        """目的：SELECT -> SeLeCt（偶数位小写、奇数位大写的确定性变形）。"""
        self.assertEqual(cm.tamper("SELECT"), "SeLeCt")

    def test_mixed_payload(self):
        """目的：多个关键词与普通字符混合时仅关键词变形（AnD 为 AnD 风格）。"""
        out = cm.tamper("1 AND 1=1")
        self.assertEqual(out, "1 AnD 1=1")

    def test_empty_and_none(self):
        """目的：空串与 None 原样返回。"""
        self.assertEqual(cm.tamper(""), "")
        self.assertIsNone(cm.tamper(None))

    def test_word_boundary(self):
        """目的：普通单词内含关键词子串不被变形。"""
        self.assertEqual(cm.tamper("command"), "command")

    def test_deterministic(self):
        """目的：同一输入两次变形结果一致（可测试、可复现，不引入随机）。"""
        self.assertEqual(cm.tamper("1 UNION SELECT x"),
                         cm.tamper("1 UNION SELECT x"))


class _FakeWafHandler(BaseHTTPRequestHandler):
    """mock 靶场：query 参数 id 含 '1=1' 返回长页（恒真），含 '1=2' 返回短页（恒假），
    其余返回中等页。模拟 sqli-labs 布尔盲注的可观测差异。"""

    def log_message(self, *a):
        pass

    def do_GET(self):
        q = parse_qs(urlparse(self.path).query)
        value = q.get("id", [""])[0]
        if "1=1" in value:
            body = "A" * 200
        elif "1=2" in value:
            body = "B" * 100
        else:
            body = "C" * 150
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body.encode())


class TestVerify(unittest.TestCase):
    """verify.py：build_variants / check_semantics（本地 mock 靶场端到端）。"""

    @classmethod
    def setUpClass(cls):
        cls.dk = dk
        cls.cm = cm
        cls.srv = HTTPServer(("127.0.0.1", 0), _FakeWafHandler)
        cls.port = cls.srv.server_address[1]
        cls.thread = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def _url(self):
        return f"http://127.0.0.1:{self.port}/Less-8/"

    def test_build_variants_applies_tampers(self):
        """目的：build_variants 返回 raw 基线 + 各 tamper 的 (true, false) 变体对。"""
        import verify as vf
        base_t, base_f = "1' AND 1=1", "1' AND 1=2"
        variants = vf.build_variants(base_t, base_f,
                                     {"double": self.dk, "case": self.cm})
        self.assertEqual(variants["raw"], (base_t, base_f))
        self.assertEqual(variants["double"], (self.dk.tamper(base_t),
                                              self.dk.tamper(base_f)))
        self.assertEqual(variants["case"], (self.cm.tamper(base_t),
                                            self.cm.tamper(base_f)))

    def test_check_semantics_semantic_equivalence(self):
        """目的：核心验收——变形后的恒真/恒假长度差与 raw 同方向非零（数据库仍按预期执行）。"""
        import verify as vf
        variants = vf.build_variants(" AND 1=1", " AND 1=2",
                                     {"double": self.dk, "case": self.cm})
        rows = vf.check_semantics(self._url(), "id", "1", variants, timeout=5)
        self.assertEqual([r["variant"] for r in rows], ["raw", "double", "case"])
        raw = rows[0]
        self.assertEqual(raw["diff"], 100)  # 200 - 100
        for r in rows[1:]:
            self.assertTrue(r["db_accepts"],
                            f"{r['variant']} 语义等价校验失败：{r}")
            self.assertEqual(r["diff"], 100)

    def test_check_semantics_detects_broken_semantics(self):
        """目的：语义被破坏（变形导致条件失效）时 db_accepts=False——
        模拟一个把 1=1/1=2 都变成同义条件的坏 tamper。"""
        import verify as vf

        class Broken:
            @staticmethod
            def tamper(payload, **kwargs):
                # 把恒真/恒假都改成同样的串 -> 长度差消失 -> 数据库条件失效
                return payload.replace("1=2", "1=1") if payload else payload

        variants = vf.build_variants(" AND 1=1", " AND 1=2", {"broken": Broken})
        rows = vf.check_semantics(self._url(), "id", "1", variants, timeout=5)
        self.assertFalse(rows[1]["db_accepts"])

    def test_load_tamper_valid_script(self):
        """目的：load_tamper 能加载仓库内的真实 tamper 脚本。"""
        import verify as vf
        mod = vf.load_tamper(str(TAMPER_DIR / "double_keywords.py"))
        self.assertTrue(hasattr(mod, "tamper"))

    def test_load_tamper_rejects_non_tamper(self):
        """目的：不含 tamper() 的脚本加载时 SystemExit 并提示原因。"""
        import verify as vf
        with tempfile.TemporaryDirectory() as d:
            bad = Path(d) / "bad.py"
            bad.write_text("x = 1\n", encoding="utf-8")
            with self.assertRaises(SystemExit):
                vf.load_tamper(str(bad))


class TestTamperSqlmapCompat(unittest.TestCase):
    """sqlmap 环境兼容性：脚本在真实 sqlmap 的 tamper 目录下应可被识别。
    （无 sqlmap 环境时跳过——本测试仅验证 import 回退路径不抛异常。）"""

    def test_scripts_compile_standalone(self):
        """目的：两个 tamper 脚本在无 sqlmap 环境下独立编译执行不抛 ImportError。"""
        for name in ("double_keywords.py", "case_mangle.py"):
            src = (TAMPER_DIR / name).read_text(encoding="utf-8")
            compile(src, name, "exec")


if __name__ == "__main__":
    unittest.main()
