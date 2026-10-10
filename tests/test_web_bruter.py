# -*- coding: utf-8 -*-
"""web-login-bruter/web_bruter.py 的单元测试。

覆盖：FormParser 表单解析、split_fields 三分类与缺失报错、build_payload token 透传、
judge 判定信号、mask 脱敏，以及基于 _mock_server.py 的 fetch_form/attempt 端到端。
"""
import _bootstrap  # noqa: F401
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

import web_bruter as wb  # noqa: E402
from web_bruter import (  # noqa: E402
    FormError,
    FormParser,
    build_payload,
    judge,
    mask,
    split_fields,
)

import _mock_server  # noqa: E402
from http.server import HTTPServer

SAMPLE_HTML = """
<html><body>
<form method="post" action="/login">
  <input type="text" name="username" value="">
  <input type="password" name="password" value="">
  <input type="hidden" name="user_token" value="abc123">
  <input type="hidden" name="session" value="s-9">
  <input type="submit" value="Login">
</form></body></html>"""


def parse(html):
    p = FormParser()
    p.feed(html)
    return [i for i in p.inputs if i["name"]]


class TestFormParser(unittest.TestCase):
    """FormParser：自适应表单解析（实训核心：不写死字段名）。"""

    def test_collects_all_named_inputs(self):
        """目的：text/password/hidden 全部按 name/type/value 收集。"""
        fields = parse(SAMPLE_HTML)
        names = [f["name"] for f in fields]
        self.assertIn("username", names)
        self.assertIn("user_token", names)
        token = next(f for f in fields if f["name"] == "user_token")
        self.assertEqual(token["type"], "hidden")
        self.assertEqual(token["value"], "abc123")

    def test_unnamed_inputs_ignored(self):
        """目的：无 name 的 input 不进入字段集（无法提交）。"""
        fields = parse('<input type="text"><input type="text" name="u">')
        self.assertEqual([f["name"] for f in fields], ["u"])

    def test_empty_page(self):
        """目的：无 input 页面产出空列表（fetch_form 层据此报错）。"""
        self.assertEqual(parse("<html></html>"), [])


class TestSplitFields(unittest.TestCase):
    """split_fields：字段三分类与缺失校验。"""

    def setUp(self):
        self.fields = parse(SAMPLE_HTML)

    def test_normal_split(self):
        """目的：text→用户名、password→密码、其余进 others（含 token）。"""
        user, pwd, others = split_fields(self.fields, "admin")
        self.assertEqual(user, "username")
        self.assertEqual(pwd, "password")
        other_names = [f["name"] for f in others]
        self.assertIn("user_token", other_names)
        self.assertIn("session", other_names)
        self.assertNotIn("username", other_names)

    def test_missing_password_field(self):
        """目的：无 password 输入框时报 FormError。"""
        with self.assertRaises(FormError):
            split_fields(parse('<input type="text" name="u">'), "admin")

    def test_missing_username_field(self):
        """目的：无 text 输入框时报 FormError。"""
        with self.assertRaises(FormError):
            split_fields(parse('<input type="password" name="p">'), "admin")


class TestBuildPayload(unittest.TestCase):
    """build_payload：token 等隐藏字段透传 + 用户名密码替换。"""

    def test_hidden_fields_carried(self):
        """目的：除用户名/密码外的字段（含 token）按页面当前值原样携带——
        这是「像浏览器一样先取后用」通过 CSRF 校验的机制。"""
        fields = parse(SAMPLE_HTML)
        user, pwd, others = split_fields(fields, "admin")
        data = build_payload(others, user, pwd, "admin", "guess1")
        self.assertEqual(data["user_token"], "abc123")
        self.assertEqual(data["session"], "s-9")
        self.assertEqual(data["username"], "admin")
        self.assertEqual(data["password"], "guess1")

    def test_no_extra_fields(self):
        """目的：无 hidden 字段时 payload 只含用户名/密码两项。"""
        data = build_payload([], "u", "p", "admin", "x")
        self.assertEqual(data, {"u": "admin", "p": "x"})


class TestJudge(unittest.TestCase):
    """judge：判定信号三分支（爆破脚本的「眼睛」）。"""

    def test_fail_marker(self):
        """目的：命中 fail_marker 判 fail。"""
        self.assertEqual(judge("Login failed", 200, "", "Login failed", ""), "fail")

    def test_success_marker_in_body(self):
        """目的：命中 success_marker 判 success（优先于 fail）。"""
        self.assertEqual(judge("Welcome admin", 200, "", "Login failed",
                               "Welcome"), "success")

    def test_success_marker_in_redirect(self):
        """目的：成功特征出现在 Location 头也算 success。"""
        self.assertEqual(judge("", 302, "/welcome", "Login failed",
                               "/welcome"), "success")

    def test_redirect_without_success_marker(self):
        """目的：302 且未配置 success_marker 时按重定向判定 success。"""
        self.assertEqual(judge("", 302, "/index.php", "Login failed", ""), "success")

    def test_unknown_when_no_signal(self):
        """目的：两个 marker 都未命中判 unknown（触发上层计数与终止逻辑）。"""
        self.assertEqual(judge("something else", 200, "", "Login failed",
                               ""), "unknown")

    def test_success_marker_wins_over_fail(self):
        """目的：页面同时含两个 marker 时以 success 为先（安全侧判定）。"""
        self.assertEqual(judge("Login failed? Welcome", 200, "", "Login failed",
                               "Welcome"), "success")


class TestMask(unittest.TestCase):
    """mask：报告脱敏（GitHub 展示友好）。"""

    def test_normal_password(self):
        """目的：保留前 2 位，其余打码并标注长度。"""
        self.assertEqual(mask("password123"), "pa*********(len=11)")

    def test_two_char_password(self):
        """目的：2 位密码只保留原样前 2 位（无星号）+ 长度。"""
        self.assertEqual(mask("ab"), "ab(len=2)")

    def test_empty_password(self):
        """目的：空密码显示 (empty)。"""
        self.assertEqual(mask(""), "(empty)")


class TestEndToEndWithMockServer(unittest.TestCase):
    """端到端：fetch_form → split_fields → attempt 全链路（复用 _mock_server）。"""

    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), _mock_server.Handler)
        cls.port = cls.srv.server_address[1]
        cls.t = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.t.start()
        cls.opener = wb.make_opener(insecure=False)
        cls.url = f"http://127.0.0.1:{cls.port}/login"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def test_fetch_form_finds_token(self):
        """目的：GET 登录页解析出 username/password/user_token 三个字段。"""
        fields, raw_len = wb.fetch_form(self.opener, self.url, 5, False)
        names = [f["name"] for f in fields]
        self.assertIn("username", names)
        self.assertIn("password", names)
        self.assertIn("user_token", names)
        self.assertGreater(raw_len, 0)

    def test_wrong_password_judged_fail(self):
        """目的：错误密码 + 正确 token → 'Login failed' → fail。"""
        fields, _ = wb.fetch_form(self.opener, self.url, 5, False)
        res, html, status, redirect = wb.attempt(
            self.opener, self.url, fields, "username", "password",
            "admin", "wrongpwd", 5, False, "utf-8", refresh_token=True)
        self.assertEqual(wb.judge(html, status, redirect, "Login failed", ""),
                         "fail")

    def test_correct_password_redirects_and_succeeds(self):
        """目的：正确密码 → 302 /welcome → 按 Location 判 success（MVP 无 success_marker）。"""
        fields, _ = wb.fetch_form(self.opener, self.url, 5, False)
        res, html, status, redirect = wb.attempt(
            self.opener, self.url, fields, "username", "password",
            "admin", _mock_server.CORRECT_PWD, 5, False, "utf-8",
            refresh_token=True)
        self.assertEqual(status, 302)
        self.assertEqual(judge(html, status, redirect, "Login failed", ""),
                         "success")

    def test_missing_token_rejected_by_server(self):
        """目的：不带 token 的 POST 被服务器拒绝——证明 token 机制真实生效，
        以及 refresh_token 两步走是必要的（实训材料的教学点）。"""
        payload = {"username": "admin", "password": "wrong"}
        status, headers, html = wb.post_attempt(self.opener, self.url, payload,
                                                5, False, "utf-8")
        self.assertIn("CSRF token is incorrect", html)

    def test_token_is_one_time(self):
        """目的：同一 token 第二次提交被拒——refresh_token=True 的必要性。"""
        fields, _ = wb.fetch_form(self.opener, self.url, 5, False)
        _, _, others = split_fields(fields, "admin")
        payload = build_payload(others, "username", "password", "admin", "x")
        s1, _, h1 = wb.post_attempt(self.opener, self.url, payload, 5, False)
        s2, _, h2 = wb.post_attempt(self.opener, self.url, payload, 5, False)
        # 第一次 fail（正常响应），第二次 token 已作废
        self.assertIn("Login failed", h1)
        self.assertIn("CSRF token is incorrect", h2)


class TestLowercaseLocationHeader(unittest.TestCase):
    """审计 M2 回归：服务器发小写 location 头时重定向判定不能失效。

    HTTP 头名不区分大小写，但把 Message 转 dict 后 get('Location') 会漏掉
    小写键——修复前 302 成功被误判 unknown，连续 3 次误终止。
    """

    @classmethod
    def setUpClass(cls):
        class LowercaseLocHandler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                self.rfile.read(length)
                # 故意用小写头名：模拟 HTTP/2 网关 / 部分反代的实际行为
                self.send_response(302)
                self.send_header("location", "/welcome")
                self.end_headers()

        cls.srv = HTTPServer(("127.0.0.1", 0), LowercaseLocHandler)
        cls.port = cls.srv.server_address[1]
        cls.t = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.t.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def test_post_attempt_reads_lowercase_location(self):
        """目的：小写 location 响应头也能取到重定向目标（大小写不敏感 get）。"""
        opener = wb.make_opener(insecure=False)
        url = f"http://127.0.0.1:{self.port}/login"
        status, redirect, _ = wb.post_attempt(opener, url, {"u": "x"}, 5, False)
        self.assertEqual(status, 302)
        self.assertEqual(redirect, "/welcome")

    def test_judge_success_via_lowercase_redirect(self):
        """目的：小写 location + 302 在无 success_marker 时判 success（修复前为 unknown）。"""
        opener = wb.make_opener(insecure=False)
        url = f"http://127.0.0.1:{self.port}/login"
        status, redirect, html = wb.post_attempt(opener, url, {"u": "x"}, 5, False)
        self.assertEqual(wb.judge(html, status, redirect, "Login failed", ""),
                         "success")


if __name__ == "__main__":
    unittest.main()
