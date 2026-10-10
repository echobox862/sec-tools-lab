# -*- coding: utf-8 -*-
"""port-scanner/scanner.py 的单元测试。

覆盖：parse_ports（正常/边界/异常）、resolve_host、scan_port（真实 socket 监听）、
scan_host 汇总与排序、export_csv/json 往返、CLI 非法输入冒烟。
"""
import _bootstrap  # noqa: F401
import csv
import json
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scanner import (  # noqa: E402
    ScanTargetError,
    export_csv,
    export_json,
    parse_ports,
    resolve_host,
    scan_host,
    scan_port,
)


def _start_listener():
    """在本机随机空闲端口起一个监听 socket，返回 (socket, port)。"""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    return srv, srv.getsockname()[1]


class TestParsePortsNormal(unittest.TestCase):
    """parse_ports 正常路径：描述串解析、去重、排序。"""

    def test_single_port(self):
        """目的：单个端口号解析为单元素列表。"""
        self.assertEqual(parse_ports("80"), [80])

    def test_comma_list(self):
        """目的：逗号分隔列表按数值排序。"""
        self.assertEqual(parse_ports("443,80,22"), [22, 80, 443])

    def test_range(self):
        """目的：范围语法展开为闭区间。"""
        self.assertEqual(parse_ports("10-13"), [10, 11, 12, 13])

    def test_mixed_and_dedupe(self):
        """目的：范围与列表混合，且重复端口去重。"""
        self.assertEqual(parse_ports("80,90-92,80,91"), [80, 90, 91, 92])

    def test_boundaries_min_max(self):
        """目的：边界值 1 与 65535 合法（整表 65535 个 = MAX_PORTS 上限内）。"""
        self.assertEqual(parse_ports("1")[0], 1)
        self.assertEqual(parse_ports("65535")[0], 65535)
        self.assertEqual(len(parse_ports("1-65535")), 65535)


class TestParsePortsInvalid(unittest.TestCase):
    """parse_ports 异常路径：每种非法描述都应抛 ScanTargetError。"""

    def test_empty_string(self):
        """目的：空串拒绝。"""
        with self.assertRaises(ScanTargetError):
            parse_ports("")

    def test_whitespace_only(self):
        """目的：纯空白拒绝。"""
        with self.assertRaises(ScanTargetError):
            parse_ports("   ")

    def test_zero_port(self):
        """目的：端口 0 超出 1-65535。"""
        with self.assertRaises(ScanTargetError):
            parse_ports("0")

    def test_port_above_65535(self):
        """目的：端口 65536 超界。"""
        with self.assertRaises(ScanTargetError):
            parse_ports("65536")

    def test_non_numeric(self):
        """目的：非数字端口拒绝。"""
        with self.assertRaises(ScanTargetError):
            parse_ports("http")

    def test_reversed_range(self):
        """目的：起止倒置拒绝。"""
        with self.assertRaises(ScanTargetError):
            parse_ports("100-50")

    def test_empty_segment(self):
        """目的：连续逗号产生空段拒绝。"""
        with self.assertRaises(ScanTargetError):
            parse_ports("80,,443")

    def test_float_like(self):
        """目的：带小数点的输入拒绝。"""
        with self.assertRaises(ScanTargetError):
            parse_ports("80.5")


class TestResolveHost(unittest.TestCase):
    """resolve_host：IP 直通、域名解析、失败报错。"""

    def test_ip_passthrough(self):
        """目的：IP 地址原样返回。"""
        self.assertEqual(resolve_host("127.0.0.1"), "127.0.0.1")

    def test_empty_host(self):
        """目的：空主机名拒绝。"""
        with self.assertRaises(ScanTargetError):
            resolve_host("   ")

    def test_unresolvable_domain(self):
        """目的：不可解析域名抛 ScanTargetError（保留 .invalid 保留域确保不依赖外网）。"""
        with self.assertRaises(ScanTargetError):
            resolve_host("nonexistent.invalid")


class TestScanPortRealSocket(unittest.TestCase):
    """scan_port 用真实 socket 验证三态判定（本机回环，无防火墙干扰）。"""

    @classmethod
    def setUpClass(cls):
        cls.srv, cls.open_port = _start_listener()

    @classmethod
    def tearDownClass(cls):
        cls.srv.close()

    def test_open_port_detected(self):
        """目的：真实监听中的端口被判定为 open。"""
        port, status, elapsed = scan_port("127.0.0.1", self.open_port, 1.0)
        self.assertEqual(status, "open")
        self.assertEqual(port, self.open_port)
        self.assertGreaterEqual(elapsed, 0.0)

    def test_closed_port_on_loopback(self):
        """目的：未监听端口不应判定为 open（三态语义：closed 或 filtered 均合理——
        Windows 上刚关闭的监听端口可能短暂保持接受状态或超时，环境相关；
        本断言只锁定「绝不可能 open」这一确定性结论）。"""
        srv2, closed_port = _start_listener()
        srv2.close()
        port, status, _ = scan_port("127.0.0.1", closed_port, 0.5)
        self.assertEqual(port, closed_port)
        self.assertIn(status, ("closed", "filtered"))
        self.assertNotEqual(status, "open")

    def test_returns_three_tuple_shape(self):
        """目的：返回值结构为 (int, str, float)。"""
        port, status, elapsed = scan_port("127.0.0.1", self.open_port, 1.0)
        self.assertIsInstance(port, int)
        self.assertIsInstance(status, str)
        self.assertIsInstance(elapsed, float)


class TestScanHost(unittest.TestCase):
    """scan_host：多端口并发扫描的汇总、排序与 summary 统计。"""

    @classmethod
    def setUpClass(cls):
        cls.srv, cls.open_port = _start_listener()

    @classmethod
    def tearDownClass(cls):
        cls.srv.close()

    def test_summary_counts_and_sorting(self):
        """目的：open/closed 统计正确，结果按端口升序，summary 含耗时。"""
        ports = [self.open_port + 2, self.open_port, self.open_port + 1]
        report = scan_host("127.0.0.1", ports, timeout=0.5, max_threads=10)
        got_ports = [p for p, _, _ in report["results"]]
        self.assertEqual(got_ports, sorted(ports))
        s = report["summary"]
        self.assertEqual(s["total"], 3)
        self.assertEqual(s["open"], 1)
        self.assertEqual(s["closed"] + s["filtered"], 2)
        self.assertGreaterEqual(s["elapsed_s"], 0)
        self.assertIn("ip", report)
        self.assertIn("started_at", report)

    def test_empty_results_note_absent_when_all_respond(self):
        """目的：有 closed（有响应）时不应触发『全部 filtered』的可信度提示。"""
        report = scan_host("127.0.0.1", [self.open_port], timeout=0.5)
        self.assertNotIn("note", report["summary"])

    def test_all_filtered_note(self):
        """目的：整段端口全部超时（不可路由地址 10.255.255.1 + 0.3s 短超时）时
        给出可信度提示。该地址为 RFC1918 私有段且本机无此路由，filtered 是确定行为。"""
        report = scan_host("10.255.255.1", [1, 2], timeout=0.3, max_threads=2)
        self.assertEqual(report["summary"]["total"], 2)
        self.assertEqual(report["summary"]["filtered"], 2)
        self.assertIn("note", report["summary"])


class TestExport(unittest.TestCase):
    """export_csv / export_json：文件往返一致性。"""

    def setUp(self):
        self.report = {
            "host": "h", "ip": "1.2.3.4", "timeout": 1.0,
            "started_at": "2026-10-10T00:00:00",
            "results": [(80, "open", 1.5), (443, "closed", 2.0)],
            "summary": {"open": 1, "closed": 1, "filtered": 0, "total": 2,
                        "elapsed_s": 0.1},
        }

    def test_csv_roundtrip(self):
        """目的：CSV 两行数据 + 表头，回读内容与报告一致。"""
        with tempfile.TemporaryDirectory() as d:
            path = str(Path(d) / "r.csv")
            export_csv(self.report, path)
            with open(path, encoding="utf-8-sig") as f:
                rows = list(csv.reader(f))
        self.assertEqual(rows[0], ["port", "status", "elapsed_ms"])
        self.assertEqual(rows[1], ["80", "open", "1.5"])
        self.assertEqual(rows[2], ["443", "closed", "2.0"])

    def test_json_roundtrip(self):
        """目的：JSON 回读后字段值一致（注意：JSON 无元组，tuple 序列化为 list）。"""
        with tempfile.TemporaryDirectory() as d:
            path = str(Path(d) / "r.json")
            export_json(self.report, path)
            with open(path, encoding="utf-8") as f:
                loaded = json.load(f)
        self.assertEqual(loaded["results"],
                         [[*r] for r in self.report["results"]])
        self.assertEqual(loaded["summary"]["open"], 1)


class TestCliSmoke(unittest.TestCase):
    """CLI 冒烟：非法输入通过 argparse 报错并返回非零退出码。"""

    def test_invalid_port_via_cli(self):
        """目的：命令行传入非法端口时进程以非零码退出且提示原因。"""
        r = subprocess.run(
            [sys.executable, str(Path(_bootstrap.ROOT) / "port-scanner" / "scanner.py"),
             "-H", "127.0.0.1", "-p", "70000"],
            capture_output=True, text=True, timeout=30)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("65535", r.stderr + r.stdout)


if __name__ == "__main__":
    unittest.main()
