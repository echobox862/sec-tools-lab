# -*- coding: utf-8 -*-
"""测试引导：把 5 个工具目录加入 sys.path，使测试文件可以直接 import 被测模块。"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

for _sub in ("port-scanner", "dict-generator", "ssh-bruter",
             "web-login-bruter", "sqlmap-tamper"):
    _p = str(ROOT / _sub)
    if _p not in sys.path:
        sys.path.insert(0, _p)
