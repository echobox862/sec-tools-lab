# -*- coding: utf-8 -*-
"""报告脱敏：命中凭据只保留前 2 位与长度，避免明文进入报告与终端。"""


def mask_password(pwd):
    """报告展示用脱敏：保留前 2 位 + 长度标注；空值显示 (empty)。

    示例：password123 -> pa*********(len=11)；"ab" -> ab(len=2)；"" -> (empty)
    """
    return (pwd[:2] + "*" * max(len(pwd) - 2, 0) + f"(len={len(pwd)})") if pwd else "(empty)"
