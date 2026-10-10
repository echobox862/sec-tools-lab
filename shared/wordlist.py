# -*- coding: utf-8 -*-
"""口令字典文件读取：一行一条，UTF-8，跳过空行与纯空白行。

内存口径：当前实现一次性载入列表——候选总量需用于 attempts_planned 统计，
且学习场景字典规模有限。超大字典的流式改造需先调整报告字段语义（见 docs/04）。
"""


class WordlistError(ValueError):
    """字典文件缺失、编码错误或为空。"""


def load_wordlist(path):
    """读取字典文件，返回非空行列表（保留行内原有空白，仅剥离行尾换行）。

    抛出 WordlistError：文件不存在 / 非 UTF-8 编码 / 无任何有效行。
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            words = [ln.rstrip("\n") for ln in f if ln.strip()]
    except FileNotFoundError:
        raise WordlistError(f"字典文件不存在：{path}")
    except UnicodeDecodeError as e:
        raise WordlistError(f"字典文件不是 UTF-8 编码：{e}")
    if not words:
        raise WordlistError("字典为空")
    return words
