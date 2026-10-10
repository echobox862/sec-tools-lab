# -*- coding: utf-8 -*-
"""报告导出：JSON / CSV 双格式统一实现。

约定（各工具一致）：
- .json -> 整个 report dict，ensure_ascii=False，indent=2；
- .csv  -> utf-8-sig（Excel 可直接打开），先写表头再写行；
- 其他后缀 -> ValueError（由调用方的 main 转为错误退出）。
"""
import csv
import json


def export_report(report, path, csv_header, csv_rows, message):
    """把 report 导出到 path。

    参数：
        report:     要序列化为 JSON 的完整报告 dict
        path:       输出路径，后缀决定格式（.json / .csv）
        csv_header: CSV 表头（list[str]）
        csv_rows:   CSV 数据行（可迭代的 list 值序列）
        message:    成功后打印的提示文案（各工具原文案不同，透传以保持输出一致）
    抛出：
        OSError（写盘失败）、ValueError（后缀非法）
    """
    lower = path.lower()
    if lower.endswith(".json"):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
    elif lower.endswith(".csv"):
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow(csv_header)
            writer.writerows(csv_rows)
    else:
        raise ValueError("导出文件需 .csv 或 .json 后缀")
    print(message)
