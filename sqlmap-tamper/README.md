# sqlmap-tamper · 关键词双写与大小写混写 tamper

> 需求分析：[docs/05-sqlmap-tamper-需求分析.md](../docs/05-sqlmap-tamper-需求分析.md)
> 仅用于本地 sqli-labs / DVWA 靶场。

## 文件

| 文件 | 说明 |
|---|---|
| `double_keywords.py` | 关键字双写：`UNION -> UNIunionON`。针对「匹配到关键词就删除」的单次替换型 WAF |
| `case_mangle.py` | 大小写混写：`SELECT -> SeLeCt`。针对大小写敏感匹配的 WAF（依赖目标库不区分大小写，MySQL 成立） |
| `verify.py` | **语义等价独立验证**：恒真/恒假 payload 在变形前后响应差是否保持——tamper 唯一验收标准的自动化 |

## 使用

```bash
# 放入 sqlmap tamper 目录或用绝对路径
sqlmap -u "http://127.0.0.1/sqli-labs/Less-8/?id=1" --batch --tamper=double_keywords.py

# 独立验证（不需要 sqlmap 环境）
python verify.py --url http://127.0.0.1/sqli-labs/Less-8/ --param id \
    --tamper double_keywords.py --tamper case_mangle.py
```

## 原理一句话

**WAF 做模式匹配，数据库做语法解析，两者对同一段文本的理解不一致处就是缝隙。**
「乱」没有用——变形后数据库仍能正确执行（语义等价）才有用；因此**报错注入不适用本类 tamper**（它依赖一个如期触发的具体错误，payload 被改得数据库看不懂只会得到语法错误）。

## 脚本骨架（sqlmap 插件约定）

```python
__priority__ = PRIORITY.NORMAL   # 多 tamper 叠加时的执行顺序
def dependencies(): ...          # 适用环境声明（如 MySQL 类不区分大小写）
def tamper(payload, **kwargs):   # 唯一必填：变形逻辑；payload 为空原样返回
```

## 已验证

- `1 UNION SELECT user FROM users` → `1 UNunionION SELselectECT user FRfromOM users`
- URL 编码片段（`%20`、`%23`）不参与替换；payload 为空原样返回
- verify.py 对不可达目标明确报错；无 tamper 时仅采集 raw 基线
