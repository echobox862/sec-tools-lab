# 05 sqlmap tamper · 需求分析

> 来源：`Python tamper编写.pdf`（23 页，**文本可正常提取**）+ 实训精讲第 6 篇
> 学习主线：WAF 与数据库「对同一段文本理解不一致」→ tamper 三行骨架 → 自写绕过脚本
> 定位：**唯一不独立运行的工具**——它是 sqlmap 的插件，交付物是两个 tamper 脚本 + 一个独立验证脚本。

---

## 1. 核心认知（设计依据）

1. **绕过的统一原理：两层解释器规则不一致**——WAF 做模式匹配（看到 `union select` 就拦），数据库做语法解析（`UnIoN/**/SeLeCt`、`ununionion` 都能懂）。**「乱」没有用，「语法等价」才有用**。
2. **唯一验收标准（材料原话级结论）：变形后的 SQL 必须仍能被数据库正确执行**。推论：**报错注入不能滥用 tamper**——报错注入依赖一个如期触发的具体错误，payload 被改得数据库看不懂只会得到语法错误，不是绕过成功。
3. sqlmap 把 payload 变形设计成插件体系：**核心引擎管「怎么测」，tamper 管「payload 长什么样」**，新增绕过只需加文件不动引擎——这个架构本身就是学习对象。

## 2. 核心业务对象与关键属性

### TamperModule（每个 tamper 脚本的三行骨架，sqlmap 约定）

| 成员 | 类型/签名 | 说明 |
|---|---|---|
| `__priority__` | PRIORITY 枚举 | 多个 tamper 同时加载时的执行顺序（LOWEST…HIGHEST，定义于 `lib/core/enums.py`）。变形有先后依赖（先编码会让后续关键词替换匹配不上），顺序是插件系统的经典问题 |
| `dependencies()` | `() -> None` | 声明适用环境（如仅某类数据库）；不满足时 sqlmap 提前提示而非跑完才失败 |
| `tamper(payload, **kwargs)` | `str` | **唯一必填实现**：输入原 payload，返回变形结果。`**kwargs` 允许接收上下文而不改签名 |

### 自写脚本清单（本次交付两个）

| 脚本 | 绕过方式 | 变形逻辑（需求描述） | 针对的 WAF 行为 |
|---|---|---|---|
| `double_keywords.py` | **关键字双写**（实训主线） | 对关键词集合 `UNION/SELECT/AND/OR/WHERE` 做 `UNION → UNIunionON` 式双写 | 「匹配到关键词就删除/拦截」的单次替换型 WAF：删掉内层关键词后剩下一个合法 UNION |
| `case_mangle.py` | **大小写混写** | 关键词按固定或随机模式混写 `SeLeCt` | 大小写敏感匹配的 WAF；**依赖目标数据库不区分大小写（MySQL 成立，其他库需 dependencies 声明）** |

### VerifyResult（独立验证脚本输出）

| 属性 | 说明 |
|---|---|
| `raw_len / tampered_len` | 原始与变形 payload 的响应特征 |
| `db_accepts` | 数据库是否仍按预期执行（恒真/恒假响应差异仍在——**语义等价的实证**） |
| `bypass` | WAF 是否放行（本地无 WAF 时此项验证「未破坏语义」；有 WAF 环境时验证「放行」） |

## 3. 接口定义

```python
# double_keywords.py（与 case_mangle.py 同构）
from lib.core.enums import PRIORITY
__priority__ = PRIORITY.NORMAL

def dependencies() -> None: ...          # 声明适用数据库（MySQL 类不区分大小写）
def tamper(payload: str, **kwargs) -> str:
    """对关键词集合逐个双写替换；payload 为空时原样返回（apostrophemask.py 的
    `if payload else payload` 防空约定）"""

# verify.py —— 脱离 sqlmap 的独立验证（本项目特色：不写死在 sqlmap 环境里才能自动化测试）
def build_variants(payload: str) -> dict[str, str]:
    """{'raw': ..., 'double': ..., 'case': ...}"""

def check_semantics(url: str, param: str, variants: dict) -> VerifyResult:
    """对本地 sqli-labs 布尔盲注关（Less-8）发恒真/恒假两组请求，
    对比响应长度差是否保持——保持 = 数据库仍正确执行 = 语义等价"""

CLI(verify): python verify.py --url http://127.0.0.1/sqli-labs/Less-8/ --param id
```

## 4. 实现步骤与模块依赖顺序

```
第1步 环境准备   （本地 Docker sqli-labs + sqlmap 可用；无依赖但先做）
第2步 基线采集   （无 tamper 时确认注入点可用：and 1=1 / and 1=2 响应长度差稳定）
第3步 case_mangle（最简单的一个，先跑通「骨架→被 sqlmap 加载」全链路）
第4步 double_keywords（核心交付；同样过 sqlmap --tamper 全链路）
第5步 verify.py  （依赖2-4；把语义等价检查自动化）
第6步 README     （原理说明 + 5 类绕过方式的关系图 + 使用/复现步骤）
```

**依赖关系特别说明**：第 5 步依赖第 2 步的基线——**没有「无 tamper 时的稳定响应差」，就无法证明「有 tamper 后语义仍等价」**，验证逻辑不成立。

## 5. 边界条件与异常场景

| # | 场景 | 触发条件 | 预期行为 |
|---|---|---|---|
| 1 | payload 为空 | sqlmap 传入空串 | 原样返回（骨架约定 `if payload else payload`），不抛异常 |
| 2 | 多 tamper 叠加顺序 | `--tamper=a,b` 同时加载 | `__priority__` 决定顺序；文档写明本脚本与 base64encode 类编码脚本**不可混用**（编码后关键词替换失效） |
| 3 | 报错注入场景 | 目标注入类型为报错型 | README 明示限制：变形可能吞掉预期错误信息 → 不适用（材料核心结论的实践面） |
| 4 | 大小写敏感数据库 | SQL Server 二进制排序规则等 | case_mangle 的 dependencies 声明不适用；verify 对该库应报「语义不等价」 |
| 5 | 双写被递归剥离 WAF 拦截 | 现代 WAF 循环剥离 | 输出「未绕过」**如实报告**——预期管理：本工具学习单次替换型 WAF 的绕过原理，不承诺绕过现代 WAF |
| 6 | sqlmap 版本差异 | PRIORITY 枚举位置变化 | README 记录适配的 sqlmap 版本；import 失败时给出版本提示 |
| 7 | URL 编码干扰 | payload 中含 %20/%23 等已编码片段 | 双写替换只作用于关键词字母本身，编码片段原样保留（替换用词边界匹配，不碰 `%` 序列） |
| 8 | 空格过滤场景 | WAF 拦空格 | P2 的 comment_inline 才处理；当前脚本不做，README 说明 |
| 9 | verify 目标不可达 | sqli-labs 未启动 | 明确报错并给出启动命令提示 |
| 10 | 网络波动 | 两次对比请求长度抖动 | verify 每组请求发 2 次取稳定值；差异 < 阈值报「无法判定」而非误报 |

## 6. MVP 划分

**必须实现（P0）**：`double_keywords.py` + `case_mangle.py` 两个 tamper（三行骨架完整：priority/dependencies/tamper）+ `verify.py` 语义等价自动验证 + 基线采集步骤文档化。

**P1**：`comment_inline.py`（`/**/` 内联注释绕过）——第三个绕过方式，实现同样简单。

**暂时不做（P2）**：特殊编码类（apostrophemask 的全角引号、base64、%00 类）、空格过滤类（同义替换空格）、Header 类 tamper（改 UA/XFF——材料提到 tamper 也能改 Header，但验证环境复杂）。**取舍理由**：编码与空格类对目标数据库依赖强、语义验证成本高；双写+大小写已覆盖「两层解释器不一致」这条核心原理的教学目标。

## 7. 验收标准

- `sqlmap -u "...Less-8/?id=1" --tamper=double_keywords.py --batch` 能正常加载并完成注入（对照无 tamper 基线结果一致）。
- verify.py 对 Less-8 报告 `db_accepts=True`（恒真/恒假响应差保持）。
- 两个脚本的 `dependencies()` 被错误环境加载时能给出提示。
- README 能回答「为什么双写能绕过单次替换型 WAF」——用删除后重组的过程图说明。
