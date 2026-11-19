# pairwise-archive-extract

## ① 题面

开放了资料包导入接口后，解压就能把文件写出目录：成员名里的 ../、绝对路径、盘符和反斜杠都直接落盘；归档里的符号链接与硬链接指向外部，解压后写文件直接穿透；只限制单文件大小，条目数、总量、压缩比和路径长度都没上限，一个压缩炸弹就能把磁盘打满；边解压边落盘，失败留下半个目录，重复成员还能覆盖已校验的文件；落盘后不再复核真实路径，大小写不敏感的文件系统上 A 与 a 互相覆盖。safe_extract/archive.py 是核心，tests/test_archive.py 15个红。要修的是：成员名先规范化并拒绝越界；链接目标解析后必须仍在目标目录内；条目数、总量、压缩比、路径长度四项上限；先全量校验再原子落盘；落盘后复查真实路径与文件清单。

## ② 运行方式

```powershell
cd D:\gsb-20261119\pairwise-archive-extract
python -m pytest tests -q
```

初始状态：`safe_extract/archive.py` 的 5 个函数全部只有契约与 `raise NotImplementedError`，因此 15 个测试全部变红。预期输出尾部：

```text
15 failed in 0.12s
```

要求恰好 `15 failed`，不能出现 collection error，也不能有 import / syntax error。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

## ④ 约束

`tests/` 目录不可修改：只允许改 `safe_extract/` 下的实现，测试文件是验收标准。
