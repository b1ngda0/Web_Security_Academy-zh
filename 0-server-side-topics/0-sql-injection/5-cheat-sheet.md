---
description: '原文链接：https://portswigger.net/web-security/sql-injection/cheat-sheet'
---

# SQL注入备忘单

这个SQL注入备忘单包含了一些有用的语法例子，您可以用来执行执行SQL注入攻击时经常出现的各种任务。

### 字符串连接

你可以将多个字符串连接在一起组成一个字符串。

| DataBases | String |
| :---: | :---: |
| **Oracle** | 'foo'\|\|'bar' |
| Microsoft | 'foo'+'bar' |
| PostgreSQL | 'foo'\|\|'bar' |
| MySQL | `'foo' 'bar'` \[Note the space between the two strings\] `CONCAT('foo','bar')` |

### 子字符串

### 注释

### 数据库版本

### 数据库内容

### 条件错误

### 批处理（或堆叠）查询

### 时间延迟

### 有条件的时间延迟

### DNS检查

### 带数据





