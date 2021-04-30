---
description: '原文链接：https://portswigger.net/web-security/sql-injection/union-attacks'
---

# SQL注入UNION攻击

当应用程序容易受到 SQL 注入攻击，并且查询结果在应用程序的响应中返回时，可使用`UNION`关键字从数据库的其他表检索数据。这就导致了 UNION 注入攻击。

`UNION`关键字允许你执行一个或者多个额外的`SELECT`查询，并将结果附加到原始查询中。例如：

```sql
SELECT a, b FROM table1 UNION SELECT c, d FROM table2
```

该 SQL 查询将返回包含两列的单个结果集，其中包含`table1`的`a`、`b`字段和`table2`的 c、d 字段。

为使 UNION 查询正常工作，必须满足两个关键要求：

* 各个查询必须返回相同数量的列。
* 每列的数据类型在各个查询之间必须兼容。

要执行 SQL 注入 UNION 攻击，你需要确保你的攻击满足以上这两个要求。这通常需要搞清楚：

* 原始查询中返回了多少列？
* 从原始查询返回的哪些列具有合适的数据类型以保存注入查询的结果？

### 确定SQL注入UNION攻击中所需的列数

当执行 SQL 注入 UNION 攻击时，有两种有效的方法可以确定从原始查询返回了多少列。

第一种方法涉及注入一系列 `ORDER BY` 子句，并递增指定的列索引，指到发生错误为止。例如，假设注入点是原始查询的 `WHERE` 子句中带一个引号的字符串，则可以提交：

```sql
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
etc.
```

这一系列 payloads 修改了原始查询，以按结果集中的不同列对结果进行排序。可以通过索引指定 `ORDER BY` 子句中的列，因此无需知道任何列的名称。当指定的列索引超过结果集中的实际列数时，数据库将返回错误，例如：

```text
The ORDER BY position number 3 is out of range of the number of items in the select list.
```

该应用程序实际上可能在其 HTTP 响应中返回数据库的错误，或者返回一般错误信息，更或者不返回任何结果。只要你能检测到应用程序响应的某些差异，就可能推断出查询返回了多少列。

第二种方法涉及提交一系列的包含不同数量 null 值的 `UNION SELECT` payloads：

```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
etc.
```

如果 null 值的数量与列的数量不匹配，数据库将返回一个错误，例如：

```text
All queries combined using a UNION, INTERSECT or EXCEPT operator must have an equal number of expressions in their target lists.
```

同样，应用程序实际上可能返回这个错误信息，或者返回一般错误信息，或者不返回任何结果。当 null 值的数量与列的数量匹配时，数据库会在结果集中返回一个额外的列，其中每一列都会包含 null 值。对产生的 HTTP 响应的影响取决于应用程序的代码。如果你够幸运的话，你会在响应中看到一些额外的内容，例如 HTML 表格的额外行。否则，null 值可能触发其他错误，例如 NullPointerException。最坏的情况下，响应可能与由不正确的 null 数量引起的响应没有区别，这使得确定列数的此方法无效。

> 译者注：NullPointerException 即空指针异常。如果一个对象为 null，调用其方法或访问其字段就会产生 NullPointerException。

{% hint style="warning" %}
**实验：**[SQL注入UNION攻击，确定查询返回的列数](https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns)
{% endhint %}

> **Note**
>
> - 使用 `NULL` 作为从注入的 `SELECT` 查询返回的值的原因是，每一列的数据类型在原始查询和注入查询之间必须兼容。由于 `NULL` 可以转换为每种常用的数据类型，因此当列数正确时，使用 `NULL` 可以最大程度的提高 payload 成功的机会。
> - 在 Oracle 中，`SELECT` 查询必须使用 `FROM` 关键字并指定一个有效表，Oracle 中有一个内置表 `dual`，可用于此目的。因此在 Oracle 中注入的查询语句类似于：`' UNION SELECT NULL FROM DUAL--`。
>
> - 所描述的 payloads 使用双破折号 -- 注释掉注入点后原始查询的其余部分。在 Mysql 中，双破折号后面必须有一个空格。另外，哈希符号 \# 可用于标识注释。
>
> 有关特定数据库语法的更多详细信息, 请参见 [SQL 注入备忘单](https://portswigger.net/web-security/sql-injection/cheat-sheet)。

### UNION注入攻击中查找具有有效数据类型的列

执行 SQL 注入 UNION 攻击的原因是为了能够从注入的查询中检索出结果。通常，你想检索的有趣数据将是字符串形式的，因此就需要在原始查询结果中查找数据类型为字符串数据或与之兼容的一个或更多列。

在已经确定所需的列数后，你可以通过提交一系列的 `UNION SELECT` payload ，依次将字符串值放入各列，来探测各列从而确定是否可以兼容字符串数据。例如，如果查询返回四列，你将提交：

```sql
' UNION SELECT 'a',NULL,NULL,NULL--
' UNION SELECT NULL,'a',NULL,NULL--
' UNION SELECT NULL,NULL,'a',NULL--
' UNION SELECT NULL,NULL,NULL,'a'--
```

如果列的数据类型与字符串数据不兼容，注入查询会导致数据库查询错误，例如：

```text
Conversion failed when converting the varchar value 'a' to data type int.
```

如果没有发生错误，并且应用程序的响应包含一些其他内容，包括注入的字符串值，则相关的列适用于检索字符串数据。

{% hint style="warning" %}
**实验：**[SQL 注入 UNION 攻击，查找包含文本的列](https://portswigger.net/web-security/sql-injection/union-attacks/lab-find-column-containing-text)
{% endhint %}

### 使用UNION注入攻击检索感兴趣的数据

当你确定了原始查询所返回列的列数，并找到哪一列可以兼容字符串时，就可以从这个位置检索感兴趣的数据。

假设：

* 原始查询返回两列，每一列都兼容字符串类型。
* 注入点是 `WHERE` 子句中带引号的字符串。
* 数据库中存在一个包含 `username` 和 `password` 字段的 `users` 表。

这种情况下，我们可以提交如下 payload 从 users 表中获取内容：

```sql
' UNION SELECT username, password FROM users--
```

当然，执行此攻击所需的关键信息是存在一个有 `username` 和 `password` 两个字段的名为 `users` 的表。没有这些信息，你不得不尝试去猜测表和列的名称。实际上，所有现代数据库都提供了检查数据库结构，以确定数据库包含哪些表和列的方法。

{% hint style="warning" %}
**实验：**[SQL 注入 UNION 攻击，从其他表中检索数据](https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-data-from-other-tables)
{% endhint %}

> 阅读更多：
>
> [在 SQL 注入攻击中检查数据库](https://portswigger.net/web-security/sql-injection/examining-the-database)

### 在单列中检索多个值

在前面的示例中，假设查询仅返回单个列。

你可以通过将这些值拼接在一起，轻松地在单个列检索多个值，理想情况下可以使用适当的分隔符来区分拼接的多个值。例如，在 Oracle 中你可以提交这样的输入：

```sql
' UNION SELECT username || '~' || password FROM users--
```

这里使用了双管符号 \|\| ，它是 Oracle 中的一个字符串连接运算符。注入查询将 `username` 和 `password` 连接在一起，通过 ~ 符号做分隔符。

查询的结果将使你可以读取所有的用户名和密码，如下：

```text
...
administrator~s3cure
wiener~peter
carlos~montoya
...
```

请注意，不同的数据库使用不同的语法执行字符串拼接。更多细节请参见 [SQL 注入备忘单](https://portswigger.net/web-security/sql-injection/cheat-sheet)。

{% hint style="warning" %}
**实验：**[SQL 注入 UNION 攻击，在单个列中检索多个值](https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-multiple-values-in-single-column)
{% endhint %}

