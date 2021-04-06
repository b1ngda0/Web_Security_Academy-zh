---
description: '原文链接：https://portswigger.net/web-security/sql-injection/cheat-sheet'
---

# SQL注入备忘单

这个SQL注入备忘单包含了一些有用的语法例子，您可以用来执行执行SQL注入攻击时经常出现的各种任务。

### 字符串连接

你可以将多个字符串连接在一起组成一个字符串。

| DataBases | Statements |
| :--- | :--- |
| **Oracle** | 'foo'\|\|'bar' |
| **Microsoft** | 'foo'+'bar' |
| **PostgreSQL** | 'foo'\|\|'bar' |
| **MySQL** | `'foo' 'bar'` \[Note the space between the two strings\] `CONCAT('foo','bar')` |

### 子字符串

您可以从指定的偏移量中提取字符串的部分长度。请注意，偏移量的索引是基于1的。以下每个表达式都会返回字符串 ba。

| DataBases | Statements |
| :--- | :--- |
| Oracle | SUBSTR\('foobar', 4, 2\) |
| Microsoft | SUBSTRING\('foobar', 4, 2\) |
| PostgreSQL | SUBSTRING\('foobar', 4, 2\) |
| MySQL | SUBSTRING\('foobar', 4, 2\) |

### 注释

您可以使用注释来截断查询，并删除输入之后的原始查询部分。

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
      <td style="text-align:left">--comment</td>
    </tr>
    <tr>
      <td style="text-align:left">Microsoft</td>
      <td style="text-align:left">
        <p>--comment</p>
        <p>/*comment*/</p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">PostgreSQL</td>
      <td style="text-align:left">
        <p>--comment</p>
        <p>/*comment*/</p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">MySQL</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left"></td>
      <td style="text-align:left"></td>
    </tr>
  </tbody>
</table>

### 数据库版本

### 数据库内容

### 条件错误

### 批处理（或堆叠）查询

### 时间延迟

### 有条件的时间延迟

### DNS检查

### 带数据渗出的DNS检查







