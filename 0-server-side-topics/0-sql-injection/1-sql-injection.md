---
description: '原文链接：https://portswigger.net/web-security/sql-injection'
---

# SQL注入

在本节中，我们将通过列举一些通用示例来解释什么是 SQL 注入，如何发现和验证不同类型的 SQL 注入漏洞，并总结如何防止 SQL 注入。

![](../../.gitbook/assets/01.svg)

## 什么是SQL注入（SQLi）

SQL 注入是一种 Web 安全漏洞，它允许攻击者干扰应用程序的正常数据库查询。通常它允许攻击者查询他们无法查询的数据。这可能包括属于其他用户的数据，或应用程序本身能够访问的任何其他数据。在许多案例中，攻击者利用 SQLi 可以修改或删除数据，从而导致应用程序内容和行为（逻辑）永久更改。

在一些情况下，攻击者还可以升级 SQL 注入攻击来破坏基础服务器或其他后端基础结构，或者执行拒绝服务攻击。

{% embed url="https://www.youtube.com/watch?v=wX6tszfgYp4" caption="" %}

## 一次成功的SQL注入有什么影响

一次成功的 SQL 注入攻击能造成未授权的敏感数据访问，比如密码、信用卡详情、个人用户信息。近年来许多备受瞩目的数据泄漏都是由 SQL 注入攻击造成的，这导致了泄露方的声誉受损和监管罚款。在某些情况下，攻击者也可以获取组织系统的持久后门，并且可能在很长一段时间内未被发现，从而达到一种攻击折衷目的。

## SQL注入示例

不同的情况下会出现各种 SQL 注入漏洞、攻击和手法。一些常见的 SQL 注入示例包括：

* 检索隐藏的数据，你可以修改 SQL 查询以返回其他结果。
* 颠覆应用程序逻辑，你可以更改查询以干扰应用程序逻辑。
* UNION 攻击，你可以从不同的数据库表中检索数据。
* 检索数据库，你可以提取数据库的版本和结构信息。
* SQL 盲注攻击，即在应用程序的响应中不返回你控制的查询结果。

## 检索隐藏数据

考虑一个显示不同类别产品的购物应用程序。当用户点击 Gifts 类别时，浏览器请求如下 URL：

```text
https://insecure-website.com/products?category=Gifts
```

这将导致应用程序执行 SQL 查询，从数据库中检索相关产品的详细信息：

```sql
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```

这个 SQL 查询要求数据库返回：

* 所有字段数据（\*）
* 从 products 表中查询
* 产品类别是 Gifts
* released 值为1

`released = 1`的限制是为了将未发布的产品隐藏起来。对于未发布的产品，想必`released = 0`。

该应用程序未对 SQL 注入攻击采取任何防御措施，因此攻击者可以构造如下攻击：

```text
https://insecure-website.com/products?category=Gifts'--
```

这导致执行 SQL 查询：

```sql
SELECT * FROM products WHERE category = 'Gifts'--' AND released = 1
```

这里的关键是，双破折号`--`在 SQL 中是一个注释符，意味着剩余的查询条件被注释了。这有效地删除了查询的其余部分，因此不再包含`AND released = 1`这个条件。这也就是说所有的产品都会被显示，包括未发布的产品。

更进一步，攻击者可以造成应用程序显示任意类别的所有产品，包括攻击者未知的类别：

```text
https://insecure-website.com/products?category=Gifts'+OR+1=1--
```

这导致如下 SQL 查询：

```sql
SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1
```

修改后的查询将返回所有类别为 Gifts 或1等于1的所有商品。由于`1 = 1`始终为真，因此查询将返回所有商品。

{% hint style="warning" %}
实验：[WHERE 子句中的 SQL 注入漏洞，允许检索隐藏数据](https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data)
{% endhint %}

## 颠覆应用程序逻辑

考虑存在一个允许用户使用用户名和密码登录的应用程序。如果一个用户提交了 `wiener` 的用户名和 `bluecheese` 的密码，应用程序会执行以下的 SQL 查询来检查凭据：

```sql
SELECT * FROM users WHERE username = 'wiener' AND password = 'bluecheese'
```

如果查询返回了用户的详情信息，就会成功登录。否则就登录失败。

这里，攻击者可以通过简单地利用 SQL 注释符`--`从 WHERE 子句中删除密码检查，从而不用密码登录任意用户。例如，提交用户名`administrator'--`和空密码将执行如下 SQL 语句：

```sql
SELECT * FROM users WHERE username = 'administrator'--' AND password = ''
```

该查询返回用户名为 administrator 的用户，并成功地将攻击者作为该用户登录。

{% hint style="warning" %}
实验：[SQL 注入漏洞允许登录绕过](https://portswigger.net/web-security/sql-injection/lab-login-bypass)
{% endhint %}

## 从其他库表检索数据

在应用程序的响应中返回了 SQL 查询结果的情况下，攻击者可以利用 SQL 注入漏洞从数据库的其他表中检索数据。这是通过`UNION`关键字实现的，它可以执行一个额外的`SELECT`查询，并将结果追加到原始查询中。

例如，一个应用程序执行如下包含用户输入"Gifts"的查询：

```sql
SELECT name, description FROM products WHERE category = 'Gifts'
```

然后攻击者提交如下输入内容：

```sql
' UNION SELECT username, password FROM users--
```

这将导致应用程序返回所有的用户名和密码以及产品的名称和描述。

阅读更多：

{% page-ref page="2-union-attacks.md" %}

## 检索数据库

在初步识别出 SQL 注入漏洞后，获取数据库本身的一些信息通常特别有用。这些信息通常可以为进一步的利用铺平道路。

你可以查询数据库版本的详细信息。查询操作取决于数据库的类型，因此你可以通过任一技术手段推断出数据库类型。例如，在 Oracle 中你可以执行：

```sql
SELECT * FROM v$version
```

你还可以确定哪些数据库表存在以及包含哪些列。例如，大多数数据库，你可以执行以下查询列出表：

```sql
SELECT * FROM information_schema.tables
```

阅读更多：

{% page-ref page="3-examining-the-database.md" %}

{% page-ref page="5-cheat-sheet.md" %}

## SQL盲注漏洞

SQL 注入的许多实例都是盲注漏洞。这意味着应用程序不会在其响应中返回 SQL 查询的结果或任何数据库错误的细节。盲注漏洞仍然可以被利用来访问未经授权的数据，但涉及的技术通常更复杂，难以执行。

根据漏洞的性质和所涉及的数据库，可以使用以下技术来利用 SQL 盲注漏洞：

* 你可以改变查询的逻辑，根据单个条件的真假来触发应用程序响应中可检测到的差异。这可能涉及到在一些布尔逻辑中注入一个新的条件，或者有条件地触发一个诸如 divide-by-zero 之类的错误。
* 你也可以有条件地触发查询处理中的时间延迟，然后从应用程序响应时间上来判断条件是否生效；
* 你可以使用 [OAST](https://portswigger.net/burp/application-security-testing/oast) 技术触发带外网络交互。该技术非常强大，可以在其他技术无法做到的情况下发挥作用。通常，你可以直接通过带外通道泄露数据，例如，将数据放入你控制的域的 DNS 查询中。

阅读更多：

{% page-ref page="4-blind.md" %}

## 如何检测SQL注入漏洞

使用 Burp Suite 的 [Web漏洞扫描器](https://portswigger.net/burp/vulnerability-scanner) 可以快速、可靠地检测大多数 SQL 注入漏洞。

通过对应用程序中的每个入口点使用系统化的测试集来手动检测 SQL 注入。

这通常涉及：

* 提交单引号字符 ' 并查找错误或其他异常。
* 提交一些特定的 SQL 语法，对入口点的基础（原始）值和其他值进行评估，并在最终的应用程序响应中寻找系统差异 。
* 提交例如`OR 1=1`和`OR 1=2`的布尔条件，并查找应用程序响应中的差异。
* 当在 SQL 查询中执行时，提交设计用于触发时间延迟的 payloads，并寻找响应时间的差异。
* 当在 SQL 查询中执行时，提交 OAST payloads，以触发带外网络交互，并监控任何结果的交互。

## 在查询不同部分中的SQL注入

大多数 SQL 注入漏洞都出现在`SELECT`查询的`WHERE`子句中。这类 SQL 注入通常被经验丰富的测试人员很好地理解。

但是 SQL 注入漏洞原则上可以发生在查询中的任何位置，也可以发生在不同的查询类型中。发生 SQL 注入的最常见其他位置是：

* 在`UPDATE`语句中，更新的值或`WHERE`子句中。
* 在`INSERT`语句中，插入的值内。
* 在`SELECT`语句中，表或列名内。
* 在`SELECT`语句中的`ORDER BY`子句中。

## 二阶SQL注入

一阶 SQL 注入发生在应用程序从 HTTP 请求获取用户输入的情况下，并且在处理该请求的过程中，以不安全的方式将输入合并到 SQL 查询中。

在二阶 SQL 注入（也称为存储 SQL 注入）中，应用程序从 HTTP 请求中获取用户输入并将其存储以备将来使用。这通常是通过将输入放入数据库来完成的，但是在存储数据时不会出现漏洞。之后，当处理其他 HTTP 请求时，应用程序将以不安全的方式检索存储的数据并将其合并到 SQL 查询中。

![](../../.gitbook/assets/02.svg)

二阶 SQL 注入经常出现在这样的情况下：开发人员意识到了 SQL 注入漏洞，从而安全地处理数据库输入的初始位置。当以后对数据进行处理时，由于先前已将其安全地放置到数据库中，因此认为该数据是安全的。此时数据的处理方式是不安全的，开发人员错误地认为数据是可信任的。

## 特定数据库因素

在主流的数据库平台上，SQL 语言的某些核心功能以相同的方式实现，因此，检测和利用 SQL 注入漏洞的许多方式在不同类型的数据库上均相同。

但是，常见数据库之间也存在许多差异。这意味着用于检测和利用 SQL 注入的某些技术在不同平台上的工作方式不同。例如：

* 字符串连接的语法
* 注释
* 批处理（或堆叠）查询
* 特定平台的 API
* 错误信息

阅读更多：

{% page-ref page="5-cheat-sheet.md" %}

## 如何防止SQL注入

通过使用参数化查询（也称为预处理语句）而不是查询中的字符串连接，可以防止大多数 SQL 注入实例。

由于用户输入直接连接到查询中，因此以下代码容易受到 SQL 注入的攻击：

```text
String query = "SELECT * FROM products WHERE category = '"+ input + "'";
Statement statement = connection.createStatement();
ResultSet resultSet = statement.executeQuery(query);
```

可以通过防止用户输入干扰查询结构的方式轻松重写此代码：

```text
PreparedStatement statement = connection.prepareStatement("SELECT * FROM products WHERE category = ?");
statement.setString(1, input);
ResultSet resultSet = statement.executeQuery();
```

参数化查询可用于不受信任的输入作为查询中显示为数据的任何情况，包括`WHERE`子句和`INSERT`或`UPDATE`语句中的值。它们不能用于处理查询其他部分中不可信任的输入，例如表或列名或`ORDER BY`子句。将不受信任的数据放入查询的这些部分的应用程序功能需要采用不同的方法，例如将允许的输入值列入白名单，或者使用不同的逻辑来传递所需的行为。

为了使参数化查询能够有效地防止 SQL 注入，查询中使用的字符串必须始终是一个硬编码常量，并且绝不能包含来自任何来源的任何变量数据。不要试图逐个决定数据项是否受信任，并在被认为安全的情况下继续在查询中使用字符串连接。这样会很容易就数据的可能来源犯错误，或者其他代码的更改而违反有关数据受到污染的假设。

阅读更多：

[使用 Burp Suite 的 Web 漏洞扫描器查找SQL注入漏洞](https://portswigger.net/burp/vulnerability-scanner)

