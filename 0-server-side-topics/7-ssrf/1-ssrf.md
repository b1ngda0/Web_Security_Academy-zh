---
description: '原文链接：https://portswigger.net/web-security/ssrf'
---

# 服务器端伪造请求（SSRF）

在本节中，我们将解释什么是服务器端请求伪造，描述一些常见例子，并讲解如何发现和利用各种 SSRF 漏洞。

## 什么是SSRF？

服务器端请求伪造（也称为 SSRF）是一个 web 安全漏洞，攻击者可以利用该漏洞诱使服务器端应用程序向攻击者选择的任意域发出 HTTP 请求。

在典型的 SSRF 例子中，攻击者可能导致服务器建立自身连接，或连接到组织基础结构中的其他基于 web 的服务，也或许连接到外部第三方系统。

![](../../.gitbook/assets/image%20%286%29%20%281%29.png)

## SSRF攻击有什么影响？

一个成功的 SSRF 攻击通常会导致未经授权的操作或对组织内数据的访问，无论是在易受攻击的应用程序本身中，还是在应用程序可以与之通信的其他后端系统中。 在某些情况下，SSRF 漏洞还可能允许攻击者执行任意命令。

导致与外部第三方系统建立连接的 SSRF 利用可能会导致恶意的后续攻击，这些攻击似乎源于托管存在漏洞的应用程序的组织，从而导致潜在的法律责任和声誉损失。

## 常见的SSRF攻击

SSRF 攻击通常利用信任关系来升级来自易受攻击的应用程序的攻击并执行未经授权的操作。 这些信任关系可能与服务器本身有关，也可能与同一组织内的其他后端系统有关。

### 针对服务器本身的SSRF攻击

在针对服务器本身的 SSRF 攻击中，攻击者诱使应用程序通过其环回网络接口向承载该应用程序的服务器发出 HTTP 请求。 这通常需要提供一个带有主机名的URL，例如`127.0.0.1`（指向环回适配器的保留IP地址）或`localhost`（同一适配器的常用名称）。

例如，考虑一个购物应用程序，该应用程序让用户查看特定商店中某商品是否有库存。 为了提供库存信息，应用程序必须根据所涉及的产品和商店查询各种后端 REST API。 该功能通过前端 HTTP 请求将 URL 传递给相关的后端 API 端点来实现。 因此，当用户查看某件商品的库存状态时，他们的浏览器会发出如下请求：

```http
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 118

stockApi=http://stock.weliketoshop.net:8080/product/stock/check%3FproductId%3D6%26storeId%3D1
```

这使服务器向指定的URL发出请求，检索库存状态，并将其返回给用户。

在这种情况下，攻击者可以修改请求以指定服务器本身本地的URL。 例如：

```http
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 118

stockApi=http://localhost/admin
```

在这里，服务器将获取`/admin` URL的内容并将其返回给用户。

当然，现在攻击者可以直接访问`/admin` URL。 但管理功能通常只有经过认证的合适用户才能访问。 因此，直接访问该 URL 的攻击者不会看到任何感兴趣的内容。 但是，当对`/admin` URL 的请求来自本地计算机本身时，将绕过常规访问控制。 该应用程序授予对管理功能的完全访问权限，因为该请求似乎来自受信任的位置。

> **实验：**[针对本地服务器的基本 SSRF](https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-localhost)

为什么应用程序会以这种方式运行，并且隐式地信任来自本地计算机的请求？ 这可能是由于各种原因造成的：

* 访问控制检查可能是在一个位于应用程序服务器前面的不同组件中实现的。当连接回到服务器本身时，检查被绕过了。
* 出于灾难恢复的目的，应用程序可能允许来自本地机器的任何用户在没有登录的情况下进行管理访问。这为管理员提供了一种方法，在他们失去凭证的情况下恢复系统。这里的假设是，只有完全信任的用户才能直接来自服务器本身。
* 管理界面可能正在侦听的端口号与主应用程序不同，因此用户可能无法直接访问。

这类信任关系，即源自本地机器的请求与普通请求的处理方式不同，往往是使 SSRF 成为一个严重漏洞的原因。

### 针对其他后端系统的SSRF攻击

另一种经常出现在服务器端请求伪造的信任关系是，应用服务器能够与用户不能直接访问的其他后端系统进行交互。 这些系统通常具有不可路由的专用 IP 地址。 由于后端系统通常受网络拓扑保护，因此它们的安全状况通常较弱。 在许多情况下，内部后端系统包含敏感功能，任何能够与后端系统交互的人都可以在没有认证的情况下访问这些功能。

在前面的示例中，假设在后端`https://192.168.0.68/admin`处有一个管理界面。 在这里，攻击者可以通过提交以下请求来利用 SSRF 漏洞访问管理界面：

```http
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 118

stockApi=http://192.168.0.68/admin
```

> **实验：**[针对另一个后端系统的基本 SSRF](https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-backend-system)

## 规避SSRF的常见防御措施

通常会看到包含SSRF行为以及旨在防止恶意利用的防御措施的应用程序。 通常，可以防御这些防御措施。

### 基于黑名单输入过滤的SSRF

一些应用程序阻止包含主机名（如`127.0.0.1`和`localhost`）或敏感 URL（如`/admin`）的输入。 在这种情况下，你通常可以使用各种技术来规避过滤器：

* 使用`127.0.0.1`的备用 IP 表示形式，例如`2130706433`、`017700000001`或`127.1`。
* 注册你自己的域名，该域名解析为`127.0.0.1`。 你可以使用`spoofed.burpcollaborator.net`来达到这个目的。
* 使用 URL 编码或大小写变化来混淆被屏蔽的字符串。

> **实验：**[具有基于黑名单输入过滤的SSRF](https://portswigger.net/web-security/ssrf/lab-ssrf-with-blacklist-filter)

### 基于白名单输入过滤的SSRF

一些应用程序只允许输入与允许值的白名单相匹配、以白名单开头或包含白名单的内容。在这种情况下，有时可以通过利用 URL 解析中的不一致来规避该过滤。

URL 规范包含许多在实现 URL 的特殊解析和验证时容易被忽略的特性：

* 你可以使用`@`字符在主机名之前的 URL 中嵌入凭证。 如：`https://expected-host@evil-host`。
* 你可以使用`#`字符表示一个 URL 片段。 如：`https://expected-host#evil-host`。
* 你可以利用 DNS 的命名层次结构将所需的输入放在你控制的完全限定 DNS 名称中。 如：`https://expected-host.evil-host`。
* 你可以使用 URL 编码字符来混淆 URL 解析代码。 如果实现过滤的代码处理 URL 编码字符的方式与执行后端 HTTP 请求的代码不同，这就特别有用。
* 你可以将这些技术组合在一起使用。

> **实验：**[具有基于白名单输入过滤的 SSRF](https://portswigger.net/web-security/ssrf/lab-ssrf-with-whitelist-filter)

> **阅读更多**
>
> [SSRF 的新时代](https://portswigger.net/blog/top-10-web-hacking-techniques-of-2017#1)

### 通过打开重定向绕过 SSRF 过滤

有时可以通过利用一个打开重定向漏洞来规避任何一种基于过滤的防御措施。

在前面的 SSRF 示例中，假设用户提交的 URL 被严格验证以防止对 SSRF 行为的恶意利用。然而，允许使用 URL 的应用程序包含一个打开重定向漏洞。 只要用来进行后端 HTTP 请求的 API 支持重定向，你就可以构建一个满足过滤的 URL，并导致重定向请求到所需要的后端目标。

例如，假设应用程序包含一个打开重定向漏洞，其中包含以下 URL：

```http
/product/nextProduct?currentProductId=6&path=http://evil-user.net
```

返回重定向到：

```text
http://evil-user.net
```

您可以利用打开重定向漏洞绕过 URL 过滤，并按如下方式利用 SSRF 漏洞：

```http
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 118

stockApi=http://weliketoshop.net/product/nextProduct?currentProductId=6&path=http://192.168.0.68/admin
```

这种 SSRF 漏洞之所以有效，是因为应用程序首先验证了所提供的`stockAPI` URL是否在允许的域中（确实如此）。 然后，应用程序请求所提供的 URL，这将触发打开重定向。 它遵循重定向，并向攻击者选择的内部 URL 发出请求。

## 盲SSRF漏洞

当可以诱使应用程序向提供的 URL 发出后端HTTP请求，但是在应用程序的前端响应中未返回来自后端请求的响应时，就会出现盲 SSRF 漏洞。

盲 SSRF 通常较难利用，但有时会导致服务器或其他后端组件完全远程执行代码。

## 查找SSRF漏洞的隐藏攻击面

许多服务器端请求伪造漏洞相对容易发现，因为应用程序的正常流量涉及包含完整 URL 的请求参数。其他 SSRF 的例子就比较难找了。

### 请求中的部分URL

有时，一个应用程序只将主机名或 URL 路径的一部分放入请求参数。然后，提交的值被纳入服务器端请求的完整 URL 中。如果该值很容易被识别为主机名或 URL 路径，那么潜在的攻击面可能是明显的。然而，作为完整的 SSRF 的可利用性可能是有限的，因为你不能控制被请求的整个 URL。

### 数据格式内的URL

某些应用程序以其规范允许包含数据解析器可能请求的 URL 的格式传输数据。这方面的一个明显例子就是 XML 数据格式，它已被广泛用于网络应用程序，从客户端向服务器传输结构化数据。当一个应用程序接受 XML 格式的数据并对其进行解析时，它可能会受到 XXE 注入的攻击，反过来也会受到通过 XXE 的 SSRF 的攻击。当我们研究 XXE 注入漏洞时，我们会更详细地介绍这个问题。

### **通过**Referer标头的SSRF

一些应用程序采用服务器端的分析软件来跟踪访问者。这种软件经常记录请求中的 Referer 头，因为这对追踪进入的链接特别有意义。通常情况下，分析软件会实际访问出现在 Referer 头中的任何第三方 URL。这通常是为了分析引用网站的内容，包括传入链接中使用的锚文本。因此，Referer 标头往往代表了 SSRF 漏洞的富有成效的攻击面。请参阅[盲 SSRF 漏洞](https://portswigger.net/web-security/ssrf/blind)，了解涉及 Referer 头的漏洞的例子。

> **阅读更多**
>
> [Cracking the lens: Targeting auxiliary systems](https://portswigger.net/blog/cracking-the-lens-targeting-https-hidden-attack-surface#aux)

