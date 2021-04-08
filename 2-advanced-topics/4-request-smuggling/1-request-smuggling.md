# HTTP请求走私

在本节中，我们将说明HTTP请求走私攻击，并描述常见的请求走私漏洞如何产生的。

## 什么是HTTP请求走私？

HTTP请求走私是一种技术，用于干扰web站点处理从一个或多个用户收到的HTTP请求序列的方式。请求走私漏洞在本质上通常是关键的，允许攻击者绕过安全控制，获得对敏感数据的未经授权的访问，并直接危及其他应用程序用户。

![](../../.gitbook/assets/image%20%288%29.png)

#### 注意

HTTP请求走私最早于2005年记录，最近被PortSwigger对该主题的研究重新流行。

## HTTP请求走私攻击会发生什么？

当今的web应用程序经常在用户和最终的应用程序逻辑之间使用HTTP服务器链。用户将请求发送到前端服务器（有时称为负载平衡器或反向代理），并且该服务器将请求转发到一个或多个后端服务器。这种类型的体系结构在现代基于云的应用程序中越来越普遍，在某些情况下是不可避免的。

当前端服务器将HTTP请求转发到后端服务器时，它通常会通过同一后端网络连接发送多个请求，因为这样做效率更高且性能更高。 该协议非常简单：HTTP请求一个接一个地发送，接收服务器解析HTTP请求标头以确定一个请求在哪里结束，下一个请求在哪里开始：

![](../../.gitbook/assets/image%20%283%29.png)

在这种情况下，至关重要的是前端和后端系统就请求之间的边界达成一致。 否则，攻击者可能会发送一个模棱两可的请求，该请求被前端和后端系统以不同的方式解释：

![](../../.gitbook/assets/image%20%2812%29.png)

在此，攻击者使前端请求的一部分被后端服务器解释为下一个请求的开始。 它实际上是在下一个请求之前，因此会干扰应用程序处理该请求的方式。 这是请求走私攻击，可能会造成破坏性后果。

## HTTP请求走私漏洞如何产生？

大多数HTTP请求走私漏洞的出现是因为HTTP规范提供了两种不同的方法来指定请求的结束位置：Content-Length标头和Transfer-Encoding标头。

Content-Length标头很简单：它以字节为单位指定消息正文的长度。 例如：

```text
POST /search HTTP/1.1
Host: normal-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 11

q=smuggling
```

可以使用Transfer-Encoding标头指定邮件正文使用分块编码。 这意味着消息正文包含一个或多个数据块。 每个块均由以字节为单位的块大小（以十六进制表示）组成，后跟换行符，然后是块内容。 该消息以大小为零的块终止。 例如：

```text
POST /search HTTP/1.1
Host: normal-website.com
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunke

d
bq=smuggling
0
```

#### Note

许多安全测试人员都不知道可以在HTTP请求中使用分块编码，原因有两个：

* Burp Suite会自动解压分块的编码，以使消息更易于查看和编辑。
* 浏览器通常不会在请求中使用分块编码，通常只能在服务器响应中看到。

由于HTTP规范提供了两种不同的方法来指定HTTP消息的长度，因此单个消息可能会同时使用这两种方法，从而使它们彼此冲突。 HTTP规范试图通过指出如果同时存在Content-Length标头和Transfer-Encoding标头来防止此问题，则应该忽略Content-Length标头。 这可能足以避免在仅使用一台服务器的情况下产生歧义，而在将两个或多个服务器链接在一起的情况下则不会。 在这种情况下，可能由于两个原因而出现问题：

* 某些服务器在请求中不支持Transfer-Encoding标头。
* 如果以某种方式混淆了标头，则某些确实支持Transfer-Encoding标头的服务器可能不会被处理。

如果前端服务器和后端服务器在（可能是混淆的）Transfer-Encoding标头方面的行为不同，则它们可能在连续请求之间的边界上存在分歧，从而导致请求走私漏洞。

## 如何执行HTTP请求走私攻击

请求走私攻击涉及将Content-Length标头和Transfer-Encoding标头都放置在单个HTTP请求中，并对它们进行处理，以便前端服务器和后端服务器以不同的方式处理请求。 完成此操作的确切方式取决于两个服务器的行为：

* CL.TE：前端服务器使用Content-Length标头，而后端服务器使用Transfer-Encoding标头。
* TE.CL：前端服务器使用Transfer-Encoding标头，而后端服务器使用Content-Length标头。
* TE.TE：前端服务器和后端服务器都支持Transfer-Encoding标头，但是可以通过对标头进行某种方式的混淆来诱导其中一台服务器不对其进行处理。

### CL.TE 漏洞

在这里，前端服务器使用Content-Length标头，而后端服务器使用Transfer-Encoding标头。 我们可以执行以下简单的HTTP请求走私攻击：

```text
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 13
Transfer-Encoding: chunked0SMUGGLED
```

前端服务器处理Content-Length标头，并确定请求主体的长度为13个字节，直至SMUGGLED的末尾。 该请求被转发到后端服务器。

后端服务器处理Transfer-Encoding标头，因此将消息正文视为使用分块编码。 它处理第一个块，该块被声明为零长度，因此被视为终止请求。 接下来的字节SMUGGLED将不予处理，后端服务器会将其视为序列中下一个请求的开始。

**实验室**[HTTP请求走私，基本的CL.TE漏洞](http://portswigger.cn/academy/subpage/allTopics/all-4.html#how-do-http-request-smuggling-vulnerabilities-arise)

### TE.CL 漏洞

在这里，前端服务器使用Transfer-Encoding标头，而后端服务器使用Content-Length标头。 我们可以执行以下简单的HTTP请求走私攻击：

```text
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0
```

#### 注意

要使用Burp Repeater发送此请求，您首先需要转到Repeater菜单，并确保未选中“ Update Content-Length”选项。

您需要在结尾的0后面加上尾随序列\r\n\r\n。

前端服务器处理Transfer-Encoding标头，因此将消息正文视为使用分块编码。 它处理第一个块，声明为8个字节长，直到SMUGGLED之后的行的开始。 它处理第二个数据块，该数据块的长度为零，因此被视为终止请求。 该请求被转发到后端服务器。

后端服务器处理Content-Length标头，并确定请求正文的长度为3个字节，直到8之后的行的开头。其余字节（从SMUGGLED开始）一直未处理，后端服务器 会将其视为序列中下一个请求的开始。

**实验室**[HTTP请求走私，基本的CL.TE漏洞](http://portswigger.cn/academy/subpage/allTopics/all-4.html#how-do-http-request-smuggling-vulnerabilities-arise)

### TE.TE行为：混淆TE标头

在这里，前端服务器和后端服务器都支持Transfer-Encoding标头，但是可以通过对标头进行某种方式的混淆来诱导其中一台服务器不对其进行处理。

可能存在无穷无尽的方式来混淆Transfer-Encoding标头。 例如：

```text
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding:[tab]chunked
[space]Transfer-Encoding: chunked
X: X[\n]Transfer-Encoding: chunked
Transfer-Encoding: chunked
```

这些技术中的每一种都涉及与HTTP规范的细微差异。 实现协议规范的实际代码很少会绝对精确地遵循该规范，并且不同的实现通常会容忍规范的不同变化。 要发现TE.TE漏洞，必须找到Transfer-Encoding标头的某些变体，以便只有前端服务器或后端服务器中的一个对其进行处理，而另一个服务器将其忽略。

根据是否诱使前端服务器或后端服务器不处理混淆的Transfer-Encoding标头，其余的攻击将采用之前描述的与CL.TE或TE.CL漏洞相同的形式。

**实验室**[HTTP请求走私，混淆了TE标头](http://portswigger.cn/academy/subpage/allTopics/all-4.html#how-do-http-request-smuggling-vulnerabilities-arise)

## 如何防止HTTP请求走私漏洞

如果前端服务器通过同一网络连接将多个请求转发到后端服务器，并且后端连接所使用的协议带来两台服务器之间的边界不一致的风险，则会出现HTTP请求走私漏洞 要求。 防止HTTP请求走私漏洞的一些通用方法如下：

* 禁用后端连接的重用，以便每个后端请求通过单独的网络连接发送。
* * 使用HTTP / 2进行后端连接，因为此协议可防止对请求之间的边界产生歧义。
* 前端服务器和后端服务器使用完全相同的Web服务器软件，以便它们就请求之间的界限达成一致。

在某些情况下，可以通过使前端服务器规范化歧义请求或使后端服务器拒绝歧义请求并关闭网络连接来避免漏洞。 但是，这些方法比上面确定的通用缓解措施更容易出错。

