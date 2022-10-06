---
description: '原文链接：https://portswigger.net/web-security/ssrf/blind'
---

# 盲SSRF漏洞

在本节中，我们将解释什么是盲服务器端请求伪造，描述一些常见的盲 SSRF 例子，并解释如何发现和利用盲 SSRF 漏洞。

### 什么是盲SSRF？

当一个应用程序可以被诱导向提供的 URL 发出后端HTTP请求，但后端请求的响应并没有在应用程序的前端响应中返回时，就会出现盲 SSRF 漏洞。

### 盲SSRF漏洞的影响是什么？

盲 SSRF 漏洞的影响通常低于普通的 SSRF 漏洞，因为它们具有单向性。它们不能被琐碎地利用来从后端系统检索敏感数据，尽管在某些情况下它们可以被利用来实现完整的远程代码执行。

### 如何发现和利用盲SSRF漏洞

检测盲 SSRF 漏洞最可靠方法是使用带外（OAST）技术。这涉及到尝试触发一个 HTTP 请求到一个你控制的外部系统，并监测与该系统的网络互动。

使用带外技术最简单和最有效的方法是使用 Burp Collaborator。你可以使用 Burp Collaborator 客户端来生成独特的域名，将这些域名放在有效载荷中发送给应用程序，并监控与这些域名的任何互动。如果观察到一个传入的 HTTP 请求来自应用程序，那么它就会受到 SSRF 的攻击。

> 注意
>
> 在测试 SSRF 漏洞时，通常会观察到提供的 Collaborator 域的 DNS 查询，但没有后续的 HTTP 请求。这通常是因为应用程序试图向该域发出 HTTP 请求，从而导致最初的 DNS 查询，但实际的 HTTP 请求被网络过滤所阻止。对于基础设施来说，允许出站的 DNS 流量是比较常见的，因为很多目的都需要DNS流量，但却阻止了对意外目的地的HTTP连接。

> 实验：[带带外检测盲 SSRF](https://portswigger.net/web-security/ssrf/blind/lab-out-of-band-detection)

仅仅识别出一个可以触发带外 HTTP 请求的盲 SSRF 漏洞，本身并不提供可利用的途径。因为你不能查看后端请求的响应，所以该行为不能被用于探索应用服务器可以到达的系统上的内容。然而，它仍然可以被利用来探测服务器本身或其他后端系统上的其他漏洞。你可以盲目地扫荡内部的 IP 地址空间，发送旨在探测知名漏洞的 payloads。如果这些 payloads 也采用盲带外技术，那么你可能会发现未打补丁的内部服务器上的关键漏洞。

> 实验：[带有 Shellshock 漏洞的盲SSRF](https://portswigger.net/web-security/ssrf/blind/lab-shellshock-exploitation)

利用盲 SSRF 漏洞的另一个途径是诱导应用程序连接到攻击者控制的系统，并向进行连接的 HTTP 客户端返回恶意响应。如果你能在服务器的 HTTP 实现中利用严重的客户端漏洞，你可能会在应用程序的基础设施中实现远程代码执行。

> 阅读更多
>
> [Cracking the lens: Remote client exploits](https://portswigger.net/blog/cracking-the-lens-targeting-https-hidden-attack-surface#remoteclient)

