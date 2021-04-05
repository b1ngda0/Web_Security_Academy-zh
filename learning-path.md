# 学习路线&目录

> 原文链接：https://portswigger.net/web-security/learning-path

如果您是网络安全的新手，可能很难知道从哪里开始。这就是为什么我们创建了这个建议的学习路线，为您指明正确的方向。我们建议您边学边完成实验，如果遇到困难，不要害怕继续学习下一个主题。一旦您的技能得到进一步发展，可以回到更具挑战性的实验。


## 服务器端主题

对于完全的初学者，我们建议从我们的服务器端主题开始。这些漏洞通常更容易学习，因为您只需要了解服务器上发生的事情。我们的材料和实验室将帮助您开发一些核心知识和技能，您将一次又一次地依赖这些知识和技能。

- ### [SQL注入](0-server-side-topics/0-sql-injection/README.md)
- ### [身份验证](0-server-side-topics/1-authentication/README.md)
- ### [目录遍历](0-server-side-topics/2-file-path-traversal.md)
- ### [操作系统命令注入](0-server-side-topics/3-os-command-injection.md)
- ### [业务逻辑漏洞](0-server-side-topics/4-logic-flaws/README.md)
- ### [信息泄露](0-server-side-topics/5-information-disclosure/README.md)
- ### [访问控制](0-server-side-topics/6-access-control/README.md)
- ### [服务器端请求伪造（SSRF）](0-server-side-topics/7-ssrf/README.md)
- ### [XXE注入](0-server-side-topics/8-xxe/README.md)


## 客户端主题

客户端漏洞引入了一个额外的复杂层次，这可能会使它们略微更具挑战性。这些材料和实验室将帮助您建立在您已经学会的服务器端技能基础上，并教您如何识别和利用一些可怕的客户端向量。

- ### [跨站脚本（XSS）](1-client-side-topics/0-cross-site-scripting/README.md)
- ### [跨站请求伪造（CSRF）](1-client-side-topics/1-csrf/README.md)
- ### [跨域资源共享（CORS）](1-client-side-topics/2-cors/README.md)
- ### [点击劫持（UI纠正）](1-client-side-topics/3-clickjacking.md)
- ### [基于DOM的漏洞](1-client-side-topics/4-dom-based/README.md)
- ### [WebSocket](1-client-side-topics/5-websocket/README.md)


## 进阶主题

这些主题并不一定更难掌握，但它们通常需要更深入的理解和更广泛的知识。我们建议在处理这些实验之前先掌握基础知识，其中一些是基于我们世界级研究团队发现的先锋技术。

- ### [不安全的反序列化](2-advanced-topics/0-deserialization/README.md)
- ### [服务器端模板注入](2-advanced-topics/1-server-side-template-injection/README.md)
- ### [Web缓存中毒](2-advanced-topics/2-web-cache-poisoning/README.md)
- ### [HTTP主机头攻击](2-advanced-topics/3-host-header/README.md)
- ### [HTTP请求走私](2-advanced-topics/4-request-smuggling/README.md)
- ### [OAuth认证](2-advanced-topics/5-oauth/README.md)
