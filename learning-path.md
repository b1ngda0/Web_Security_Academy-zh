# 学习路线

如果你是Web安全的新手，可能很难知道从哪里开始入手。这就是为什么我们创建了这个建议的学习路径，目的是为你指明正确的方向。我们建议你边学边完成实验，如果你遇到困难，不要害怕转到下一个主题。一旦你的技能得到进一步的发展，就可以到更有挑战性的实验中。

## 服务器端主题

对于完全的初学者，我们建议从服务器端主题开始。这些漏洞通常更容易学习，因为你只需要了解服务器上发生的事情即可。我们的材料和实验将帮助你发展一些核心知识和技能，你将一次又一次地依赖这些知识和技能。

1. [**SQL注入**](0-server-side-topics/0-sql-injection/)
2. [**认证**](0-server-side-topics/1-authentication/)
3. [**目录遍历**](0-server-side-topics/2-file-path-traversal/)
4. [**命令注入**](0-server-side-topics/3-os-command-injection/)
5. [**业务逻辑漏洞**](0-server-side-topics/4-logic-flaws/)
6. [**信息泄露**](0-server-side-topics/5-information-disclosure/)
7. [**访问控制**](0-server-side-topics/6-access-control/)
8. [**文件上传漏洞**](0-server-side-topics/7-file-upload/)
9. [**服务器端请求伪造（SSRF）**](0-server-side-topics/8-ssrf/)
10. [**XXE注入**](0-server-side-topics/9-xxe/)

## 客户端主题

客户端漏洞引入了额外的复杂性，这可能会使它们略微更具挑战性。这些材料和实验将帮助你在已经学到的服务器端技能的基础上，教你如何识别和利用一些棘手的客户端载体。

1. [**跨站脚本（XSS）**](1-client-side-topics/0-cross-site-scripting/)
2. [**跨站请求伪造（CSRF）**](1-client-side-topics/1-csrf/)
3. [**跨域资源共享（CORS）**](1-client-side-topics/2-cors/)
4. [**点击劫持**](1-client-side-topics/3-clickjacking/)
5. [**基于DOM的漏洞**](1-client-side-topics/4-dom-based/)
6. [**WebSockets**](1-client-side-topics/5-websocket/)

## 进阶主题

这些主题并不一定较难掌握，但通常需要更深刻的理解和更广泛的知识范围。我们建议在处理这些实验之前先掌握基础知识，其中一些是基于我们世界级研究团队发现的开创性技术。

1. [**不安全的反序列化**](2-advanced-topics/0-deserialization/)
2. [**服务器端模板注入**](2-advanced-topics/1-server-side-template-injection/)
3. [**Web缓存中毒**](2-advanced-topics/2-web-cache-poisoning/)
4. [**HTTP主机头攻击**](2-advanced-topics/3-host-header/)
5. [**HTTP请求走私**](2-advanced-topics/4-request-smuggling/)
6. [**OAuth认证**](2-advanced-topics/5-oauth/)
7. [**JWT认证**](2-advanced-topics/6-jwt/)

## 番外篇 - Web应用程序安全测试

1. [**Web应用程序安全测试**](3-extras/0-application-security-testing/README.md)
2. [**动态应用程序安全测试（DAST）**](3-extras/0-application-security-testing/1-dast.md)
3. [**带外通道应用程序安全测试（OAST）**](3-extras/0-application-security-testing/2-oast.md)