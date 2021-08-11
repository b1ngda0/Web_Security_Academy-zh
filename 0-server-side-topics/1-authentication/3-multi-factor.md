---
description: '原文链接：https://portswigger.net/web-security/authentication/multi-factor'
---

# 多因素身份验证中的漏洞

在本节中，我们将看看多因素认证机制中可能出现的一些漏洞。我们还提供了几个互动实验室来演示你如何利用多因素认证中的这些漏洞。

许多网站完全依赖使用密码的单因素认证来认证用户。然而，有些网站要求用户使用多个认证因素来证明其身份。

对大多数网站来说，验证生物识别因素是不现实的。然而，越来越多的人看到基于**你知道的东西**和**你拥有的东西**的强制性和选择性双因素认证（2FA）。这通常要求用户同时输入一个传统的密码和一个来自他们所拥有的带外物理设备的临时验证码。

虽然攻击者有时有可能获得一个基于知识的因素，如密码，但能够同时从一个带外来源获得另一个因素的可能性要小得多。由于这个原因，双因素认证显然比单因素认证更安全。然而，就像任何安全措施一样，它的安全性只取决于它的实施。实施不力的双因素认证可以被打败，甚至完全被绕过，就像单因素认证一样。

同样值得注意的是，只有通过验证多个**不同**的因素，才能实现多因素认证的全部好处。以两种不同的方式验证同一个因素并不是真正的双因素认证。基于电子邮件的2FA就是这样一个例子。尽管用户必须提供一个密码和一个验证码，但访问验证码只依赖于他们知道其电子邮件账户的登录凭证。因此，知识认证因素只是被验证了两次。

## 双因素认证token

验证码通常由用户从某种物理设备上读取。现在，许多高安全性的网站为用户提供专用设备，如RSA令牌或键盘设备，你可能用它来访问你的网上银行或工作的笔记本电脑。除了专门用于安全之外，这些专用设备还具有直接生成验证码的优势。出于同样的原因，网站使用专用的移动应用程序也很常见，如谷歌认证器。

另一方面，一些网站将验证码以短信的形式发送到用户的手机上。虽然这在技术上仍然是验证 "你所拥有的东西 "的因素，但它很容易被滥用。首先，代码是通过短信传输的，而不是由设备本身产生的。这就产生了代码被截获的可能性。还有一个SIM卡交换的风险，即攻击者以欺诈的方式获得一个带有受害者电话号码的SIM卡。然后，攻击者会收到发给受害者的所有短信，包括包含他们的验证码的短信。

## 绕过双因素认证

有时，双因素认证的实施存在缺陷，以至于可以完全绕过它。

如果用户首先被提示输入密码，然后被提示在另一个页面上输入验证码，那么在用户输入验证码之前，他们实际上处于 "已登录 "状态。在这种情况下，值得测试的是，在完成第一个验证步骤后，你是否可以直接跳到 "只登录 "的页面。偶尔，你会发现一个网站在加载页面之前实际上并没有检查你是否完成了第二步。

> 实验：[2FA简单绕过](https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-simple-bypass)

## 有缺陷的双因素认证逻辑

有时，双因素认证中的逻辑缺陷意味着在用户完成最初的登录步骤后，网站并没有充分验证同一个用户是否在完成第二步。

例如，用户在第一步用他们的正常凭证登录，如下：

```http
POST /login-steps/first HTTP/1.1
Host: vulnerable-website.com
...
username=carlos&password=qwerty
```

然后，他们被分配一个与他们的账户有关的cookie，然后被带入登录过程的第二步：

```http
HTTP/1.1 200 OK
Set-Cookie: account=carlos

GET /login-steps/second HTTP/1.1
Cookie: account=carlos
```

在提交验证码时，请求使用这个cookie来确定用户试图访问哪个账户：

```http
POST /login-steps/second HTTP/1.1
Host: vulnerable-website.com
Cookie: account=carlos
...
verification-code=123456
```

在这种情况下，攻击者可以使用自己的凭证登录，但在提交验证码时将账户cookie的值改为任何任意的用户名。

```http
POST /login-steps/second HTTP/1.1
Host: vulnerable-website.com
Cookie: account=victim-user
...
verification-code=123456
```

如果攻击者能够暴力破解验证码，这是非常危险的，因为这将使他们能够完全根据用户的用户名登录任意用户的账户。他们甚至不需要知道用户的密码。

> 实验：[破坏2FA逻辑](https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-broken-logic)

## 暴力破解2FA验证码

与密码一样，网站需要采取措施，防止对2FA验证码进行暴力破解。这一点尤其重要，因为验证码通常是一个简单的4位或6位数字。如果没有足够的暴力保护，破解这样的代码是轻而易举的。

一些网站试图通过在用户输入一定数量的错误验证码时自动注销来防止这种情况。这在实践中是无效的，因为高级攻击者甚至可以通过为Burp Intruder[创建宏](https://portswigger.net/burp/documentation/desktop/options/sessions#macros)来自动完成这一多步骤过程。[Turbo Intruder](https://portswigger.net/bappstore/9abaa233088242e8be252cd4ff534988)扩展也可用于此目的。

> 实验：[使用暴力破解绕过2FA](https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-bypass-using-a-brute-force-attack)

