# 跨站请求伪造（CSRF）

在本节中，我们将解释什么是跨站点请求伪造，描述一些常见CSRF漏洞的示例，并解释如何防止CSRF攻击。

## 什么是CSRF?

跨站点请求伪造（也称为CSRF）是一个web安全漏洞，攻击者可以利用该漏洞诱使用户执行他们不打算执行的操作。 它允许攻击者部分规避同一原始策略，该策略旨在防止不同的网站相互干扰。

![](../../.gitbook/assets/image%20%284%29.png)

## CSRF攻击有什么影响？

在成功的CSRF攻击中，攻击者会导致受害者用户无意中执行操作。 例如，这可能是更改其帐户上的电子邮件地址，更改其密码或进行资金转帐。 根据操作的性质，攻击者可能会完全控制用户的帐户。 如果受感染的用户在应用程序中具有特权角色，则攻击者可能能够完全控制所有应用程序的数据和功能。

## CSRF如何工作？

为了使CSRF攻击成为可能，必须具备三个关键条件：

* **相关动作。**攻击者有理由诱使应用程序中发生某种动作。 这可能是特权操作（例如，修改其他用户的权限）或对用户特定数据的任何操作（例如，更改用户自己的密码）。
* **基于Cookie的会话处理。** 执行该操作涉及发出一个或多个HTTP请求，并且该应用程序仅依靠会话cookie来识别发出请求的用户。 没有其他机制可以跟踪会话或验证用户请求。
* **没有不可预测的请求参数。** 执行该操作的请求不包含攻击者无法确定或猜测其值的任何参数。 例如，当使用户更改密码时，如果攻击者需要知道现有密码的值，则该功能不会受到攻击。

例如，假设一个应用程序包含一个功能，该功能使用户可以更改其帐户上的电子邮件地址。 用户执行此操作时，将发出如下HTTP请求：

```http
POST /email/change HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 30
Cookie: session=yvthwsztyeQkAPzeQ5gHgTvlyxHfsAfE

email=wiener@normal-user.com
```

这符合CSRF所需的条件：

* 攻击者会对更改用户帐户上的电子邮件地址的操作感兴趣。 执行此操作后，攻击者通常将能够触发密码重置并完全控制用户的帐户。
* 该应用程序使用会话cookie来标识哪个用户发出了请求。 没有其他令牌或机制来跟踪用户会话。
* 攻击者可以轻松确定执行操作所需的请求参数的值。

在满足这些条件的情况下，攻击者可以构建一个包含以下HTML的网页：

```markup
<html>
  <body>
    <form action="https://vulnerable-website.com/email/change" method="POST">
      <input type="hidden" name="email" value="pwned@evil-user.net" />
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```

如果受害用户访问攻击者的网页，则会发生以下情况：

* 攻击者的页面将触发对易受攻击的网站的HTTP请求。
* 如果用户登录到易受攻击的网站，则其浏览器将自动在请求中包括其会话cookie（假设未使用SameSite cookie）。
* 易受攻击的网站将以正常方式处理请求，将其视为受害用户提出，并更改其电子邮件地址。

> Note
>
> 虽然CSRF通常是针对基于Cookie的会话处理来描述的，但它也会在其他情况下出现，在这些情况下，应用程序会自动将一些用户凭证添加到请求中，例如HTTP Basic认证和基于证书的认证。

## 如何构造CSRF攻击

手动创建CSRF攻击所需的HTML可能很麻烦，特别是在所需的请求包含大量参数或请求中存在其他异常的情况下。 构造CSRF漏洞最简单的方法是使用Burp Suite Professional内置的CSRF PoC生成器：

* 在Burp Suite Professional中的任何位置选择要测试或利用的请求。
* 从右键单击上下文菜单中，选择“参与工具” /“生成CSRF PoC”。
* Burp Suite将生成一些HTML，这些HTML会触发选定的请求（减去cookie，该cookie将由受害者的浏览器自动添加）。
* 您可以在CSRF PoC生成器中调整各种选项，以微调攻击的各个方面。 您可能需要在某些不常见的情况下执行此操作，以处理请求的古怪功能。
* 将生成的HTML复制到网页中，在登录到易受攻击的网站的浏览器中查看它，并测试是否成功发出了预期的请求并执行了所需的操作。

**实验室**CSRF漏洞，没有防御措施

## 如何进行CSRF攻击

跨站点请求伪造攻击的传递机制与反射的XSS基本上相同。 通常，攻击者会将恶意HTML放到他们控制的网站上，然后诱使受害者访问该网站。 这可以通过电子邮件或社交媒体消息向用户提供指向网站的链接来完成。 或者，如果将攻击置于流行的网站中（例如，在用户评论中），他们可能只是在等待用户访问该网站。

请注意，一些简单的CSRF漏洞利用GET方法，并且可以通过易受攻击的网站上的单个URL完全自包含。 在这种情况下，攻击者可能不需要使用外部站点，并且可以在易受攻击的域上直接向受害者提供恶意URL。 在前面的示例中，如果可以使用GET方法执行更改电子邮件地址的请求，则自包含式攻击将如下所示：

```markup
<img src="https://vulnerable-website.com/email/change?email=pwned@evil-user.net">
```

## 防止CSRF攻击

防御CSRF攻击的最可靠方法是在相关请求中包含CSRF令牌。 令牌应为：

* 与一般的会话令牌一样，在高熵下不可预测。
* 绑定到用户的会话。
* 在执行相关操作之前，在每种情况下均经过严格验证。

SameSite cookie是对CSRF部分有效的另一种防御措施，可以与CSRF令牌结合使用。

## 常见的CSRF漏洞

最有趣的CSRF漏洞是由CSRF令牌验证中的错误引起的。

在前面的示例中，假设应用程序现在在更改用户密码的请求中包含CSRF令牌：

`POST /email/change HTTP/1.1Host: vulnerable-website.comContent-Type: application/x-www-form-urlencodedContent-Length: 68Cookie: session=2yQIDcpia41WrATfjPqvm9tOkDvkMvLmcsrf=WfF1szMUHhiokx9AHFply5L2xAOfjRkE&email=wiener@normal-user.com`

这应该防止CSRF攻击，因为它违反了CSRF漏洞的必要条件：应用程序不再仅依赖cookie进行会话处理，并且请求包含一个参数，攻击者无法确定其值。 但是，可以通过多种方式来打破防御，这意味着该应用程序仍然容易受到CSRF的攻击。

### CSRF令牌的验证取决于请求方法

当请求使用POST方法时，某些应用程序正确地验证了令牌，但是当使用GET方法时，跳过了验证。

在这种情况下，攻击者可以切换到GET方法来绕过验证并发送CSRF攻击：

`GET /email/change?email=pwned@evil-user.net HTTP/1.1Host: vulnerable-website.comCookie: session=2yQIDcpia41WrATfjPqvm9tOkDvkMvLm`

**实验室**CSRF，令牌验证取决于请求方法

### CSRF令牌的验证取决于令牌是否存在

如果令牌存在，某些应用程序会正确验证令牌，但是如果省略令牌，则跳过验证。

在这种情况下，攻击者可以删除包含令牌的整个参数（而不仅仅是令牌的值），以绕过验证并进行CSRF攻击：

`POST /email/change HTTP/1.1Host: vulnerable-website.comContent-Type: application/x-www-form-urlencodedContent-Length: 25Cookie: session=2yQIDcpia41WrATfjPqvm9tOkDvkMvLmemail=pwned@evil-user.net`

**实验室**CSRF，其中令牌验证取决于存在的令牌

### CSRF令牌未绑定到用户会话

某些应用程序无法验证令牌与发出请求的用户属于同一会话。 而是，应用程序维护已发出的全局令牌池，并接受该池中显示的所有令牌。

在这种情况下，攻击者可以使用自己的帐户登录到应用程序，获取有效令牌，然后在其CSRF攻击中将该令牌提供给受害用户。

**实验室**CSRF，令牌未绑定到用户会话

### CSRF令牌绑定到非会话cookie

在上述漏洞的一种变体中，某些应用程序确实将CSRF令牌绑定到cookie，但没有绑定到用于跟踪会话的cookie。 当应用程序使用两种不同的框架（未集成在一起）时，很容易发生这种情况：一种用于会话处理，另一种用于CSRF保护。

`POST /email/change HTTP/1.1Host: vulnerable-website.comContent-Type: application/x-www-form-urlencodedContent-Length: 68Cookie: session=pSJYSScWKpmC60LpFOAHKixuFuM4uXWF; csrfKey=rZHCnSzEp8dbI6atzagGoSYyqJqTz5dvcsrf=RhV7yQDO0xcq9gLEah2WVbmuFqyOq7tY&email=wiener@normal-user.com`

这种情况很难利用，但仍然很脆弱。 如果该网站包含允许攻击者在受害者的浏览器中设置cookie的任何行为，则可能构成攻击。 攻击者可以使用自己的帐户登录应用程序，获取有效的令牌和关联的cookie，利用cookie的设置行为将其cookie放入受害者的浏览器中，并在CSRF攻击中将其令牌提供给受害者。

**实验室**CSRF，令牌与非会话Cookie绑定在一起

### CSRF令牌仅在cookie中重复

在前述漏洞的另一种变体中，某些应用程序不维护任何已发布令牌的服务器端记录，而是复制cookie和request参数中的每个令牌。 当后续请求得到验证时，应用程序仅验证请求参数中提交的令牌是否与cookie中提交的值匹配。 有时将其称为针对CSRF的“双重提交”防御，之所以被提倡，是因为它易于实现并且避免了任何服务器端状态的需要：

`POST /email/change HTTP/1.1Host: vulnerable-website.comContent-Type: application/x-www-form-urlencodedContent-Length: 68Cookie: session=1DQGdzYbOJQzLP7460tfyiv3do7MjyPw; csrf=R8ov2YBfTYmzFyjit8o2hKBuoIjXXVpacsrf=R8ov2YBfTYmzFyjit8o2hKBuoIjXXVpa&email=wiener@normal-user.com`

在这种情况下，如果网站包含任何cookie设置功能，则攻击者可以再次执行CSRF攻击。 在这里，攻击者无需获取自己的有效令牌。 他们只是发明了一个令牌（如果正在检查，则可能采用所需的格式），利用cookie设置行为将其cookie置于受害者的浏览器中，并在CSRF攻击中将令牌提供给受害者。

**实验室**CSRF，其中令牌在cookie中重复

## 针对CSRF的基于引用者的防御

除了采用CSRF令牌的防御措施外，某些应用程序还利用HTTP Referer标头尝试防御CSRF攻击，通常是通过验证请求是否来自应用程序自己的域来进行。 这种方法通常效果较差，并且经常会绕过。

#### Referer标头

HTTP Referer标头（在HTTP规范中无意中拼写错误）是一个可选的请求标头，其中包含链接到所请求资源的网页的URL。 通常，当用户触发HTTP请求时，浏览器会自动添加它，包括单击链接或提交表单。 存在各种方法，允许链接页面保留或修改Referer标头的值。 通常出于隐私原因这样做。

### Referer的验证取决于标头的存在

某些应用程序在请求中存在Referer标头时会对其进行验证，但是如果省略标头，则会跳过验证。

在这种情况下，攻击者可以以导致受害者用户的浏览器在结果请求中删除Referer标头的方式设计CSRF利用。 有多种方法可以实现此目的，但最简单的方法是在承载CSRF攻击的HTML页面中使用META标签：

**实验室**CSRF，其中Referer来源验证取决于标头的存在

### 可以避免Referer的验证

一些应用程序以一种可以绕过简单的方式验证Referer标头。 例如，如果应用程序仅验证引荐来源网址包含其自己的域名，则攻击者可以在URL中的其他位置放置所需的值：

`http://attacker-website.com/csrf-attack?vulnerable-website.com`

如果应用程序验证了Referer中的域以期望值开头，则攻击者可以将其放置为自己域的子域：

`http://vulnerable-website.com.attacker-website.com/csrf-attack`

**实验室**Referer验证失效的CSRF

