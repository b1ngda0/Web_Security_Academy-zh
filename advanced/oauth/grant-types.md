# OAuth授权类型

在本节中，我们将介绍两种最常见的OAuth授权类型的基础知识。如果你完全不熟悉 OAuth，我们建议你在尝试完成[OAuth认证](https://portswigger.net/web-security/oauth)实验前先阅读本节内容。

## 什么是OAuth授权类型？

OAuth授权类型决定了OAuth流程中所涉及的确切步骤顺序。授权类型还会影响客户端应用在每个阶段与OAuth服务通信的方式，包括访问令牌本身的发送方式。因此，授权类型通常被称为“OAuth流”（OAuth flows）。 

在客户端应用初始化相应的流之前，OAuth服务必须被配置为支持特定的授权类型。客户端应用在向OAuth服务发送的初始授权请求中指定它要使用的授权类型。

有几种不同的授权类型，每一种都具有不同的复杂性和安全性考虑。我们将重点关注“授权码”（authorization code）和“隐式”（implicit）授权类型，因为它们是目前最常见的类型。

## OAuth作用域

对于任何OAuth授权类型，客户端应用都必须指定它想要访问的数据，以及它想要执行的操作类型。它通过一个参数来实现它的目的，这个参数是发送给OAuth服务的授权请求中的`scope`参数。

对于基本的OAuth，客户端应用可以请求访问的作用域（scope）对于每个OAuth服务都是唯一的。由于作用域的名称只是一个任意文本字符串，因此其格式在不同的提供者之间会有很大差异。有些甚至使用一个完整的URI作为作用域的名称，类似于REST API的端点。例如，当请求对用户联系人列表的读取访问权限时，根据所使用的OAuth服务，作用域名称可能采用以下任何一种形式：

```
scope=contacts
scope=contacts.read
scope=contact-list-r
scope=https://oauth-authorization-server.com/auth/scopes/user/contacts.readonly
```

但是，当OAuth被用于认证时，通常会使用标准化的OpenID Connect作用域。例如，`openid profile`作用域将授权客户端应用对一组预定义用户基本信息（例如他们的电子邮件地址、用户名等）的读取权限。稍后我们将详细讨论[OpenID Connect](./openid.md)。

## 授权码授权类型

授权码授权类型一开始看起来非常复杂，但一旦你熟悉了一些基础知识，它实际上比你想象的要简单。



简而言之，客户端应用和OAuth服务首先使用重定向来交换一系列启动流程的基于浏览器的 HTTP 请求。询问用户是否同意所请求的访问。如果他们接受，则授权客户端应用程序“授权码”。然后，客户端应用程序与OAuth服务交换此代码以接收“访问令牌”，他们可以使用该令牌进行 API 调用以获取相关的用户数据。

从代码/令牌交换开始发生的所有通信都通过安全的、预配置的反向通道发送到服务器，因此对最终用户是不可见的。此安全通道在客户端应用程序首次向OAuth服务注册时建立。此时，`client_secret`还会生成 a，客户端应用程序在发送这些服务器到服务器的请求时必须使用它来验证自己。

由于最敏感的数据（访问令牌和用户数据）不是通过浏览器发送的，因此这种授权类型可以说是最安全的。如果可能，服务器端应用程序理想情况下应始终使用此授权类型。

![OAuth授权代码授权类型的流程](https://portswigger.net/web-security/images/oauth-authorization-code-flow.jpg)

#### 1. 授权请求

客户端应用程序向OAuth服务的端点发送请求，请求`/authorization`获得访问特定用户数据的权限。请注意，端点映射可能因提供商而异——我们的实验室`/auth`为此目的使用端点。但是，你应该始终能够根据请求中使用的参数来识别端点。

```
GET /authorization?client_id=12345&redirect_uri=https://client-app.com/callback&response_type=code&scope=openid%20profile&state=ae13d489bd00e3c24 HTTP/1.1 Host: oauth-authorization-server.com
```

此请求包含以下值得注意的参数，通常在查询字符串中提供：

- ```
  client_id
  ```

  包含客户端应用程序的唯一标识符的强制参数。此值在客户端应用程序向OAuth服务注册时生成。

- ```
  redirect_uri
  ```

  将授权代码发送到客户端应用程序时应将用户浏览器重定向到的 URI。这也称为“回调 URI”或“回调端点”。许多OAuth攻击都是基于利用此参数验证中的缺陷。

- ```
  response_type
  ```

  确定客户端应用程序期望的响应类型，以及它想要启动的流。对于授权码授权类型，该值应为`code`。

- ```
  scope
  ```

  用于指定客户端应用程序想要访问的用户数据的哪个子集。请注意，这些可能是OAuth提供者设置的自定义范围或 OpenID Connect 规范定义的标准化范围。稍后我们将更详细地介绍[OpenID Connect](https://portswigger.net/web-security/oauth/openid)。

- ```
  state
  ```

  存储一个唯一的、不可猜测的值，该值与客户端应用程序上的当前会话相关联。OAuth服务应在响应中返回此确切值以及授权代码。此参数用作客户端应用程序的[CSRF 令牌](https://portswigger.net/web-security/csrf/tokens)形式，确保对其`/callback`端点的请求来自启动OAuth流的同一个人。

#### 2. 用户登录和同意

当授权服务器接收到初始请求时，它将用户重定向到登录页面，在那里他们将被提示登录到他们在OAuth提供者处的帐户。例如，这通常是他们的社交媒体帐户。

然后，他们将看到客户端应用程序想要访问的数据列表。这基于授权请求中定义的范围。用户可以选择是否同意此访问。

需要注意的是，一旦用户批准了客户端应用程序的给定范围，只要用户仍然与OAuth服务保持有效会话，此步骤就会自动完成。换句话说，用户第一次选择“使用社交媒体登录”时，他们需要手动登录并表示同意，但如果他们稍后重新访问客户端应用程序，他们通常可以重新登录单击。

#### 3.授权码授权

如果用户同意所请求的访问，他们的浏览器将被重定向到授权请求参数中`/callback`指定的端点。`redirect_uri`生成的`GET`请求将包含授权代码作为查询参数。根据配置，它也可能发送`state`与授权请求中相同的参数。

```
GET /callback?code=a1b2c3d4e5f6g7h8&state=ae13d489bd00e3c24 HTTP/1.1 Host: client-app.com
```

#### 4.访问令牌请求

客户端应用程序收到授权代码后，需要将其交换为访问令牌。为此，它向`POST`OAuth服务的`/token`端点发送一个服务器到服务器的请求。从这一点开始的所有通信都发生在一个安全的反向通道中，因此通常不能被攻击者观察或控制。

```
POST /token HTTP/1.1 Host: oauth-authorization-server.com … client_id=12345&client_secret=SECRET&redirect_uri=https://client-app.com/callback&grant_type=authorization_code&code=a1b2c3d4e5f6g7h8
```

除了`client_id`和 授权`code`，你还会注意到以下新参数：

- ```
  client_secret
  ```

  客户端应用程序必须通过包含向OAuth服务注册时分配的密钥来验证自身。

- ```
  grant_type
  ```

  用于确保新端点知道客户端应用程序想要使用的授权类型。在这种情况下，这应该设置为`authorization_code`。

#### 5.访问令牌授权

OAuth服务将验证访问令牌请求。如果一切都如预期的那样，服务器通过授权客户端应用程序具有请求范围的访问令牌来响应。

```
{    "access_token": "z0y9x8w7v6u5",    "token_type": "Bearer",    "expires_in": 3600,    "scope": "openid profile",    … }
```

#### 6.API调用

现在客户端应用程序有了访问代码，它终于可以从资源服务器获取用户的数据了。为此，它对OAuth服务的`/userinfo`端点进行 API 调用。访问令牌在`Authorization: Bearer`标头中提交，以证明客户端应用程序有权访问此数据。

```
GET /userinfo HTTP/1.1 Host: oauth-resource-server.com Authorization: Bearer z0y9x8w7v6u5
```

#### 7. 资源补助

资源服务器应验证令牌是否有效以及它是否属于当前客户端应用程序。如果是这样，它将通过发送请求的资源来响应，即基于访问令牌范围的用户数据。

```
{    "username":"carlos",    "email":"carlos@carlos-montoya.net",    … }
```

客户端应用程序最终可以将这些数据用于其预期目的。在OAuth身份验证的情况下，它通常用作一个 ID 来授权用户一个经过身份验证的会话，从而有效地登录。

## 隐式授权类型

隐式授权类型要简单得多。客户端应用程序不是首先获取授权代码，然后将其交换为访问令牌，而是在用户同意后立即接收访问令牌。

你可能想知道为什么客户端应用程序并不总是使用隐式授权类型。答案相对简单——安全性要低得多。使用隐式授权类型时，所有通信都通过浏览器重定向进行 - 没有像授权代码流中那样的安全反向通道。这意味着敏感访问令牌和用户数据更容易受到潜在攻击。

隐式授权类型更适合单页应用程序和原生桌面应用程序，这些应用程序无法`client_secret`在后端轻松存储，因此无法从使用授权码授权类型中获得太多好处。

![OAuth隐式授权类型的流程](https://portswigger.net/web-security/images/oauth-implicit-flow.jpg)

#### 1. 授权请求

隐式流程的开始方式与授权代码流程大致相同。唯一的主要区别是`response_type`参数必须设置为`token`。

```
GET /authorization?client_id=12345&redirect_uri=https://client-app.com/callback&response_type=token&scope=openid%20profile&state=ae13d489bd00e3c24 HTTP/1.1 Host: oauth-authorization-server.com
```

#### 2. 用户登录和同意

用户登录并决定是否同意请求的权限。此过程与授权码流程完全相同。

#### 3.访问令牌授权

如果用户同意所请求的访问，这就是事情开始不同的地方。OAuth服务会将用户的浏览器重定向到`redirect_uri`授权请求中指定的浏览器。但是，它不会发送包含授权代码的查询参数，而是将访问令牌和其他特定于令牌的数据作为 URL 片段发送。

```
GET /callback#access_token=z0y9x8w7v6u5&token_type=Bearer&expires_in=5000&scope=openid%20profile&state=ae13d489bd00e3c24 HTTP/1.1 Host: client-app.com
```

由于访问令牌是在 URL 片段中发送的，因此它永远不会直接发送到客户端应用程序。相反，客户端应用程序必须使用合适的脚本来提取片段并存储它。

#### 4. API调用

一旦客户端应用程序成功地从 URL 片段中提取了访问令牌，它就可以使用它来对OAuth服务的`/userinfo`端点进行 API 调用。与授权代码流不同，这也通过浏览器发生。

```
GET /userinfo HTTP/1.1 Host: oauth-resource-server.com Authorization: Bearer z0y9x8w7v6u5
```

#### 5. 资源补助

资源服务器应验证令牌是否有效以及它是否属于当前客户端应用程序。如果是这样，它将通过发送请求的资源来响应，即基于与访问令牌关联的范围的用户数据。

```
{    "username":"carlos",    "email":"carlos@carlos-montoya.net" }
```

客户端应用程序最终可以将这些数据用于其预期目的。在OAuth身份验证的情况下，它通常用作一个 ID 来授权用户一个经过身份验证的会话，从而有效地登录。

#### 阅读更多

现在你对不同流程的工作方式有了更多了解，你应该能够按照我们的学习材料了解如何利用基于OAuth的身份验证机制中的漏洞。

[OAuth身份验证漏洞](https://portswigger.net/web-security/oauth)
