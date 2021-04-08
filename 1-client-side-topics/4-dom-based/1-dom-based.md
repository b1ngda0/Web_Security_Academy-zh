# 基于DOM的漏洞

在本节中，我们将描述DOM是什么，解释DOM数据的不安全处理如何会引入漏洞，并建议如何防止网站上基于DOM的漏洞。

## 什么是DOM?

文档对象模型（DOM）是web浏览器对页面上元素的层次表示。 网站可以使用JavaScript来操纵DOM的节点和对象及其属性。 DOM操作本身不是问题。 实际上，它是现代网站运作不可或缺的一部分。 但是，不安全地处理数据的JavaScript会引发各种攻击。 当网站包含JavaScript时，就会出现基于DOM的漏洞，该JavaScript获得攻击者可控制的值（称为源），并将其传递给危险的功能（称为接收器）。

## 污染源漏洞

许多基于DOM的漏洞可以追溯到客户端代码操纵攻击者可控制数据的方式问题。

### 什么是污染流？

要利用或减轻这些漏洞，您必须首先熟悉源和接收器之间的污染流的基本知识。

#### 源

源是一个JavaScript属性，它接受可能受到攻击者控制的数据。 来源的一个示例是location.search属性，因为它从查询字符串中读取输入，这对于攻击者而言比较容易控制。 最终，攻击者可以控制的任何属性都是潜在的来源。 这包括引用URL（由document.referrer字符串公开），用户的cookie（由document.cookie字符串公开）和web消息。

#### 接收器

接收器是潜在危险的JavaScript函数或DOM对象，如果将攻击者控制的数据传递给它，则可能导致不良后果。 例如，eval（）函数是一个接收器，因为它处理作为JavaScript传递给它的参数。 HTML接收器的一个示例是document.body.innerHTML，因为它可能允许攻击者注入恶意HTML并执行任意JavaScript。

从根本上讲，当网站将数据从源传递到接收器时，基于DOM的漏洞就会出现，该接收器随后会在客户端会话的上下文中以不安全的方式处理数据。

最常见的来源是URL，通常可通过location对象访问该URL。 攻击者可以构建一个链接，以将受害者发送到易受攻击的页面，并在查询字符串和URL的片段部分中添加有效负载。 考虑以下代码：

```text
goto = location.hash.slice(1)if(goto.startsWith('https:')) { location = goto;}
```

这很容易受到基于DOM的开放式重定向的影响，因为location.hash源是以不安全的方式处理的。 如果URL包含以https：开头的哈希片段，则此代码将提取location.hash属性的值并将其设置为窗口的location属性。 攻击者可以通过构造以下URL来利用此漏洞：

```text
https://www.innocent-website.com/example#https://www.evil-user.net
```

当受害者访问此URL时，JavaScript会将location属性的值设置为[https://www.evil-user.net，这将自动将受害者重定向到恶意站点。](https://www.evil-user.net，这将自动将受害者重定向到恶意站点。) 例如，可以很容易地利用此行为来构造网络钓鱼攻击。

### 共同来源

以下是可用于开发各种污染流漏洞的典型来源：

```text
document.URLdocument.documentURIdocument.URLUnencodeddocument.baseURI位置document.cookiedocument.referrerwindow.namehistory.pushStatehistory.replaceStatelocalStoragesessionStorageIndexedDB (mozIndexedDB, webkitIndexedDB, msIndexedDB)数据库
```

### 哪些接收器可能导致基于DOM的漏洞？

以下列表提供了常见的基于DOM的漏洞的快速概述，以及可能导致每个漏洞的接收器示例。 有关相关接收器的更全面列表，请通过单击以下链接来参考特定于漏洞的页面。

| 基于DOM的漏洞 | 接收器示例 |
| :--- | :--- |
| [DOM XSS](javascript:;) LABS | `document.write()` |
| [开放重定向](javascript:;) LABS | `window.location` |
| [Cookie操作](javascript:;) LABS | `document.cookie` |
| [JavaScript注入](javascript:;) | `eval()` |
| [文档范围操作](javascript:;) | `document.domain` |
| [WebSocket-URL中毒](javascript:;) | `WebSocket()` |
| [链接操纵](javascript:;) | `someElement.src` |
| [网络消息操纵](javascript:;) | `postMessage()` |
| [Ajax请求标头操作](javascript:;) | `setRequestHeader()` |
| [本地文件路径操作](javascript:;) | `FileReader.readAsText()` |
| [客户端SQL注入](javascript:;) | `ExecuteSql()` |
| [HTML5存储操作](javascript:;) | `sessionStorage.setItem()` |
| [客户端XPath注入](javascript:;) | `document.evaluate()` |
| [客户端JSON注入](javascript:;) | `JSON.parse()` |
| [DOM数据操作](javascript:;) | `someElement.setAttribute()` |
| [拒绝服务](javascript:;) | `RegExp()` |

### 如何防止基于DOM的污染流漏洞

您不能采取任何行动来完全消除基于DOM的攻击的威胁。 但是，一般而言，避免基于DOM的漏洞的最有效方法是避免允许来自任何不受信任源的数据动态更改传输到任何接收器的值。

如果应用程序所需的功能意味着这种行为是不可避免的，则必须在客户端代码内实施防御。 在许多情况下，可以在白名单的基础上验证相关数据，仅允许已知安全的内容。 在其他情况下，有必要对数据进行清理或编码。 这可能是一项复杂的任务，并且取决于要插入数据的上下文，它可能会按照适当的顺序包含JavaScript转义，HTML编码和URL编码的组合。

有关可以采取的防止特定漏洞的措施，请参阅上表链接的相应漏洞页面。

## DOM破坏

DOM破坏是一种高级技术，您可以将HTML注入页面中以操纵DOM并最终更改网站上JavaScript的行为。 DOM破坏的最常见形式是使用锚元素覆盖全局变量，然后该全局变量将被应用程序以不安全的方式使用，例如生成动态脚本URL。

