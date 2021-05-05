# 测试WebSockets安全漏洞

在本节中，我们将说明如何处理WebSocket消息和连接，描述WebSocket可能出现的各种安全漏洞，并提供一些利用WebSocket漏洞的示例。

## WebSockets

WebSockets广泛用于现代web应用程序中。 它们通过HTTP发起，并通过双向双向通信提供长期连接。

WebSocket用于各种目的，包括执行用户操作和传输敏感信息。 几乎与常规HTTP一起出现的任何web安全漏洞也可能与WebSockets通信有关。

![](../../.gitbook/assets/image%20%2811%29.png)

## 操纵WebSocket流量

查找WebSockets安全漏洞通常涉及以应用程序无法预期的方式操纵它们。 您可以使用Burp Suite执行此操作。

您可以使用Burp Suite来：

* 拦截和修改WebSocket消息。
* 重播并生成新的WebSocket消息。
* 操纵WebSocket连接。

### 拦截和修改WebSocket消息

您可以使用Burp Proxy来拦截和修改WebSocket消息，如下所示：

* 配置浏览器以将Burp Suite用作其代理服务器。
* 浏览到使用WebSockets的应用程序功能。 您可以通过使用应用程序并查找Burp Proxy中“ WebSockets历史记录”选项卡中显示的条目来确定正在使用WebSockets。
* 在Burp Proxy的“拦截”选项卡中，确保已启用拦截。
* 从浏览器或服务器发送WebSocket消息时，它将显示在“拦截”选项卡中，供您查看或修改。 按转发按钮转发消息。

### 重放并生成新的WebSocket消息

除了动态拦截和修改WebSocket消息外，您还可以重放单个消息并生成新消息。 您可以使用Burp Repeater执行此操作：

* 在Burp Proxy中，在WebSockets历史记录或“拦截”选项卡中选择一条消息，然后从上下文菜单中选择“发送到转发器”。
* 现在，在Burp Repeater中，您可以编辑选定的消息，然后反复发送。
* 您可以输入新消息并将其以任何方向发送到客户端或服务器。
* 在Burp Repeater的“历史记录”面板中，您可以查看通过WebSocket连接传输的消息的历史记录。 这包括您在Burp Repeater中生成的消息，以及浏览器或服务器通过同一连接生成的任何消息。
* 如果要编辑和重新发送历史记录面板中的任何消息，可以通过选择消息并从上下文菜单中选择“编辑并重新发送”来进行。

### 操纵WebSocket连接

除了处理WebSocket消息外，有时还需要操纵建立连接的WebSocket交握。

在多种情况下，可能需要操纵WebSocket交握：

* 它可以使您看到更多的攻击面。
* 某些攻击可能会导致您的连接断开，因此您需要建立一个新的连接。
* 原始交握请求中的单点登录或其他数据可能已过时，需要更新。

您可以使用Burp Repeater操纵WebSocket交握：

* 如上所述，将WebSocket消息发送到Burp Repeater。
* 在Burp Repeater中，单击WebSocket URL旁边的铅笔图标。 这将打开一个向导，该向导可让您连接到现有的已连接WebSocket，克隆已连接的WebSocket或重新连接至断开连接的WebSocket。
* 如果选择克隆连接的WebSocket或重新连接到断开连接的WebSocket，则向导将显示WebSocket交握请求的完整详细信息，您可以在执行交握之前根据需要进行编辑。
* 当您单击“连接”时，Burp将尝试执行配置的交握并显示结果。 如果成功建立了新的WebSocket连接，则可以使用它在Burp Repeater中发送新消息。

## WebSockets安全漏洞

原则上，实际上与WebSockets有关的任何web安全漏洞都可能出现：

* 传输到服务器的用户提供的输入可能以不安全的方式处理，从而导致漏洞，例如SQL注入或XML外部实体注入。
* 通过WebSockets达到的某些盲目的漏洞可能仅使用带外（OAST）技术才能检测到。
* 如果攻击者控制的数据通过WebSockets传输到其他应用程序用户，则可能导致XSS或其他客户端漏洞。

### 处理WebSocket消息以利用漏洞

可以通过篡改WebSocket消息的内容来发现和利用影响WebSocket的大多数基于输入的漏洞。

例如，假设一个聊天应用程序使用WebSocket在浏览器和服务器之间发送聊天消息。 当用户键入聊天消息时，将如下所示的WebSocket消息发送到服务器：

```text
{"message":"Hello Carlos"}
```

消息的内容（再次通过WebSockets）传输到另一个聊天用户，并在用户的浏览器中呈现，如下所示：

```text
<td>Hello Carlos</td>
```

在这种情况下，只要没有其他输入处理或防御措施在起作用，攻击者就可以通过提交以下WebSocket消息来执行概念验证XSS攻击：

```text
{"message":"<img src=1 onerror='alert(1)'>"}
```

**实验室**处理WebSocket消息以利用漏洞

### 操纵WebSocket交握以利用漏洞

只有通过操纵WebSocket交握才能发现和利用某些WebSocket漏洞。 这些漏洞往往涉及设计缺陷，例如：

* 对HTTP标头的放错位置的信任以执行安全性决策，例如X-Forwarded-For标头。
* 会话处理机制存在缺陷，因为处理WebSocket消息的会话上下文通常由交握消息的会话上下文确定。
* 应用程序使用的自定义HTTP标头引入的攻击面。

**实验室**操纵WebSocket交握以利用漏洞

### 使用跨站点WebSocket利用漏洞

当攻击者从攻击者控制的网站建立跨域WebSocket连接时，会出现一些WebSockets安全漏洞。 这被称为跨站点WebSocket劫持攻击，它涉及利用WebSocket握手上的跨站点请求伪造（CSRF）漏洞。 攻击通常会产生严重的影响，使攻击者可以代表受害者用户执行特权操作或捕获受害者用户可以访问的敏感数据。

## 如何保护WebSocket连接

为了最大程度地降低WebSocket引起的安全漏洞的风险，请使用以下准则：

* 使用wss：//协议（基于TLS的WebSockets）。
* 硬编码WebSockets终结点的URL，当然不要将用户可控制的数据合并到此URL中。
* 保护WebSocket交握消息免受CSRF的攻击，以避免跨站点WebSocket劫持漏洞。
* 双向将通过WebSocket接收的数据视为不可信。 在服务器和客户端上安全地处理数据，以防止基于输入的漏洞，例如SQL注入和跨站点脚本。

