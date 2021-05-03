# 目录遍历

在本节中，我们将解释什么是目录遍历，描述如何进行路径遍历攻击和规避常见障碍，并阐明如何防止路径遍历漏洞。

![](../.gitbook/assets/image%20%2814%29%20%281%29.png)

## 什么是目录遍历？

目录遍历（也称为文件路径遍历）是一个 Web 安全漏洞，它允许攻击者读取正在运行应用程序的服务器上的任意文件。 这可能包括应用程序代码和数据，后端系统的凭据以及敏感的操作系统文件。 在某些情况下，攻击者可能能够往服务器写入任意文件，从而允许他们修改应用程序的数据或行为，并最终完全控制服务器。

{% embed url="https://www.youtube.com/watch?v=NQwUDLMOrHo" %}

## 通过目录遍历读取任意文件

考虑一个显示待出售商品图片的购物应用程序。 图片是通过一些 HTML 加载的，如下所示：

```markup
<img src="/loadImage?filename=218.png">
```

`loadImage` 接收一个`filename`参数，并返回指定文件的内容。 图片文件本身存储在磁盘上的`/var/www/images/`位置。 为了返回图像，应用程序将请求的文件名附加到此目录，并使用文件系统 API 读取文件的内容。 在上述情况下，应用程序将从以下文件路径读取：

```text
/var/www/images/218.png
```

该应用程序没有针对目录遍历攻击采取任何防御措施，因此攻击者可以请求以下 URL，从服务器中检索任意文件：

```markup
https://insecure-website.com/loadImage?filename=../../../etc/passwd
```

这将导致应用程序从以下文件路径读取：

```bash
/var/www/images/../../../etc/passwd
```

`../`在文件路径中是有效的，它意味着在目录结构中上升一级。 三个连续的`../`序列从`/var/www/images/`升至文件系统的根目录，因此实际读取的文件为：

```text
/etc/passwd
```

在基于Unix的操作系统上，这是一个标准文件，其中包含在服务器上的用户详细信息。

在Windows上，`../`和`..\`都是有效的目录遍历序列，而检索标准操作系统文件的等效攻击为：

```text
https://insecure-website.com/loadImage?filename=..\..\..\windows\win.ini
```

{% hint style="warning" %}
实验：[文件路径遍历，简单情况](https://portswigger.net/web-security/file-path-traversal/lab-simple)
{% endhint %}

## 利用文件路径遍历漏洞的常见障碍

许多应用程序实施了某种针对路径遍历攻击的防御措施

许多将用户输入文件路径的应用程序，实施了某种针对路径遍历攻击的防御措施，而这些防御往往可以被绕过。

如果应用程序从用户提供的文件名中删除或阻止目录遍历序列，那么就有可能使用各种技术绕过该防御。

您也许可以使用文件系统根目录中的绝对路径（例如`filename=/etc/passwd`）来直接引用文件，而无需使用任何遍历序列。

{% hint style="warning" %}
实验：[文件路径遍历，使用绝对路径绕过被阻止的序列](https://portswigger.net/web-security/file-path-traversal/lab-absolute-path-bypass)
{% endhint %}

您也许可以使用嵌套的遍历序列，例如`....//`或`....\/`，当内部序列被删除时，它们将还原为简单的遍历序列。

{% hint style="warning" %}
**实验：**[文件路径遍历，遍历序列非递归删除](https://portswigger.net/web-security/file-path-traversal/lab-sequences-stripped-non-recursively)
{% endhint %}

您也许可以使用各种非标准编码（例如`..%c0%af`或`..%252f`）来绕过输入过滤。

{% hint style="warning" %}
**实验：**[文件路径遍历，多余的 URL 解码遍历序列被删除](https://portswigger.net/web-security/file-path-traversal/lab-superfluous-url-decode)
{% endhint %}

如果应用程序要求用户提供的文件名必须以预期的基本文件夹（例如`/var/www/images`）开头，则可以包括所需的基本文件夹后跟适当的遍历序列。 例如： 

```text
filename=/var/www/images/../../../etc/passwd
```

{% hint style="info" %}
**实验：**[遍历文件路径，验证路径的起始点](https://portswigger.net/web-security/file-path-traversal/lab-validate-start-of-path)
{% endhint %}

如果应用程序要求用户提供的文件名必须以预期的文件扩展名（例如`.png`）结尾，则可以使用空字节来有效地在所需的扩展名之前终止文件路径。 例如：

```text
filename=../../../etc/passwd%00.png
```

{% hint style="warning" %}
**实验：**[文件路径遍历，使用空字节绕过文件扩展名验证](https://portswigger.net/web-security/file-path-traversal/lab-validate-file-extension-null-byte-bypass)
{% endhint %}

## 如何防止目录遍历攻击

防止文件路径遍历漏洞的最有效方法是避免将用户提供的输入完全传递给文件系统 API。 可以重写许多执行此操作的应用程序功能，以更安全的方式提供相同的行为。

如果认为将用户提供的输入传递给文件系统 API 是不可避免的，则应同时使用两层防御来防止攻击：

* 应用程序应该在处理用户输入之前对其进行验证。理想情况下，验证应与允许值的白名单进行比较。 如果这对所需的功能来说是不可能，那么验证应该验证输入只包含允许的内容，如纯粹的字母数字字符。
* 在验证了所提供的输入后，应用程序应将输入追加到基本目录中，并使用平台文件系统 API 来规范路径。它应该验证规范化的路径以预期的基本目录开始。

下面是一些简单的Java代码示例，根据用户的输入来验证文件的规范路径：

```java
File file = new File(BASE_DIRECTORY, userInput);
if (file.getCanonicalPath().startsWith(BASE_DIRECTORY)) {
    // process file
}
```

> 阅读更多
>
> [使用 Burp Suite 的 Web 漏洞扫描器寻找目录穿越漏洞](https://portswigger.net/burp/vulnerability-scanner)

