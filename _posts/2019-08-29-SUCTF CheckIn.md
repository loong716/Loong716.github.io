---
title: 从SUCTF 2019 CheckIn 浅谈.user.ini的利用
author: Loong716
date: 2019-08-29 14:10:00 +0800
categories: [CTF]
tags: [File Upload]
---

文章首发于先知社区

https://xz.aliyun.com/t/6091

* toc
{:toc}

# 前言

在前段时间SUCTF 2019的比赛中做了一道名为**CheckIn**的文件上传题，学到了一种新的利用姿势——**.user.ini**。

原题的链接已经失效了，但SU的师傅们把题目源码贴在GitHub上了（感谢师傅们！！），如果想尝试的话可以下载源码复现，在这里放一下地址：

https://github.com/team-su/SUCTF-2019

***

## CheckIn题目分析

首先我们来看一下题目，首页就是一个简单的上传界面：

![](https://xzfile.aliyuncs.com/media/upload/picture/20190824211301-e66945d4-c670-1.png)

我们先上传一个php文件试一下，显然是illegal的
![](https://xzfile.aliyuncs.com/media/upload/picture/20190824211507-31a1ba9a-c671-1.png)

经过fuzz发现修改`content-type`和利用特殊扩展名`php5`、`pht`等都没有成功（当然也不会这么简单233）

然后我们把扩展名改为`aaa`试一下会怎样，发现回显：`&lt;? in contents!`，那么就是说文件内容不能包含`<?`喽，但我们此时知道它是黑名单过滤了。

![](https://xzfile.aliyuncs.com/media/upload/picture/20190824211520-392d2b50-c671-1.png)

我们再把文件内容换一下，发现回显：`exif_imagetype:not image!`，猜测后端应该调用了php的`exif_imagetype()`函数，这个很好绕过，添加图片文件头就可以了


![](https://xzfile.aliyuncs.com/media/upload/picture/20190824211528-3e3566da-c671-1.png)

我们添加最简单的gif文件头`GIF89a`，发现上传成功（注意看该文件夹下还有一个index.php，当时没有注意，但在后面有大用处）
![](https://xzfile.aliyuncs.com/media/upload/picture/20190824211539-44709bc8-c671-1.png)

我们先来捋一下思路：

-> 上传过滤为黑名单，但php脚本文件应该是无法上传的

-> 存在文件头过滤，需要添加图片文件的文件头

-> 文件的内容不能包含`<?`，但可以上传`<script language='php'><scirpt>`类型的图片马来绕过

既然是黑名单过滤而且可以上传图片马，那我们首先想到的肯定是传一个.htaccess上去来将图片马解析为php，而这种方法经过尝试发现失败了。。。

看了一下服务器是**nginx 1.10.3**，似乎版本较高，不存在解析漏洞。

随后在网上看到了一篇p牛的文章，讲的是利用`.user.ini`来上传php后门

***

## .user.ini

我们先在php手册上看一下对`.user.ini`的介绍：

![](https://xzfile.aliyuncs.com/media/upload/picture/20190824211552-4c92f9fe-c671-1.png)

也就是说我们可以在`.user.ini`中设置`php.ini`中**PHP_INI_PERDIR** 和 **PHP_INI_USER** 模式的 INI 设置，而且只要是在使用 **CGI／FastCGI** 模式的服务器上都可以使用`.user.ini`

在p牛的文章中提到了两个有趣的设置：**auto_prepend_file**和**auto_append_file**

我们再到手册中看了下这两个设置的定义：

![](https://xzfile.aliyuncs.com/media/upload/picture/20190824211604-538774ce-c671-1.png)

大致意思就是：我们指定一个文件（如a.jpg），那么该文件就会被包含在要执行的php文件中（如index.php），类似于在index.php中插入一句：`require(./a.jpg);`

这两个设置的区别只是在于**auto_prepend_file**是在文件前插入；**auto_append_file**在文件最后插入（当文件调用的有`exit()`时该设置无效）

## 寻找突破getflag

看过`.user.ini`的分析后我们的思路应该比较清晰了，我们可以上传一个这样的`.user.ini`：

``` php
GIF89a
auto_prepend_file=a.jpg
```

![](https://xzfile.aliyuncs.com/media/upload/picture/20190824211621-5dab4d40-c671-1.png)

此时我们注意到上传目录下还有一个index.php，我们正好需要该目录下有一个可执行php文件，那这简直暴露了考点就是`.user.ini`，看来这个思路应该是可行的

然后再上传一个这样的图片马a.jpg：

``` php
GIF89a
<script language='php'>system('cat /flag');</script>
```

![](https://xzfile.aliyuncs.com/media/upload/picture/20190824211640-68ee25f6-c671-1.png)

最后，我们访问:

http://192.168.177.152:9021/uploads/6683eb5bfa1174bd139499256f60b7ab/index.php

即可得到flag

***

## .user.ini实战利用的可能性

综上所述`.user.ini`的利用条件如下：

1. 服务器脚本语言为PHP
2. 服务器使用CGI／FastCGI模式
3. 上传目录下要有可执行的php文件

从这来看`.user.ini`要比`.htaccess`的应用范围要广一些，毕竟`.htaccess`只能用于Apache

但仔细推敲我们就会感到**“上传目录下要有可执行的php文件”**这个要求在文件上传中也比较苛刻，应该没有天才开发者会把上传文件放在主目录或者把php文件放在上传文件夹。

但也不是全无办法，如果我们根据实际情况配合其他漏洞使用可能会有奇效，前段时间我遇到一个CMS对上传时的路径没有检测`../`，因此导致文件可被上传至任意目录，这种情况下我们就很有可能可以利用`.user.ini`

除此之外，把`.user.ini`利用在隐藏后门上应该是个很好的利用方法，我们在存在php文件的目录下留下`.user.ini`和我们的图片马，这样就达到了隐藏后门的目的。

***

**参考文章：**

https://wooyun.js.org/drops/user.ini%E6%96%87%E4%BB%B6%E6%9E%84%E6%88%90%E7%9A%84PHP%E5%90%8E%E9%97%A8.html
