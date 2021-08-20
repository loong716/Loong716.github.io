---
title: 从mimikatz学习Windows安全之访问控制模型（二）
author: Loong716
date: 2021-08-20 14:10:00 +0800
categories: [Pentest]
tags: [mimikatz]
---

文章首发于中安网星公众号，原文地址：[从mimikatz学习Windows安全之访问控制模型（二）](https://mp.weixin.qq.com/s/OHbFhqyLQlx5W2W40PRoLg)

* toc
{:toc}

作者：Loong716@[Amulab](https://github.com/Amulab)

## 0x00 前言

上次的文章分析了mimikatz的token模块，并简单介绍了windows访问控制模型的概念。在本篇文章中，主要介绍sid相关的概念，并介绍mimikatz的sid模块，着重分析sid::patch功能的原理


## 0x01 SID简介

### 1. 安全标识符(SID)

在Windows操作系统中，系统使用安全标识符来唯一标识系统中执行各种动作的实体，每个用户有SID，计算机、用户组和服务同样也有SID，并且这些SID互不相同，这样才能保证所标识实体的唯一性

SID一般由以下组成：

+ **“S”**表示SID，SID始终以S开头
+ **“1”**表示版本，该值始终为1
+ **“5”**表示Windows安全权威机构
+ **“21-1463437245-1224812800-863842198”**是子机构值，通常用来表示并区分域
+ **“1128”**为相对标识符(RID)，如域管理员组的RID为512

![1628765377311.png](https://i.loli.net/2021/08/20/mo4YkHC8qK6t5vR.png)

Windows也定义了一些内置的本地SID和域SID来表示一些常见的组或身份


| SID      |  Name   |
| :-------- | --------:|
| S-1-1-0  | World |
| S-1-3-0  | Creator Owner |
| S-1-5-18  | Local SYSTEM |
| S-1-5-11  | Authenticated Users |
| S-1-5-7  | Anonymous |


### 2. AD域中的SID

在AD域中，SID同样用来唯一标识一个对象，在LDAP中对应的属性名称为`objectSid`：

![1628765597849.png](https://i.loli.net/2021/08/20/1FcgGIpNOEsUzAt.png)

重点需要了解的是LDAP上的`sIDHistory`属性

#### (1) SIDHistory

SIDHistory是一个为支持域迁移方案而设置的属性，当一个对象从一个域迁移到另一个域时，会在新域创建一个新的SID作为该对象的`objectSid`，在之前域中的SID会添加到该对象的`sIDHistory`属性中，此时该对象将保留在原来域的SID对应的访问权限

比如此时域A有一个用户User1，其LDAP上的属性如下：

| cn      |  objectSid   | sIDHistory  |
| :-------- | :--------| :------ |
| User1  | S-1-5-21-3464518600-3836984554-627238718-2103 |  null   |

此时我们将用户User1从域A迁移到域B，那么他的LDAP属性将变为：


| cn      |  objectSid   | sIDHistory  |
| :-------- | :--------| :------ |
| User1  | S-1-5-21-549713754-3312163066-842615589-2235 |  S-1-5-21-3464518600-3836984554-627238718-2103   |

此时当User1访问域A中的资源时，系统会将目标资源的DACL与User1的`sIDHistory`进行匹配，也就是说User1仍具有原SID在域A的访问权限

值得注意的是，该属性不仅在两个域之间起作用，它同样也可以用于单个域中，比如实战中我们将一个用户A的`sIDHistory`属性设置为域管的`objectSid`，那么该用户就具有域管的权限

另一个实战中常用的利用，是在金票中添加Enterprise Admins组的SID作为`sIDHistory`，从而实现同一域林下的跨域操作，这个将在后面关于金票的文章中阐述

#### (2) SID Filtering

SID Filtering简单的说就是跨林访问时目标域返回给你的服务票据中，会过滤掉非目标林中的SID，即使你添加了`sIDHistory`属性。SID Filtering林信任中默认开启，在单林中默认关闭

具体可以参考微软的文档和@dirkjanm的文章：

https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280?redirectedfrom=MSDN

https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/



## 0x02 mimikatz的sid模块

### 1. sid::lookup

该功能实现SID与对象名之间的相互转换，有三个参数：

+ **/name**：指定对象名，将其转换为SID
+ **/sid**：指定SID，将其转换为对象名
+ **/system**：指定查询的目标计算机

![1628765625224.png](https://i.loli.net/2021/08/20/wYFEgUAqa4fMI7r.png)


其原理是调用`LookupAccountName()`和`LookupAccountSid()`来实现对象名和SID之间的相互转化，这类API底层是调用MS-LSAT协议(RPC)，比如将对象名转换为SID，底层调用的是`LsarLookupNames4()`

![1628838956631.png](https://i.loli.net/2021/08/20/58qNSDMvTViljf4.png)



### 2. sid::query

该功能支持通过SID或对象名来查询对象的信息，同样有三个参数，使用时指定**/sam**或**/sid**，**/system**可选

+ **/sam**：指定要查询对象的`sAMAccountName`
+ **/sid**：指定要查询对象的`objectSid`
+ **/system**：指定查询的目标域控（LDAP）

![1628765631526.png](https://i.loli.net/2021/08/20/lKZashwv8piR2Wo.png)


这个功能其原理就是直接使用LDAP查询，通过`sAMAccountName`查询对应的`objectSid`，或者通过`objectSid`查询对应的`sAMAccountName`

其核心是调用Windows一系列的LDAP操作API，主要是`ldap_search_s()`：

![1628765637474.png](https://i.loli.net/2021/08/20/epOA2SRJVmYinU4.png)



### 3. sid::modify

该功能用于修改一个域对象的SID，可以使用的参数有三个：

+ **/sam**：通过`sAMAccountName`指定要修改SID的对象
+ **/sid**：通过`objectSid`指定要修改SID的对象
+ **/new**：要修改对象的新SID

使用该功能是需要先使用sid::patch功能对限制LDAP修改SID的函数进行patch（自然也需要先开启debug特权），需要在域控上执行

![1628765644151.png](https://i.loli.net/2021/08/20/z9iMcvoFmEPqybX.png)


修改时的操作就很简单了，调用LDAP操作的API对域对象的`objectSid`进行修改，主要使用的是`ldap_modify_s()`：

![1628765649948.png](https://i.loli.net/2021/08/20/9CGbvUPJtHhL8dz.png)



### 4. sid::add

该功能用来向一个域对象添加`sIDHistoy`属性，有两个参数：

+ **/sam**：通过`sAMAccountName`指定要修改的对象
+ **/sid**：通过`objectSid`指定要修改的对象
+ **/new**：要修改`sIDHistory`为哪个对象的SID，该参数可指定目标的`sAMAccountName`或`objectSid`，当指定名称时会先调用`LookupAccountSid`将其转换为SID

使用该功能也要先执行sid::patch，修改时同样是操作LDAP通过`ldap_modify_s()`修改，不再赘述

![1628765657271.png](https://i.loli.net/2021/08/20/JjaWG5e2L38FIrn.png)



### 5. sid::clear

该功能用来清空一个对象的`sIDHistory`属性

+ **/sam**：要清空`sIDHistory`的对象的`sAMAccountName`
+ **/sid**：要清空`sIDHistory`的对象的`objectSid`

![1628765664170.png](https://i.loli.net/2021/08/20/KXCaHOFYPTBsxvQ.png)

原理就是使用`ldap_modify_s()`将目标对象`sIDHistory`属性修改为空

### 6. sid::patch

对域控LDAP修改过程中的验证函数进行patch，需要在域控上执行，该功能没有参数

patch共分为两个步骤，如果仅第一步patch成功的话，那么可以使用sid::add功能，两步都patch成功的话才可以使用sid::modify功能

![1628765670511.png](https://i.loli.net/2021/08/20/l8LtsVAvZxX7BYT.png)



## 0x03 sid::patch分析

sid::patch在系统版本 < Vista时，patch的是samss服务中ntdsa.dll的内存，更高版本patch的是ntds服务中ntdsai.dll的内存

![1628765677009.png](https://i.loli.net/2021/08/20/KaEpso59XxfUZVn.png)

整个patch过程分为两步：

1. 第一步patch的是`SampModifyLoopbackCheck()`的内存
2. 第二步patch的是`ModSetAttsHelperPreProcess()`的内存

![1628765683129.png](https://i.loli.net/2021/08/20/ZfdUE4Kc69YN82q.png)


我们以Windows Server 2012 R2环境为例来分析，首先我们需要找到NTDS服务所对应的进程，我们打开任务管理器选中NTDS服务，单击右键，选择“转到详细信息”就会跳转到对应进程，这里NTDS服务对应的进程是lsass.exe

![1628765689712.png](https://i.loli.net/2021/08/20/WV5xTal2kzgH9JE.png)


### 1. 域控对LDAP请求的处理

大致分析一下域控对本地LDAP修改请求的过滤与处理流程，当我们修改`objectSid`和`sIDHistory`时，`SampModifyLoopbackCheck()`会过滤我们的请求，即使绕过该函数修改`objectSid`时，仍会受到`SysModReservedAtt()`的限制

侵入式切换到lsass进程并重新加载用户态符号表：

![1628739189573.png](https://i.loli.net/2021/08/20/4G7DZawiLqTpMBf.png)

给两个检查函数打断点

![1628739317777.png](https://i.loli.net/2021/08/20/ZVlfQr2iMCeX8SP.png)

此时我们修改一个用户的描述来触发LDAP修改请求

![1628739357444.png](https://i.loli.net/2021/08/20/7yFN6iRqWt39GZP.png)

命中断点后的调用栈如下：

![1628739417298.png](https://i.loli.net/2021/08/20/FfS3HQJIwg5MvmD.png)

`SampModifyLoopbackCheck()`函数中存在大量Check函数，通过动态调试发现修改`sIDHistoy`的请求经过该函数后便会进入返回错误代码的流程

![1628739474732.png](https://i.loli.net/2021/08/20/e8VoZOz2kvJ3CG1.png)


继续调试到下一个断点


![1628739564431.png](https://i.loli.net/2021/08/20/MgdvPzNIelx7W31.png)

在`SysModReservedAtt()`执行结束后，正常的修改请求不会在`jne`处跳转，而当修改`objectSid`时会在`jne`处跳转，进入返回错误的流程

![1628742079850.png](https://i.loli.net/2021/08/20/kJwLZaip4AEWXtr.png)


### 2. Patch 1/2


当我们想要进行内存patch时，通常会寻找目标内存地址附近的一块内存的值作为标记，编写程序时首先在内存中搜索该标记并拿到标记的首地址，然后再根据偏移找到要patch的内存地址，然后再进行相应的修改操作

mimikatz正是使用这种方法，其在内存中搜索的标记在代码中有明确的体现：

![1628591032930.png](https://i.loli.net/2021/08/20/DErFhQM59okgq6p.png)

我们将域控的ntdsai.dll拿回本地分析，在其中搜索标记`41 be 01 00 00 00 45 89 34 24 83`

![1628590895782.png](https://i.loli.net/2021/08/20/zjrw7u5WgPKtdNR.png)

这一部分内容是在函数`SampModifyLoopbackCheck()`函数的流程中，我们可以使用windbg本地调试对比一下patch前后的函数内容

首先我们找到lsass.exe的基址并切换到该进程上下文：

![1628767377463.png](https://i.loli.net/2021/08/20/IW9G2q4xCw7alJh.png)


使用`lm`列出模块，可以看到lsass进程中加载了ntdsai.dll，表明此时我们可以访问ntdsai.dll对应的内存了

![1628589643623.png](https://i.loli.net/2021/08/20/W2sFkPpYKTXElxA.png)


我们直接查看`SampModifyLoopbackCheck()`函数在内存中的反汇编

![1628593850553.png](https://i.loli.net/2021/08/20/9wV8t1hpYNqHovR.png)

为了对比patch前后的区别，我们使用mimikatz执行sid::patch，然后再查看函数的反汇编。如下图所示，箭头所指处原本是`74`也就是`je`，而patch后直接改为`eb`即`jmp`，使流程直接跳转到`0x7ffc403b2660`

![1628590204617.png](https://i.loli.net/2021/08/20/GibTkPyBSVhtjMF.png)

而`0x7ffc403b2660`处的代码之后基本没有条件检查的函数了，恢复堆栈和寄存器后就直接返回了，这样就达到了绕过检查逻辑的目的

### 3. Patch 2/2

同理，按照mimikatz代码中的标记搜索第二次patch的位置`0f b7 8c 24 b8 00 00 00`

![1628590647544.png](https://i.loli.net/2021/08/20/UutAbskiXPcGDC4.png)

查看`ModSetAttsHelperPreProcess()`处要patch的内存，patch前如下图所示

![1628593751928.png](https://i.loli.net/2021/08/20/PzCaWI954ZR2nFG.png)

patch完成后内存如下图，其实本质是让`SysModReservedAtt()`函数失效，在内存中寻找到标记后偏移-6个字节，然后将验证后的跳转逻辑`nop`掉

![1628594084266.png](https://i.loli.net/2021/08/20/pLR7y1HvZDMa4V2.png)


### 4. 解决patch失败的问题

由于mimikatz中内存搜索的标记覆盖的windows版本不全，所以经常会出现patch失败的问题。例如在我的Windows Server 2016上，第二步patch就会失败，这种情况多半是因为mimikatz中没有该系统版本对应的内存patch标记

![1628765163096.png](https://i.loli.net/2021/08/20/Zkj632OoGfTA7Ea.png)


此时我们只需要将目标的ntdsai.dll拿下来找到目标地址

![1628764918063.png](https://i.loli.net/2021/08/20/5kEZdLW9iITJlSf.png)

然后修改为正确的内存标记和对应的偏移地址即可，如果新增的话记得定义好版本号等信息

![1628764685521.png](https://i.loli.net/2021/08/20/vqr2gF5Vpk4tebf.png)

此时重新编译后就可以正常patch了

![1628764653869.png](https://i.loli.net/2021/08/20/7SUhPwkTXlbrzAG.png)


## 0x04 渗透测试中的应用

在渗透测试中的利用，一个是使用SIDHistory属性来留后门，另一个是修改域对象的SID来实现域内的“影子账户”或者跨域等操作

### 1. SIDHistoy后门

拿下域控后，我们将普通域用户test1的`sIDHistory`属性设置为域管的SID：

![1628742853399.png](https://i.loli.net/2021/08/20/FAhaHG3QsOKNVbe.png)

此时test1将具有域管权限，我们可以利用这个特性来留后门

![1628742938767.png](https://i.loli.net/2021/08/20/aBpGYrqLWTbcE25.png)


### 2. 域内“影子账户”

假设我们此时拿到了域控，然后设置一个普通域用户的SID为域管的SID

![1628760869128.png](https://i.loli.net/2021/08/20/QgziKWjLa6VlhJE.png)

此时我们这个用户仍然只是Domain Users组中的普通域成员

![1628761098910.png](https://i.loli.net/2021/08/20/rPV9xpWB1uhYG5E.png)

但该用户此时已经具有了域管的权限，例如dcsync：

![1628761077861.png](https://i.loli.net/2021/08/20/dLv2zl9D7TqEXwn.png)

并且此时也可以用该用户的账号和密码登录域控，登录成功后是administrator的session。但该操作很有可能造成域内一些访问冲突（猜测，未考证），建议在生产环境中慎用


### 3. 跨域

通常我们拿到一个域林下的一个子域，会通过黄金票据+SIDHistory的方式获取企业管理员权限，控制整个域林

除了这种方法，我们也可以直接修改当前子域对象的`sIDHistory`属性，假设我们现在拿到一个子域域控，通过信任关系发现存在一个父域，此时我们无法访问父域域控的CIFS

![1628751284837.png](https://i.loli.net/2021/08/20/3lM6QF47AkzEe9m.png)

但我们给子域域管的`sIDHistory`属性设置为父域域管的SID

![1628751525767.png](https://i.loli.net/2021/08/20/fnmQYN429J35iI7.png)


此时就可以访问父域域控的CIFS了：

![1628751504053.png](https://i.loli.net/2021/08/20/dFso2lSDn6Wg1t3.png)



## 0x05 参考

https://docs.microsoft.com/

https://github.com/gentilkiwi/mimikatz

