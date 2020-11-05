---
title: Cobalt Strike Beacon Bypass AV
author: Loong716
date: 2020-11-05 14:10:00 +0800
categories: [Pentest]
tags: [Bypass-AntiVirus]
---


简单的shellcode loader，测试可过数字卫士、火绒、Windows Defender，不能过avp，其他未测试

* toc
{:toc}

## AES+Base64

shellcode采用AES+Base64处理，相关代码编码or加密代码可自己实现，也可以用一些现成的

![1604558201876.png](https://i.loli.net/2020/11/05/57E9exYBR3ZbgPf.png)

我个人遇到的坑点：

+ 常规思路写的base64编码库可能大多都是针对字符串编码的。内存中字符串结束的标志为`\0`，而shellcode不是简单的字符串，其中也有大量的`\0`，此时如果用针对字符串编码的base64库时，可能会造成部分shellcode的丢失
+ 在loader的代码中，加密后的shellcode经过base64_decode后要赋值给一个数组，此时同样会遇到上一点提到的情况

第一个问题产生的原因是有些base64编码函数内部取数据长度是用`strlen()`函数来取的

我个人的解决思路：

+ 编写base64_encode这个函数时，添加一个参数，其值为被编码的内容的长度
+ 在loader中提前声明一个数组指针，指定指向的数组大小为shellcode的大小

## 360

可正常上线并执行命令，一段时间后云查杀未报毒

![1604557099399.png](https://i.loli.net/2020/11/05/HFIl6B1TcrRjebX.png)

![1604557138630.png](https://i.loli.net/2020/11/05/ktTQKou4NclCsPZ.png)

![1604557172498.png](https://i.loli.net/2020/11/05/1CNZoLBdH3FE8Va.png)


## 火绒

同样没问题：

![1604555723518.png](https://i.loli.net/2020/11/05/2Fpt9QP8hiK1nYc.png)

![1604555733307.png](https://i.loli.net/2020/11/05/P8ZMe3nhmJaHbzI.png)


## Windows Defender

没截图，测试可过静态 + 正常上线并执行命令