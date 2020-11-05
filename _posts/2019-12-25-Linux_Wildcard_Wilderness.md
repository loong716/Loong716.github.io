---
title: Linux提权鸡肋小trick——Wildcard Wilderness
author: Loong716
date: 2019-12-25 14:10:00 +0800
categories: [Pentest]
tags: [privilege elevation]
---

* toc
{:toc}

## Demo

首先我们在测试目录下创建了三个文件`test1`、`test2`、`--help`，其内容不影响测试

![Alt text](https://i.loli.net/2019/12/25/NUSbHWAre4wc268.png)

然后我们分别使用`cat`命令查看三个文件的内容：

![Alt text](https://i.loli.net/2019/12/25/qQ7tpAZFaCW3bvn.png)

我们的预期是查看`--help`的内容时会打印出其内容`help`，而此时却打印了`cat`命令的帮助，说明会优先打印出内置的帮助

那其他参数是不是也是这样呢？我们再来测试一下：

![Alt text](https://i.loli.net/2019/12/25/qCovjZ2c1tWJuH3.png)

可以看到仍然是将`--version`当作内置的版本来处理

如果用户想使用命令操作该文件，就要加上路径`./`：

![Alt text](https://i.loli.net/2019/12/25/Dlh8ZSekLPiO4U9.png)

通过利用该特性，再配合一些命令的特殊参数，我们就可以做一些有意思的操作

### Why?

以执行`rsync`为例，我们使用`strace`来看一下系统的调用过程，先看一下`execve()`函数的说明：

> 在父进程中fork一个子进程，在子进程中调用exec函数启动新的程序。exec函数一共有六个，其中execve为内核级系统调用，其他（execl，execle，execlp，execv，execvp）都是调用execve的库函数。
> 
> int execve(const char *filename, char *const argv[ ], char *const envp[ ]);

例如这段代码的效果就等同于执行`/bin/ls -al /etc/passwd`

``` cpp
#include<unistd.h>   
main()   
{   
　　char *argv[ ]={"ls", "-al", "/etc/passwd", NULL};   
　　char *envp[ ]={"PATH=/bin", NULL}   
　　execve("/bin/ls", argv, envp);   
}  
```

此时再来看`rsync`的系统调用过程就清晰了，可以看到系统将`-e sh test.sh`这些都作为参数传给了`execve()`，这样我们创建的文件的名字就会被作为参数来调用

![Alt text](https://i.loli.net/2019/12/25/we97DMRaEIbrFhB.png)


## Exploit chown/chmod

`chown`/`chmod`命令的相关利用

### File owner/privilege hijacking

使用`chown`的`--reference`参数配合`Wildcard Wilderness`可以达到文件所属用户劫持的效果，先在看该命令和参数的定义：

![Alt text](https://i.loli.net/2019/12/25/mnMONTlgBr1zC6R.png)

首先我们使用`test`用户创建了`a.php`、`b.php`、`c.php`三个文件，文件的拥有者为`test`。然后我们又用`hacker`用户创建了`hacker.php`和`--reference=hacker.php`这两个文件，文件拥有者为`hacker`

![Alt text](https://i.loli.net/2019/12/25/u2tEKQq6kf9JxVT.png)

此时我们使用`chown`命令将该目录下的所有php文件的用户和组修改为`test`：

`sudo chown -R test:test *.php`

执行抛出了一个错误，当我们再次查看当前目录权限时，发现所有的php文件的用户和组被更改为了`hacker`

![Alt text](https://i.loli.net/2019/12/25/PbhCLdjVUe2AqaG.png)

原因就是`--reference=hacker.php`这个文件仍然被当作内置参数处理，相当于在命令后添加了`--reference=hacker.php`这个参数，将当前目录所有php文件的拥有者和所属组改成了`hacker.php`的拥有者和所属组

**PS：**`chmod`命令同样拥有`--reference`参数，利用方法不再赘述


## Exploit tar

以下均为`tar`命令在存在**root权限的计划任务**时的利用，后两个demo复现时没有创建计划任务，只复现一下利用流程


**注意：**`tar`命令利用`--checkpoint-action`和`--checkpoint`这两个参数时要求**被压缩的目标文件/目录**不能为绝对路径


### Reverse shell

以`lin.security`的靶机为例，利用root权限的计划任务配合`tar`的`--checkpoint`和`--checkpoint-action`参数来反弹shell，完成权限提升

先来看一下需要利用的这两个参数的定义：

![Alt text](https://i.loli.net/2019/12/25/L6YtvZPBS52bxac.png)

大意是`--checkpoint`读取备份文件时列出目录名称，`--checkpoint-action`是为每个checkpoint执行动作，也就是说`--checkpoint-action`可以执行命令，例子如下：

前面的计划任务信息不用多说了，就是每分钟执行操作将用户目录下的文件使用`tar`打包后放在`/etc/backups`，而且是root用户的计划任务

![Alt text](https://i.loli.net/2019/12/25/Pjnp2GUZcVLm6uO.png)

![Alt text](https://i.loli.net/2019/12/25/AGVIl4cpe5uWidj.png)

将nc反弹shell的命令先写入`shell.sh`，并对其赋予执行权限。然后在分别创建文件名为`--checkpoint-action=exec=sh shell.sh`和`--checkpoint=1`的两个文件

![Alt text](https://i.loli.net/2019/12/25/7N6Woe4HauDP2Ug.png)

然后在攻击机监听对应端口，待计划任务执行后即可弹回shell，且为root权限

![Alt text](https://i.loli.net/2019/12/25/jeKwvAGoEyfJSCs.png)

### Add Sudoers

首先创建一个修改`/etc/sudoers`内容为允许hacker用户无密码sudo执行任何命令的shell脚本，然后使用`tar`的两个参数执行该shell脚本

![Alt text](https://i.loli.net/2019/12/25/F3AGKV7q4SQTv8E.png)

模拟root权限的计划任务执行

![Alt text](https://i.loli.net/2019/12/25/yTwqcsOZ2RK3iJd.png)

此时查看hacker用户的`sudo`权限，发现已经修改成功，使用`sudo bash`成功提权

![Alt text](https://i.loli.net/2019/12/25/ODgjIbC8l4aPMsd.png)


### Give SUID permission to system binaries

首先创建一个将`/usr/bin/find`赋予SUID的shell脚本，然后还是使用`tar`的这两个参数去执行这个脚本

![Alt text](https://i.loli.net/2019/12/25/BhMvbewYTPLXD5V.png)

此时模拟root权限的计划任务执行`tar`命令

![Alt text](https://i.loli.net/2019/12/25/vBQL7EpHi2Ghd5e.png)

然后使用`find`的`-exec`参数来执行命令。可以看到此时`euid`为root，但是`-exec`这个参数无法执行`cat /etc/shadow`这种带参数命令，于是去看了一下手册：

> -exec command ;
> 
> Execute command; true if 0 status is returned. All following arguments to find are taken to be arguments to the command until an argument consisting of ';' is encountered. The string '{}' is replaced by the current file name being processed everywhere it occurs in the arguments to the command, not just in arguments where it is alone, as in some versions of find. Both of these constructions might need to be escaped (with a '\') or quoted to protect them from expansion by the shell. See the EXAMPLES section for examples of the use of the -exec option. The specified command is run once for each matched file. The command is executed in the starting directory. There are unavoidable security problems surrounding use of the -exec action; you should use the -execdir option instead.
> 
> Example: find repo/ -exec test -d {}/.svn -o -d {}/.git -o -d {}/CVS ; \

发现执行命令的参数取的是在前面查找的目录/文件，于是使用

`find /etc/shadow -exec "cat" {} \;`

来查看`/etc/shadow`

![Alt text](https://i.loli.net/2019/12/25/9JyNqXp36Yo1Qkn.png)

## Exploit rsync

> rsync命令是一个远程数据同步工具，可通过LAN/WAN快速同步多台主机间的文件。rsync使用所谓的“rsync算法”来使本地和远程两个主机之间的文件达到同步，这个算法只传送两个文件的不同部分，而不是每次都整份传送，因此速度相当快。

`rsync`命令同样有比较有意思的参数：

![Alt text](https://i.loli.net/2019/12/25/vYsozX8iKlITtEy.png)


### Add root user to /etc/passwd

创建一个向`/etc/passwd`中写入内容的shel脚本，这里我只是写了一个'test'，在实际中你可以尝试写入一个id为0的用户，这样就相当于写入一个root权限的用户

![Alt text](https://i.loli.net/2019/12/25/6qdbagkY3F42DIO.png)

使用root来执行`rsync`，注意这里`-a`参数后也不能使用绝对路径

执行之后发现`/etc/passwd`已经被写入内容了

![Alt text](https://i.loli.net/2019/12/25/8B6FqmOhKy3RLoi.png)

