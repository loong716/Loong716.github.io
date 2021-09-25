---
title: 从mimikatz学习Windows安全之访问控制模型（三）
author: Loong716
date: 2021-09-25 14:10:00 +0800
categories: [Pentest]
tags: [mimikatz]
---

文章首发于中安网星公众号，原文地址：[从mimikatz学习Windows安全之访问控制模型（三）](https://mp.weixin.qq.com/s/Jbi5HwnCCTDNhmL_M5wSCQ)

* toc
{:toc}

作者：Loong716@[Amulab](https://github.com/Amulab)

## 0x00 前言

在之前的文章中，分别向大家介绍了Windows访问控制模型中的SID和Access Token，本篇文章中将为大家介绍最后一个概念——特权

Windows操作系统中许多操作都需要有对应的特权，特权也是一种非常隐蔽的留后门的方式。在AD域中，一些特权在**Default Domain Controller Policy**组策略中被授予给一些特殊的组，这些组的成员虽然不是域管，但如果被攻击者控制同样能给AD域带来巨大的风险

因此对防御者来讲，排查用户的特权配置也是重中之重，本文将对一些比较敏感的特权进行介绍，便于防御者更好的理解特权的概念以及进行排查

## 0x01 令牌中的Privilege

特权是一个用户或组在本地计算机执行各种系统相关操作（关闭系统、装载设备驱动程序、改变系统时间）的权限，特权与访问权限的区别如下：

+ 特权控制账户对系统资源和系统相关任务的访问，而访问权限控制对安全对象（可以具有安全描述符的对象）的访问
+ 系统管理员为用户或组指派特权，而系统根据对象的DACL中的ACE授予或拒绝对安全对象的访问，有时拥有特权可以忽略ACL的检查

在之前介绍Access Token的文章中我们已经了解过了token的基本结构，其中有一部分表示了该用户及该用户所属组所拥有的特权，如下图所示：

![1632456879323.png](https://i.loli.net/2021/09/25/4LzTdyX8sNqhUAH.png)


通常我们会使用`whoami /priv`命令查看当前用户所拥有的特权，默认情况下大部分特权是禁用状态，在使用时需要启用

![1632456864605.png](https://i.loli.net/2021/09/25/r69bRiw8zJQY72q.png)




## 0x02 mimikatz的privilege模块

mimikatz中的privilege模块主要有以下功能，下图中第一个红框中的部分是为当前进程启用一些指定的特权，第二个红框中的`id`和`name`分别支持指定特权的id和名称，并为当前进程启用id和名称对应的特权

![1632456845760.png](https://i.loli.net/2021/09/25/CDLhvoymJ9TPMWb.png)


通常我们比较通用的启用进程特权的方法是这样的，代码如下：

``` cpp
BOOL GetDebugPrivilege()
{
	BOOL status = FALSE;
	HANDLE hToken;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		TOKEN_PRIVILEGES tokenPrivs;
		tokenPrivs.PrivilegeCount = 1;
		if (LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &tokenPrivs.Privileges[0].Luid))
		{
			tokenPrivs.Privileges[0].Attributes = TRUE ? SE_PRIVILEGE_ENABLED : 0;
			if (AdjustTokenPrivileges(hToken, FALSE, &tokenPrivs, sizeof(tokenPrivs), NULL, NULL))
			{
				status = TRUE;
			}
		}
		else wprintf(L"[!] LookupPrivilegeValueW error: %u when get debug privilege.\n", GetLastError());

		CloseHandle(hToken);
	}
	else wprintf(L"[!] OpenProcessToken error: %u when get debug privilege.\n", GetLastError());

	return status;
}
```

而mimikatz是通过调用一个未文档化的API`RtlAdjustPrivilege()`，该API的功能是对当前进程或线程启用/禁用指定的特权，共有四个参数：

+ **ULONG  Privilege**：需要操作的特权的ID
+ **BOOLEAN  Enable**：启用或禁用的标志，1为启用，0为禁用
+ **BOOLEAN  CurrentThread**：指定是否为当前线程，1则设置线程令牌，0则设置进程令牌
+ **PBOOLEAN  Enabled**：该特权修改之前是禁用的还是启用的

``` cpp
NTSTATUS RtlAdjustPrivilege
(
	ULONG    Privilege, // [In]	
	BOOLEAN  Enable,  // [In]	
	BOOLEAN  CurrentThread,  // [In]	
	PBOOLEAN Enabled  // [Out]	
)
```

如果参数指定的是特权的名称，则会先调用`LookupPrivilegeValue()`拿到特权名称对应的特权ID，然后再调用`RtlAdjustPrivilege()`来启用特权

![1632456816631.png](https://i.loli.net/2021/09/25/5JfluC92hyGNxZL.png)


前面提到的是将禁用的特权启用，而如果想给一个账户赋予特权，则可以通过本地策略/组策略来设置，也可以通过`LsaAddAccountRights()`这个API，这里不再赘述



## 0x03 危险的特权

这里主要介绍11个危险的特权，在检查域内安全时要格外注意

### 1. SeDebugPrivilege

通常情况下，用户只对属于自己的进程有调试的权限，但如果该用户Token中被赋予`SeDebugPrivilege`并启用时，该用户就拥有了调试其他用户进程的权限，此时就可以对一些高权限进程执行操作以获取对应的权限，以进程注入为例：


![1632473290240.png](https://i.loli.net/2021/09/25/FIPUa213zLq64fN.png)



### 2. SeBackupPrivilege

该特权代表需要执行备份操作的权限，授予当前用户对所有文件的读取权限，不受文件原本的ACL限制，主要有以下利用思路：

1. 备份SAM数据库
2. 备份磁盘上高权限用户的敏感文件
3. 域内在域控上备份ntds.dit

下图以导出注册表中的SAM和SYSTEM为例

![1632457002019.png](https://i.loli.net/2021/09/25/i1yjRz3BwO7In9A.png)


观察上图可能有师傅会问：为什么前面显示`SeBackupPrivilege`是Disable状态，却能成功执行reg save呢？一开始我猜测可能是reg.exe在执行操作前默认会启用一些特权，随后通过对reg.exe的逆向也印证了这点：

![1632457018350.png](https://i.loli.net/2021/09/25/XvbyhxVwcmMEQRB.png)


在域环境中，**Backup Operators**和**Server Operators**组成员允许在域控进行本地登录，并在域控上拥有`SeBackupPrivilege`特权，所以也可以对ntds.dit进行备份操作，再备份注册表中的SYSTEM和SECURITY，进而解密ntds.dit

需要注意的是在调用`CreateFile()`时，需要指定`FILE_FLAG_BACKUP_SEMANTICS`标志来表示正在为备份或恢复操作打开或创建文件，从而覆盖文件的ACL检查

``` cpp
HANDLE hFile = CreateFileW(
	L"C:\\Windows\\System32\\1.txt", 
	GENERIC_READ, 
	0, 
	NULL, 
	OPEN_EXISTING, 
	FILE_FLAG_BACKUP_SEMANTICS, 
	NULL);
```


### 3. SeRestorePrivilege

该特权是执行还原操作所需的权限，拥有此特权的用户对所有文件拥有写权限，不受文件原本的ACL限制，主要利用思路如下：

1. 修改注册表，实现修改服务、修改启动项等操作
2. 写文件进行DLL劫持

![1632457344306.png](https://i.loli.net/2021/09/25/Dnjgio7PBWylzpZ.png)


域环境中，**Backup Operators**和**Server Operators**组成员同样在域控上也有`SeRestorePrivilege`，因此也可以利用上述操作在域控上完成提权和维权等操作

需要注意的仍是调用API时，需要指定对应的标志，如`CreateFile()`需要指定`FILE_FLAG_BACKUP_SEMANTICS`，`RegCreateKeyEx()`需要指定`REG_OPTION_BACKUP_RESTORE`

### 4. SeTakeOwnershipPrivilege


该特权用来修改目标对象的所有权，也就是说拥有该特权的用户可以修改任意对象的所有者（Owner），而所有者对该对象是有WriteDACL的权限的，可以任意修改对象的ACL

所以如果拥有了`SeTakeOwnershipPrivilege`，就相当于对任意对象有读写的权限，利用方式和`SeRestorePrivilege`、`SeBackupPrivilege`基本相同

``` cpp
GetTakeOwnershipPriv();
...
status = SetNamedSecurityInfo(
	L"C:\\Windows\\System32\\localspl.dll",
	SE_FILE_OBJECT,
	OWNER_SECURITY_INFORMATION,
	user->User.Sid,
	NULL,
	NULL,
	NULL);
```

如下图所示，可以将对象的Owner从TrustedInstaller修改为当前用户：

![1631702263345.png](https://i.loli.net/2021/09/25/VJXHfeYOrs1TMEu.png)



### 5. SeImpersonatePrivilege

当`SeImpersonatePrivilege`特权分配给用户时，表示允许该用户运行的程序模拟客户端，默认Service账户（如MSSQL、IIS的服务账户）和管理员账户会拥有该权限

该权限也是一些potato提权的重要条件，可以通过printbug+`ImpersonateNamedPipeClient()`等等许多方式获取到高权限令牌，进而执行模拟，此处以pipepotato为例：

![1632293320896.png](https://i.loli.net/2021/09/25/VT6gdQXEjc8laFR.png)



### 6. SeAssignPrimaryTokenPrivilege

该特权表示可以为进程分配主令牌，经常与`SeImpersonatePrivilege`特权配合使用在potato的提权中。拥有该特权时，我们可以使用非受限的令牌调用`CreateProcessAsUser()`；或者先创建挂起的进程，再通过`NtSetInformationProcess()`来替换进程的token

顺便提一嘴，之前文章中提到的mimikatz的token::run模块在使用时可能会出现0x00000522错误，如下图所示

![1632299817792.png](https://i.loli.net/2021/09/25/oUQWZflcKrT6sPY.png)

这是因为在调用`CreateProcessAsUser()`时，如果传入的是非受限令牌，那么则需要`SeAssignPrimaryTokenPrivilege`特权，有关受限令牌的概念可阅读微软文档：https://docs.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens

![1632300088335.png](https://i.loli.net/2021/09/25/KWdv2CXBstaehxI.png)

因此该功能应该是用来从SYSTEM权限窃取其他用户的Access Token（因为默认SYSTEM才有`SeAssignPrimaryTokenPrivilege`），如果想要非SYSTEM用户调用的话可以考虑改为用`CreateProcessWithToken()`创建进程

![1632303407818.png](https://i.loli.net/2021/09/25/BIYNSfxormyk8HX.png)


### 7. SeLoadDriverPrivilege

该权限用来加载或卸载设备的驱动，在windows中用户可以通过`NTLoadDriver()`进行驱动的加载，其DriverServiceName参数需要传入驱动配置的注册表项

``` cpp
NTSTATUS NTLoadDriver(
	_In_ PUNICODE_STRING DriverServiceName // \Registry\Machine\System\CurrentControlSet\Services\DriverName
);
```

其中DriverName表示启动名称，该键下至少应有两个值：

+ **ImagePath**：REG_EXPAND_SZ类型，“\??\C:\path\to\driver.sys” 格式
+ **Type**：REG_WORD类型，其值需要被设置为1，表示KENERL_DRIVER

如果是非管理员权限，默认无法操作HKLM注册表项，则可以在HKEY_CURRENT_USER (HKCU) 下创建注册表项并设置驱动程序配置设置，再调用`NTLoadDriver()`指定之前创建的注册表项来注册驱动，代码可参考：https://github.com/TarlogicSecurity/EoPLoadDriver/

此时可以利用一些有漏洞的驱动程序来实现LPE等操作，以Capcom.sys为例：

![1631937778041.png](https://i.loli.net/2021/09/25/hz5Ub4HKfxkIBNR.png)

除此之外，在AD域中`SeLoadDriverPrivilege`权限在域控上默认授予**Print Operators**组，使得该组用户可以远程在域控加载打印机驱动程序，前一段时间的Printnightmare便是绕过了该权限的检查


### 8. SeCreateTokenPrivilege

该特权表示：允许拥有此特权的进程可以通过`ZwCreateToken()`创建Access Token

``` cpp
 NTSATUS ZwCreateToken(
	 OUT PHANDLE             TokenHandle,
	 IN ACCESS_MASK          DesiredAccess,
	 IN POBJECT_ATTRIBUTES   ObjectAttributes,
	 IN TOKEN_TYPE           TokenType,
	 IN PLUID                AuthenticationId,
	 IN PLARGE_INTEGER       ExpirationTime,
	 IN PTOKEN_USER          TokenUser,
	 IN PTOKEN_GROUPS        TokenGroups,
	 IN PTOKEN_PRIVILEGES    TokenPrivileges,
	 IN PTOKEN_OWNER         TokenOwner,
	 IN PTOKEN_PRIMARY_GROUP TokenPrimaryGroup,
	 IN PTOKEN_DEFAULT_DACL  TokenDefaultDacl,
	 IN PTOKEN_SOURCE        TokenSource 
);
```

那么我们肯定会想：能不能直接利用该API创建一个SYSTEM的token，然后起进程？很遗憾，该权限不允许用户使用他们刚创建的令牌

但我们可以利用模拟，创建一个当前用户的、包含特权组SID的token，因为只要令牌是针对同一个用户的，并且完整性级别小于或等于当前进程完整性级别（完整性级别可以通过构造令牌时来设置），就可以不需要`SeImpersonatePrivilege`特权，对线程设置模拟令牌

以创建Group List中包含administrators组SID的token为例，在创建token前修改了组SID、特权列表，最初成功利用模拟令牌创建线程，在system32下写入文件：

![1632387608993.png](https://i.loli.net/2021/09/25/YMvlONm4aAxdngV.png)


需要注意的是在Win10 >= 1809和Windows Server 2019，以及安装了KB4507459的Win10和2016上，我们不能使用生成的模拟令牌，会爆“1346：未提供所需的模拟级别，或提供的模拟级别无效”错误

![1632385533225.png](https://i.loli.net/2021/09/25/krMoRHtA6BPl4Ki.png)

幸运的是已经有大牛发现了绕过的方法，就是把Token的AuthenticationID从`SYSTEM_LUID`(0x3e7)修改为`ANONYMOUS_LOGON_LUID`(0x3e6)，最终成功使用模拟令牌向system32目录写入了文件：

![1632385686357.png](https://i.loli.net/2021/09/25/QJCAbSk71c8nFoe.png)


### 9. SeTcbPrivilege

该特权标志着其拥有者是操作系统的一部分，拥有该特权的进程可利用`LsaLogonUser()`执行创建登录令牌等操作，因此可以充当任意用户

``` cpp
NTSTATUS LsaLogonUser(
	HANDLE              LsaHandle,
	PLSA_STRING         OriginName,
	SECURITY_LOGON_TYPE LogonType,
	ULONG               AuthenticationPackage,
	PVOID               AuthenticationInformation,
	ULONG               AuthenticationInformationLength,
	PTOKEN_GROUPS       LocalGroups,
	PTOKEN_SOURCE       SourceContext,
	PVOID               *ProfileBuffer,
	PULONG              ProfileBufferLength,
	PLUID               LogonId,
	PHANDLE             Token,
	PQUOTA_LIMITS       Quotas,
	PNTSTATUS           SubStatus
);
```

根据微软官方文档，当以下一项获多项为真时，`LsaLogonUser()`调用者需要`SeTcbPrivilege`特权：

+ 使用了 Subauthentication 包
+ 使用 KERB_S4U_LOGON，调用者请求模拟令牌
+ `LocalGroups`参数不为NULL

我们主要关注第二点和第三点，从文档的描述来看，如果使用KERB_S4U_LOGON来登录(也可以使用MSV1_0_S4U_LOGON，但文档中未体现)，我们就可以拿到一张模拟令牌，并且可以在`LocalGroups`参数给该令牌添加附加组：

``` cpp
WCHAR systemSID[] = L"S-1-5-18";
ConvertStringSidToSid(systemSID, &pExtraSid);

pGroups->Groups[pGroups->GroupCount].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
pGroups->Groups[pGroups->GroupCount].Sid = pExtraSid;
pGroups->GroupCount++;
```

此时我们就可以拿到一张拥有SYSTEM的SID的令牌，如何在没有`SeImpersonatePrivilege`特权的情况下使用模拟令牌在`SeCreateTokenPrivilege`的利用中已经提到过了

如下图所示，成功在system32下写入文件：

![1632393013344.png](https://i.loli.net/2021/09/25/xtHo8ZDf1Mjh2WY.png)

当然，如果在域内，也可以尝试KERB_S4U_LOGON来获取域内用户的模拟令牌


### 10. SeTrustedCredmanAccessPrivilege

该特权用来访问凭据管理器，备份凭据管理器中的凭据需要使用`CredBackupCredentials()`这一API，而调用该API需要拥有`SeTrustedCredmanAccessPrivilege`特权，该特权默认授予winlogon.exe和lsass.exe这两个进程

``` cpp
BOOL WINAPI CredBackupCredentials(
	HANDLE Token, 
    LPCWSTR Path, 
    PVOID Password, 
    DWORD PasswordSize, 
    DWORD Flags);
```

为了测试我在凭据管理器中手动新增了一条凭据，用于访问192.168.47.20，用户名和密码为admin/adminpass

![1632281596372.png](https://i.loli.net/2021/09/25/3ewhivfcAqmNV1p.png)

利用方式即窃取winlogon.exe的token，并调用`CredBackupCredentials()`对凭据管理器中的凭据进行备份（指定加密密码为NULL），最终再调用`CryptUnprotectData()`对备份的文件进行解密。此处代码参考：https://github.com/BL0odz/POSTS/blob/main/DumpCred_TrustedTokenPriv/main.cpp

![1632281674885.png](https://i.loli.net/2021/09/25/9Fndoh1uLpGskrK.png)


### 11. SeEnableDelegationPrivilege

在域内配置无约束委派和约束委派时（这里特指传统的约束委派，不包括基于资源的约束委派），都是修改的LDAP中的`userAccountControl`属性来配置（当然约束委派还要修改`msDS-AllowedToDelegateTo`来配置委派可以访问的服务），而想要配置无约束委派的约束委派，不仅需要对属性有写权限，还需要在域控有`SeEnableDelegationPrivilege`特权


![1632367655922.png](https://i.loli.net/2021/09/25/13BgRpIfvb9syCu.png)

虽然该利用对攻击者来说较为苛刻，但如果发现域内组策略给普通账户配置了`SeEnableDelegationPrivilege`特权，就需要检查是否是正常的业务需求

## 0x04 检测与缓解

检测思路：

+ 查看域内Server Operators、Backup Operators、Print Operators等特权组内是否有不应出现的用户
+ 查看域内组策略配置文件，是否有将特权授予不常见的SID
+ 检测“4672: 分配给新登录的特殊权限”日志

缓解思路：

+ 非业务必需情况下不为普通账户赋予特权
+ 不影响业务的情况下，可以取消部分管理员账户的`SeDebugPrivilege`等特权

## 0x05 参考

https://docs.microsoft.com/

https://github.com/gentilkiwi/mimikatz

https://bbs.pediy.com/thread-76552.htm

https://3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-Windows%E4%B9%9D%E7%A7%8D%E6%9D%83%E9%99%90%E7%9A%84%E5%88%A9%E7%94%A8

https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt

https://hackinparis.com/data/slides/2019/talks/HIP2019-Andrea_Pierini-Whoami_Priv_Show_Me_Your_Privileges_And_I_Will_Lead_You_To_System.pdf

https://www.tiraniddo.dev/2021/05/dumping-stored-credentials-with.html

https://www.tarlogic.com/blog/abusing-seloaddriverprivilege-for-privilege-escalation/

https://decoder.cloud/2019/07/04/creating-windows-access-tokens/