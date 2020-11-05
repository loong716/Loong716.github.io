---
title: 文件上传总结
author: Loong716
date: 2019-08-14 14:10:00 +0800
categories: [Web]
tags: [File_Upload]
---


* toc
{:toc}

以下上传测试使用的HTML表单的代码为：

``` html
<html>
	<head>
		<title>File Upload</title>
		<meta charset="utf-8">
	</head>
	<body>
		<form action="upload.php" method="POST" enctype="multipart/form-data">
			<input type="hidden" name="MAX_FILE_SIZE" value="1000000">
			选择文件: <input type="file" name="myfile">
			<input type="submit" value="Upload">
		</form>
	</body>
</html>
```
## 1.1 前端JavaScript检测

前端一般都是使用js来限制我们的上传类型和文件大小，这里以upload-labs Pass-01的源码为例：

``` javascript
function checkFile() {
    var file = document.getElementsByName('upload_file')[0].value;
    if (file == null || file == "") {
        alert("请选择要上传的文件!");
        return false;
    }
    //定义允许上传的文件类型
    var allow_ext = ".jpg|.png|.gif";
    //提取上传文件的类型
    var ext_name = file.substring(file.lastIndexOf("."));
    //判断上传文件类型是否允许上传
    if (allow_ext.indexOf(ext_name + "|") == -1) {
        var errMsg = "该文件不允许上传，请上传" + allow_ext + "类型的文件,当前文件类型为：" + ext_name;
        alert(errMsg);
        return false;
    }
}
```

## 2.1 后端检测文件类型

### 2.1.1 检测content-type

后端代码大致为：

``` php
<?php
$allow_content_type = array("image/gif", "image/png", "image/jpeg");
$path = "./uploads";
$type = $_FILES["myfile"]["type"];

if (!in_array($type, $allow_content_type)) {
        die("File type error!<br>");
} else {
        $file = $path . '/' . $_FILES["myfile"]["name"];
        if (move_uploaded_file($_FILES["myfile"]["tmp_name"], $file)) {
                echo 'Success!<br>';
        } else {
                echo 'Error!<br>';
        }
}
?>
```

**绕过方法：**

抓包将`content-type`改为图片形式（即'image/png'等），即可成功上传

### 2.1.2 检测文件头判断文件类型

后端代码大致为：

``` php
<?php
$allow_mime = array("image/gif", "image/png", "image/jpeg");
$imageinfo = getimagesize($_FILES["myfile"]["tmp_name"]);
$path = "./uploads";

if (!in_array($imageinfo['mime'], $allow_mime)) {
        die("File type error!<br>");
} else {
        $file = $path . '/' . $_FILES["myfile"]["name"];
        if (move_uploaded_file($_FILES["myfile"]["tmp_name"], $file)) {
                echo 'Success!<br>';
        } else {
                echo 'Error!<br>';
        }
}
?>
```

此时虽然检查的也是文件类型，但是是使用`getimagesize()`函数来获取文件的MIME类型，此时检测的不是数据包中的`content-type`，而是图片的文件头，常见的图片文件头如下：

> gif(GIF89a) : 47 49 46 38 39 61
> 
> jpg、jpeg : FF D8 FF
> 
> png : 89 50 4E 47 0D 0A  

**绕过方法：**

当上传php文件时，可以使用**winhex**、**010editor**等十六进制处理工具，在数据最前面添加图片的文件头，从而绕过检测


## 2.2 后端检测文件扩展名

### 2.2.1 黑名单检测

后端代码大致为：

``` php
<?php
// 实际情况中黑名单内数据会更多更全面
$blacklist = array('php', 'asp', 'aspx', 'jsp');
$path = "./uploads";
$type = array_pop(explode('.', $_FILES['myfile']['name']));

if (in_array(strtolower($type), $blacklist)) {
        die("File type errer!<br>");
} else {
        $file = $path . '/' . $_FILES['myfile']['name'];
        if (move_uploaded_file($_FILES['myfile']['tmp_name'], $file)) {
                echo 'Success!<br>';
        } else {
                echo 'Error!<br>';
        }
}
?>
```

众所周知使用黑名单是非常不安全的，很多网站会使用扩展名黑名单来限制上传文件类型，有些甚至在判断时都不用`strtolower()`来处理，因此造成漏洞

**绕过方法：**

1. 使用一些特殊扩展名来绕过（如php可以使用php3、php4、php5等来代替）
2. 在后端比较没有转换大小写处理时，使用大小写混淆（如将php改为pHp等）来绕过

### 2.2.2 白名单检测

大致代码如下，与黑名单检测没有太大差别：

``` php
<?php
$whitelist = array('png', 'jpg', 'jpeg', 'gif');
$path = "./uploads";
$type = array_pop(explode('.', $_FILES['myfile']['name']));

if (!in_array(strtolower($type), $whitelist)) {
        die("File type errer!<br>");
} else {
        $file = $path . '/' . $_FILES['myfile']['name'];
        if (move_uploaded_file($_FILES['myfile']['tmp_name'], $file)) {
                echo 'Success!<br>';
        } else {
                echo 'Error!<br>';
        }
}
```

白名单相对与黑名单就安全许多，要求只能是特定扩展名的文件才能上传，虽然我们无法从代码层面来绕过，但这样也不是绝对的安全，可以利用其他漏洞来绕过

**绕过方法：**

1. 使用%00截断文件名来上传（后面会讲）
2. 如果目标还存在文件包含漏洞，那么就可以上传图片马再文件包含来拿shell


## 2.3 后端检测文件内容

### 2.3.1 文件内容替换

这种主要是将文件中的敏感字符替换掉，大致代码类似于下面这样：
``` php
<?php
$path = "./uploads";
$content = file_get_contents($_FILES['myfile']['tmp_name']);
$content = str_replace('?', '!', $content);
$file = $path . '/' . $_FILES['myfile']['name'];

if (move_uploaded_file($_FILES['myfile']['tmp_name'], $file)) {
        file_put_contents($file, $content);
        echo 'Success!<br>';
} else {
        echo 'Error!<br>';
}
?>
```
此时如果我们要上传php的一句话`<?php @eval($_POST['shell']);?>`时，php的语言标记中的`?`会被替换为`!`，这样一句话就不能被执行了

**绕过方法：**

主要还是要根据实际过滤的字符来判断，如果写死的话可能是没办法的（一般不会，因为还要兼顾图片上传）

比如过滤掉问号，我们就可以使用`<script language='php'>system('ls');</script>`这样的一句话。具体方法要看实际代码过滤了哪些字符。


### 2.3.2 图片二次渲染

这个情况自己平时没有遇到过，是在syclover的一个paper中看到的

大致意思是后端调用了php的GD库，提取了文件中的图片数据，然后再重新渲染，这样图片中插入的恶意代码就会被过滤掉了，可以参考一下upload-labs Pass-16中二次渲染的代码：

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

详细的可以查看：http://www.owasp.org.cn/OWASP_Training/Upload_Attack_Framework.pdf

## 3.1 解析漏洞及其他漏洞

### 3.1.1 IIS解析漏洞

#### 1.IIS6.0

在IIS6.0中有两个很重要的asp解析漏洞：

1. 假设当前有一个名为"xxx.asp"的目录，那么该目录下的所有文件都将被作为asp文件解析
2. 假设上传一个名为"test.asp;xxx.jpg"时，该文件会被当做asp文件解析

#### 2.IIS7.5

在该版本的IIS中存在一个php的解析漏洞，但这个漏洞利用条件是服务器在php.ini中将`cgi.fix_pathinfo`的值设置为1

然后当我们访问服务器上任意一个文件时（如：http://test.com/a.jpg），当我们在URL后面添加`.php`（即：http://test.com/a.jpg/.php），那么文件a.jpg就将被作为php文件来解析


### 3.1.2 Apache解析漏洞

#### 1.利用低版本apache扩展名解析特性

在了解这个解析漏洞之前，我们要首先了解apache和php的三种结合方式：

> Apache和php三种结合方式：
> 1.CGI
> 2.Module
> 3.FastCGI

该解析漏洞只有在apache和php以Module方式结合时才存在，而且Apache还有一个特性：

> Apache在解析文件时会以文件名从右向左解析，当最后一个扩展名无法识别时，就会向左查看是否有可以识别的文件名，如果没有的话就以配置中的默认文件类型来解析
> 例如：
> a.php.xxx因为xxx无法识别，而左边的php可识别，就会被解析为php文件

因此，如果上传文件名为a.php.xxx的一句话，访问后就很可能拿到shell


#### 2.CVE-2017-15715

还有一个apache的解析漏洞就是CVE-2017-15715，这个漏洞利用方式就是上传一个文件名最后带有换行符(只能是`\x0A`，如上传a.php，然后在burp中在文件名最后添上`\x0A`)，以此来绕过一些黑名单过滤

具体的漏洞分析可以看p牛：https://www.leavesongs.com/PENETRATION/apache-cve-2017-15715-vulnerability.html

### 3.1.3 nginx解析漏洞

nginx有一个和IIS7.5差不多的解析漏洞。其实这个漏洞的成因不在nginx和IIS，而是因为php-cgi的配置问题才导致的漏洞。漏洞的条件和利用方法和前面讲的IIS7.5相同。

似乎nginx还有一个%00的解析漏洞（不是截断，而是在访问test.jpg时在其后添加%00.php，然后test.jpg会被作为php文件解析），但是存在于很早之前的版本中，查了一下是以下版本：**0.5.x, 0.6.x, 0.7 <= 0.7.65, 0.8 <= 0.8.37**

### 3.1.4 %00截断

这个多数被利用在截断路径，利用的条件是：

> PHP < 5.3.4
> 
> magic_quotes_gpc 关闭

因为`0x00`是字符串的结束标志符，所以php在读取到`0x00`时就不会再往后读取，我们可以利用这些截断字符后面不需要的内容

以upload-labs的Pass-12为例，源码如下：
``` php
$is_upload = false;
$msg = null;
if(isset($_POST['submit'])){
    $ext_arr = array('jpg','png','gif');
    $file_ext = substr($_FILES['upload_file']['name'],strrpos($_FILES['upload_file']['name'],".")+1);
    if(in_array($file_ext,$ext_arr)){
        $temp_file = $_FILES['upload_file']['tmp_name'];
        $img_path = $_POST['save_path']."/".rand(10, 99).date("YmdHis").".".$file_ext;

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

由于是白名单限制了上传文件类型，因此我们无法在文件名处做文章。但最终`move_uploaded_file()`的目标目录是我们可控的，我们可以将POST传入的`save_path`改为`../upload/shell.php%00`，这样后面的内容就会被截断掉，这就导致了任意文件上传

还要注意的是`%00`是url编码，在以POST传参时应该使用burpsuite对其进行url decode，或者修改hex值为00；当GET传参时因为浏览器会做一遍url decode，所以直接传`%00`即可。

### 3.1.5 利用.htaccess解析

> .htaccess文件(或者"分布式配置文件"）,全称是Hypertext Access(超文本入口)。提供了针对目录改变配置的方法， 即，在一个特定的文档目录中放置一个包含一个或多个指令的文件， 以作用于此目录及其所有子目录。作为用户，所能使用的命令受到限制。管理员可以通过Apache的AllowOverride指令来设置。

利用.htaccess的条件：Apache中配置`AllowOverride All`

.htaccess文件可以配置将特定的文件按规定的文件类型进行解析，可以用以下两种方式来配置：

``` html
<FilesMatch "test">
  SetHandler application/x-httpd-php
</FilesMatch>
```
这一种采用正则匹配，只要文件名为test的文件都将被作为php文件解析
``` html
AddType application/x-httpd-php .jpg
```
第二种是将.jpg文件都作为php文件解析

这样我们如果能将.htaccess上传到服务器的话，就可以再根据我们自己设定的规则来解析上传的文件，以此来绕过上传过滤

