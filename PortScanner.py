# -*- coding:utf-8 -*-

import nmap, re, sys, pycurl, json, time, pymysql, logging, smtplib, os
from email.mime.text import MIMEText
from email.header import Header
from multiprocessing import Pool
from StringIO import StringIO

# create table scan_port(id int(11) not null auto_increment primary key,ip varchar(20) not null,port int(6) not null,status varchar(20),services varchar(255),deal varchar(20),create_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP);

conn = pymysql.connect(host='localhost',port=3306,user='root',passwd='root',db="test")
cursor = conn.cursor()

# 第一步，创建一个logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)  # Log等级总开关
# 第二步，创建一个handler，用于写入日志文件
rq = time.strftime('%Y%m%d', time.localtime(time.time()))
log_path = os.path.dirname(os.path.realpath(__file__)) + '/'
log_name = log_path + rq + '.log'
logfile = log_name
fh = logging.FileHandler(logfile, mode='w')
# 输出到file的log等级的开关
fh.setLevel(logging.DEBUG)
# 第三步，定义handler的输出格式
formatter = logging.Formatter("%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s")
fh.setFormatter(formatter)
# 第四步，将logger添加到handler里面
logger.addHandler(fh)


def sendemail(content):

    sender = 'xxx@xx.com'
    receiver = ['xxx@xx.com','xxx@qq.com']
    subject = '[这是一封测试邮件]服务器端口扫描报告'
    smtpserver = 'email.xx.com'
    smtpuser = 'xxx@xx.com'
    smtppass = 'xxxxxx'

    msg = MIMEText(content,'html','utf-8')#中文需参数‘utf-8'，单字节字符不需要
    msg['Subject'] = Header(subject, 'utf-8')
    msg['From'] = '<%s>' % sender
    msg['To'] = ";".join(receiver)
    try:
        smtp = smtplib.SMTP()
        smtp.connect(smtpserver)
        smtp.login(smtpuser, smtppass)
        smtp.sendmail(sender, receiver, msg.as_string())
        smtp.quit()
    except Exception,e:
        print e

def get_iplist():
    url = 'url'
    buffer = StringIO()
    c = pycurl.Curl()  # 创建一个curl对象
    c.setopt(pycurl.URL, url)
    c.setopt(pycurl.SSL_VERIFYPEER, 0)
    c.setopt(pycurl.SSL_VERIFYHOST, 0)
    # 连接超时时间,5秒
    c.setopt(pycurl.CONNECTTIMEOUT, 5)

    # 下载超时时间,20秒
    c.setopt(pycurl.TIMEOUT, 20)
    c.setopt(pycurl.FORBID_REUSE, 1)
    c.setopt(pycurl.MAXREDIRS, 1)
    c.setopt(pycurl.NOPROGRESS, 1)
    c.setopt(pycurl.DNS_CACHE_TIMEOUT, 30)

    c.setopt(pycurl.WRITEDATA, buffer)
    try:
        c.perform()
    except Exception, e:
        print "connecion error:" + str(e)
        c.close()
        sys.exit()

    body = json.loads(buffer.getvalue())
    i = 0
    iplist = []
    while i < len(body['result']):
        ip = body['result'][i]['cuccAddr']
        if ip != None:
            iplist.append(ip)
        i += 1

    return iplist

def check_port(portrange):
    try:
        p1 = re.compile(r'(\d+)-(\d+)$')
        p2 = re.compile(r'((\d+,)+)(\d+)$')
        if p1.match(portrange):
            return True
        elif p2.match(portrange):
            return True
        else:
            return False
    except Exception as err:
        logging.error(err)

class Template_html(object):
    """html报告"""
    HTML_TMPL = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>主机端口安全扫描报告</title>
            <link href="http://libs.baidu.com/bootstrap/3.0.3/css/bootstrap.min.css" rel="stylesheet">
            <style type="text/css" media="screen">
        body  { font-family: Microsoft YaHei,Tahoma,arial,helvetica,sans-serif;padding: 20px;}
        </style>
        </head>
        <body style="-moz-box-sizing:border-box;-ms-text-size-adjust:100%(html)s;-webkit-box-sizing:border-box;-webkit-text-size-adjust:100%(html)s;Margin:0;background:#fff!important;box-sizing:border-box;color:#0a0a0a;font-family:Helvetica,Arial,sans-serif;font-size:16px;font-weight:400;line-height:1.3;margin:0;min-width:100%(html)s;padding:0;text-align:left;width:100%(html)s!important">
        <span class="preheader" style="color:#f3f3f3;display:none!important;font-size:1px;line-height:1px;max-height:0;max-width:0;mso-hide:all!important;opacity:0;overflow:hidden;visibility:hidden"></span>
        <table class="body" style="Margin:0;background:#fff!important;border-collapse:collapse;border-spacing:0;color:#0a0a0a;font-family:Helvetica,Arial,sans-serif;font-size:16px;font-weight:400;height:100%(html)s;line-height:1.3;margin:0;padding:0;text-align:left;vertical-align:top;width:100%(html)s">
            <tr style="padding:0;text-align:left;vertical-align:top">
                <td class="center" align="center" valign="top" style="-moz-hyphens:auto;-webkit-hyphens:auto;Margin:0;border-collapse:collapse!important;color:#0a0a0a;font-family:Helvetica,Arial,sans-serif;font-size:16px;font-weight:400;hyphens:auto;line-height:1.3;margin:0;padding:0;text-align:left;vertical-align:top;word-wrap:break-word">
                    <center data-parsed="" style="min-width:580px;width:100%(html)s">
                        <table bgcolor="#ffffff" align="center" class="wrapper ysec float-center" style="Margin:0 auto;border-collapse:collapse;border-spacing:0;float:none;font-family:Microsoft Yahei;margin:0 auto;padding:0;text-align:center;vertical-align:top;width:1200px">
                            <tr style="padding:0;text-align:left;vertical-align:top">
                                <td class="wrapper-inner" style="-moz-hyphens:auto;-webkit-hyphens:auto;Margin:0;border-collapse:collapse!important;color:#0a0a0a;font-family:Microsoft Yahei;font-size:16px;font-weight:400;hyphens:auto;line-height:1.3;margin:0;padding:0;text-align:left;vertical-align:top;word-wrap:break-word">
                                    <table bgcolor="#1f83f3" class="wrapper header" align="center" style="background:#1f83f3;border-collapse:collapse;border-spacing:0;padding:0;text-align:left;vertical-align:top;width:100%(html)s">
                                        <tr style="padding:0;text-align:left;vertical-align:top">
                                            <td class="wrapper-inner" style="-moz-hyphens:auto;-webkit-hyphens:auto;Margin:0;border-collapse:collapse!important;color:#0a0a0a;font-family:Microsoft Yahei;font-size:16px;font-weight:400;hyphens:auto;line-height:1.3;margin:0;padding:20px;text-align:left;vertical-align:top;word-wrap:break-word">
                                                <table align="center" class="container" style="Margin:0 auto;background:0 0;border-collapse:collapse;border-spacing:0;margin:0 auto;padding:0;text-align:inherit;vertical-align:top;width:1150px">
                                                    <tbody>
                                                    <tr style="padding:0;text-align:left;vertical-align:top">
                                                        <td style="-moz-hyphens:auto;-webkit-hyphens:auto;Margin:0;border-collapse:collapse!important;color:#0a0a0a;font-family:Microsoft Yahei;font-size:16px;font-weight:400;hyphens:auto;line-height:1.3;margin:0;padding:0;text-align:left;vertical-align:top;word-wrap:break-word">
                                                            <table class="row collapse" style="border-collapse:collapse;border-spacing:0;display:table;padding:0;position:relative;text-align:left;vertical-align:top;width:100%(html)s">
                                                                <tbody>
                                                                <tr style="padding:0;text-align:left;vertical-align:top">
                                                                    <th class="small-12 large-2 columns first" valign="middle" style="Margin:0 auto;color:#0a0a0a;font-family:Microsoft Yahei;font-size:16px;font-weight:400;line-height:1.3;margin:0 auto;padding:0;padding-bottom:0;padding-left:0;padding-right:0;text-align:left;width:104.67px">
                                                                        <table style="border-collapse:collapse;border-spacing:0;padding:0;text-align:left;vertical-align:top;width:100%(html)s">
                                                                            <tr style="padding:0;text-align:left;vertical-align:top">
                                                                                <th style="Margin:0;color:#0a0a0a;font-family:Microsoft Yahei;font-size:16px;font-weight:400;line-height:1.3;margin:0;padding:0;text-align:left">
                                                                                </th>
                                                                            </tr>
                                                                        </table>
                                                                    </th>
                                                                    <th class="small-12 large-8 columns" valign="middle" style="Margin:0 auto;color:#0a0a0a;font-family:Microsoft Yahei;font-size:16px;font-weight:400;line-height:1.3;margin:0 auto;padding:0;padding-bottom:0;padding-left:0;padding-right:0;text-align:left;width:386.67px">
                                                                        <table style="border-collapse:collapse;border-spacing:0;padding:0;text-align:left;vertical-align:top;width:100%(html)s">
                                                                            <tr style="padding:0;text-align:left;vertical-align:top">
                                                                                <th style="Margin:0;color:#0a0a0a;font-family:Microsoft Yahei;font-size:16px;font-weight:400;line-height:1.3;margin:0;padding:0;text-align:left">
                                                                                    <h2 class="text-center mail-title" style="Margin:0;Margin-bottom:10px;color:#fff;font-family:Microsoft Yahei;font-size:18pt;font-weight:400;line-height:1.3;margin:0;margin-bottom:10px;padding:0;text-align:center;word-wrap:normal">主机端口漏洞预警通知</h2>
                                                                                    <p class="text-center mail-date" style="Margin:0;Margin-bottom:10px;color:#fff;font-family:Microsoft Yahei;font-size:16px;font-weight:400;line-height:1.3;margin:0;margin-bottom:10px;padding:0;padding-top:15px;text-align:center">
                                                                                        %(time)s
                                                                                    </p>
                                                                                </th>
                                                                            </tr>
                                                                        </table>
                                                                    </th>
                                                                    <th class="small-12 large-2 columns last" valign="middle" style="Margin:0 auto;color:#0a0a0a;font-family:Microsoft Yahei;font-size:16px;font-weight:400;line-height:1.3;margin:0 auto;padding:0;padding-bottom:0;padding-left:0;padding-right:0;text-align:left;width:104.67px">
                                                                        <table style="border-collapse:collapse;border-spacing:0;padding:0;text-align:left;vertical-align:top;width:100%(html)s">
                                                                            <tr style="padding:0;text-align:left;vertical-align:top">
                                                                                <th style="Margin:0;color:#0a0a0a;font-family:Microsoft Yahei;font-size:16px;font-weight:400;line-height:1.3;margin:0;padding:0;text-align:left">
                                                                                </th>
                                                                            </tr>
                                                                        </table>
                                                                    </th>
                                                                </tr>
                                                                </tbody>
                                                            </table>
                                                        </td>
                                                    </tr>
                                                    </tbody>
                                                </table>
                                            </td>
                                        </tr>
                                    </table>
                                    <table bgcolor="#f4f4f4" class="wrapper content" align="center" style="background:#f4f4f4;border-collapse:collapse;border-spacing:0;padding:0;text-align:left;vertical-align:top;width:100%(html)s">
                                        <tr style="padding:0;text-align:left;vertical-align:top">
                                            <td class="wrapper-inner" style="-moz-hyphens:auto;-webkit-hyphens:auto;Margin:0;background:#f4f4f4;border-collapse:collapse!important;color:#0a0a0a;font-family:Microsoft Yahei;font-size:16px;font-weight:400;hyphens:auto;line-height:1.3;margin:0;padding:0;text-align:left;vertical-align:top;word-wrap:break-word">
                                                <table class="spacer" style="border-collapse:collapse;border-spacing:0;padding:0;text-align:left;vertical-align:top;width:100%(html)s">
                                                    <tbody>
                                                    <tr style="padding:0;text-align:left;vertical-align:top">
                                                        <td height="10pxpx" style="-moz-hyphens:auto;-webkit-hyphens:auto;Margin:0;background:#f4f4f4;border-collapse:collapse!important;color:#0a0a0a;font-family:Microsoft Yahei;font-size:10pxpx;font-weight:400;hyphens:auto;line-height:10pxpx;margin:0;mso-line-height-rule:exactly;padding:0;text-align:left;vertical-align:top;word-wrap:break-word">
                                                            &#xA0;
                                                        </td>
                                                    </tr>
                                                    </tbody>
                                                </table>
                                                <table align="center" class="container" style="Margin:0 auto;background:#fefefe;border-collapse:collapse;border-spacing:0;margin:0 auto;padding:0;text-align:inherit;vertical-align:top;width:1150px">
                                                    <tbody>
                                                    <tr style="padding:0;text-align:left;vertical-align:top">
                                                        <td style="-moz-hyphens:auto;-webkit-hyphens:auto;Margin:0;background:#f4f4f4;border-collapse:collapse!important;color:#0a0a0a;font-family:Microsoft Yahei;font-size:16px;font-weight:400;hyphens:auto;line-height:1.3;margin:0;padding:0;text-align:left;vertical-align:top;word-wrap:break-word">
                                                            <p style="Margin:0;Margin-bottom:10px;background:#f4f4f4;color:#0a0a0a;font-family:Microsoft Yahei;font-size:14pt;font-weight:700;line-height:1.3;margin:0;margin-bottom:10px;padding:0;text-align:left">
                                                                亲、你好!
                                                            </p>
                                                            <p class="text-body mail-dec-text" style="Margin:0;Margin-bottom:10px;background:#f4f4f4;color:#0a0a0a;font-family:Microsoft Yahei;font-size:11pt;font-weight:400;line-height:30px;margin:0;margin-bottom:0;padding:0;text-align:left;text-indent:30px;vertical-align:middle">
                                                                这是一封主机端口漏洞提醒信，为了提醒您及时修复漏洞，我们发送此邮件。
                                                            </p>
                                                            <p class="text-body mail-dec-text" style="Margin:0;Margin-bottom:10px;background:#f4f4f4;color:#0a0a0a;font-family:Microsoft Yahei;font-size:11pt;font-weight:400;line-height:30px;margin:0;margin-bottom:0;padding:0;text-align:left;text-indent:30px;vertical-align:middle">
                                                                您名下 <strong style="color:red">%(ip)s</strong> 主机共存在 <strong style="color:red">%(count)s</strong> 个漏洞，<span style="color:#E7505A">请及时检查修复端口漏洞并点击确认修复按钮进行确认。</span>
                                                            </p>
                                                            <table width="100%(html)s" class="layout-table" cellspacing="0" cellpadding="0" border="0" style="background:#f4f4f4;border-collapse:collapse;border-spacing:0;padding:0;text-align:left;vertical-align:top">
                                                                <tbody style="background:#f4f4f4">
                                                                <tr style="background:#f4f4f4;padding:0;text-align:left;vertical-align:top">
                                                                    <th style="Margin:0;background:#f4f4f4;color:#0a0a0a;font-family:Microsoft Yahei;font-size:16px;font-weight:400;height:30px;line-height:1.3;margin:0;padding:0;text-align:right" valign="top">
                                                                        <a href="http://www.baidu.com" class="bt-default" style="Margin:0;background:#0c90ff;border:1px #f2f2f2 solid;border-radius:3px;color:#fff;display:inline-block;font-family:Helvetica,Arial,sans-serif;font-size:9pt;font-weight:400;height:20px;line-height:20px;margin:0;margin-left:5px;padding:5px;text-align:center;text-decoration:none;vertical-align:middle">&nbsp;批量修复&nbsp;</a>
                                                                    </th>
                                                                </tr>
                                                                </tbody>
                                                            </table>
                                                            <table class="spacer" style="border-collapse:collapse;border-spacing:0;padding:0;text-align:left;vertical-align:top;width:100%(html)s">
                                                                <tbody>
                                                                <tr style="padding:0;text-align:left;vertical-align:top">
                                                                    <td height="10px" style="-moz-hyphens:auto;-webkit-hyphens:auto;Margin:0;background:#f4f4f4;border-collapse:collapse!important;color:#0a0a0a;font-family:Microsoft Yahei;font-size:10px;font-weight:400;hyphens:auto;line-height:10px;margin:0;mso-line-height-rule:exactly;padding:0;text-align:left;vertical-align:top;word-wrap:break-word">
                                                                        &#xA0;
                                                                    </td>
                                                                </tr>
                                                                </tbody>
                                                            </table>
                                                            <table class="content-table" style="border-collapse:collapse;border-spacing:0;padding:0;text-align:left;vertical-align:top;width:100%(html)s">
                                                                <thead>
                                                                <tr style="padding:0;text-align:left;vertical-align:top">
                                                                    <th class="top-blue" style="Margin:0;background:#fff;border-bottom:1px #f2f2f2 solid;border-top:2px #1f83f3 solid;color:#0a0a0a;font-family:Microsoft Yahei;font-size:11pt;font-weight:700;height:45px;line-height:1.3;margin:0;padding:0;padding-left:10px;text-align:left;vertical-align:middle">
                                                                        IP地址
                                                                    </th>
                                                                    <th class="top-orange" style="Margin:0;background:#fff;border-bottom:1px #f2f2f2 solid;border-top:2px #f60 solid;color:#0a0a0a;font-family:Microsoft Yahei;font-size:11pt;font-weight:700;height:45px;line-height:1.3;margin:0;padding:0;padding-left:10px;text-align:left;vertical-align:middle">
                                                                        端口
                                                                    </th>
                                                                    <th class="top-blue" style="Margin:0;background:#fff;border-bottom:1px #f2f2f2 solid;border-top:2px #1f83f3 solid;color:#0a0a0a;font-family:Microsoft Yahei;font-size:11pt;font-weight:700;height:45px;line-height:1.3;margin:0;padding:0;padding-left:10px;text-align:left;vertical-align:middle">
                                                                        服务
                                                                    </th>
                                                                    <th class="top-orange" style="Margin:0;background:#fff;border-bottom:1px #f2f2f2 solid;border-top:2px #f60 solid;color:#0a0a0a;font-family:Microsoft Yahei;font-size:11pt;font-weight:700;height:45px;line-height:1.3;margin:0;padding:0;padding-left:10px;text-align:left;vertical-align:middle">
                                                                        状态
                                                                    </th>
                                                                    <th class="top-blue" style="Margin:0;background:#fff;border-bottom:1px #f2f2f2 solid;border-top:2px #1f83f3 solid;color:#0a0a0a;font-family:Microsoft Yahei;font-size:11pt;font-weight:700;height:45px;line-height:1.3;margin:0;padding:0;padding-left:10px;text-align:left;vertical-align:middle">
                                                                        扫描时间
                                                                    </th>
                                                                    <th class="top-orange" style="Margin:0;background:#fff;border-bottom:1px #f2f2f2 solid;border-top:2px #1f83f3 solid;color:#0a0a0a;font-family:Microsoft Yahei;font-size:11pt;font-weight:700;height:45px;line-height:1.3;margin:0;padding:0;padding-left:10px;text-align:left;vertical-align:middle">
                                                                        操作
                                                                    </th>
                                                                </tr>
                                                                </thead>
                                                                <tbody>
                                                                    %(table_tr)s
                                                                </tbody>
                                                            </table>
                                                            <table class="spacer" style="border-collapse:collapse;border-spacing:0;padding:0;text-align:left;vertical-align:top;width:100%(html)s">
                                                                <tbody>
                                                                <tr style="padding:0;text-align:left;vertical-align:top">
                                                                    <td height="20px" style="-moz-hyphens:auto;-webkit-hyphens:auto;Margin:0;background:#f4f4f4;border-collapse:collapse!important;color:#0a0a0a;font-family:Microsoft Yahei;font-size:20px;font-weight:400;hyphens:auto;line-height:20px;margin:0;mso-line-height-rule:exactly;padding:0;text-align:left;vertical-align:top;word-wrap:break-word">
                                                                        &#xA0;
                                                                    </td>
                                                                </tr>
                                                                </tbody>
                                                            </table>
                                                        </td>
                                                    </tr>
                                                    </tbody>
                                                </table>
                                            </td>
                                        </tr>
                                    </table>
                                    <table class="wrapper footer" align="center" style="background:#bec2c6;border-bottom:2px #1f83f3 solid;border-collapse:collapse;border-spacing:0;height:120px;padding:0;text-align:left;vertical-align:top;width:100%(html)s">
                                        <tr style="padding:0;text-align:left;vertical-align:top">
                                            <td class="wrapper-inner" style="-moz-hyphens:auto;-webkit-hyphens:auto;Margin:0;background:#bec2c6;border-collapse:collapse!important;color:#0a0a0a;font-family:Microsoft Yahei;font-size:16px;font-weight:400;hyphens:auto;line-height:1.3;margin:0;padding:0;text-align:left;vertical-align:top;word-wrap:break-word">
                                                <table align="center" class="container" style="Margin:0 auto;background:#fefefe;border-collapse:collapse;border-spacing:0;margin:0 auto;padding:0;text-align:inherit;vertical-align:top;width:1150px">
                                                    <tbody>
                                                    <tr style="padding:0;text-align:left;vertical-align:top">
                                                        <td style="-moz-hyphens:auto;-webkit-hyphens:auto;Margin:0;background:#bec2c6;border-collapse:collapse!important;color:#0a0a0a;font-family:Microsoft Yahei;font-size:16px;font-weight:400;hyphens:auto;line-height:1.3;margin:0;padding:0;text-align:left;vertical-align:top;word-wrap:break-word">
                                                            <table align="center" class="container" style="Margin:0 auto;background:#fefefe;border-collapse:collapse;border-spacing:0;margin:0 auto;padding:0;text-align:inherit;vertical-align:top;width:1150px">
                                                                <tbody>
                                                                <tr style="padding:0;text-align:left;vertical-align:top">
                                                                    <td style="-moz-hyphens:auto;-webkit-hyphens:auto;Margin:0;background:#bec2c6;border-collapse:collapse!important;color:#0a0a0a;font-family:Microsoft Yahei;font-size:16px;font-weight:400;hyphens:auto;line-height:1.3;margin:0;padding:0;text-align:left;vertical-align:top;word-wrap:break-word">
                                                                        <table class="row collapse" style="border-collapse:collapse;border-spacing:0;display:table;padding:0;position:relative;text-align:left;vertical-align:top;width:100%(html)s">
                                                                            <tbody>
                                                                            <tr style="padding:0;text-align:left;vertical-align:top">
                                                                                <th class="small-12 large-6 columns first" valign="middle" style="Margin:0 auto;background:#bec2c6;color:#0a0a0a;font-family:Microsoft Yahei;font-size:16px;font-weight:400;line-height:1.3;margin:0 auto;padding:0;padding-bottom:16px;padding-left:0;padding-right:0;text-align:left;width:100%(html)s">
                                                                                    <table style="border-collapse:collapse;border-spacing:0;padding:0;text-align:left;vertical-align:top;width:100%(html)s">
                                                                                        <tr style="padding:0;text-align:left;vertical-align:top">
                                                                                            <th style="Margin:0;background:#bec2c6;color:#0a0a0a;font-family:Microsoft Yahei;font-size:16px;font-weight:400;line-height:1.3;margin:0;padding:0;text-align:left">
                                                                                                <table class="spacer" style="border-collapse:collapse;border-spacing:0;padding:0;text-align:left;vertical-align:top;width:100%(html)s">
                                                                                                    <tbody>
                                                                                                    <tr style="padding:0;text-align:left;vertical-align:top">
                                                                                                        <td height="20px" style="-moz-hyphens:auto;-webkit-hyphens:auto;Margin:0;background:#bec2c6;border-collapse:collapse!important;color:#0a0a0a;font-family:Microsoft Yahei;font-size:20px;font-weight:400;hyphens:auto;line-height:20px;margin:0;mso-line-height-rule:exactly;padding:0;text-align:left;vertical-align:top;word-wrap:break-word">&#xA0;</td></tr>
                                                                                                    </tbody>
                                                                                                </table>
                                                                                                <p style="Margin:0;Margin-bottom:10px;background:#bec2c6;color:#0a0a0a;font-family:Microsoft Yahei;font-size:16px;font-weight:400;line-height:1.3;margin:0;margin-bottom:10px;padding:0;text-align:left">联系我们：
                                                                                                <p style="Margin:0;Margin-bottom:10px;background:#bec2c6;color:#0a0a0a;font-family:Microsoft Yahei;font-size:16px;font-weight:400;line-height:1.3;margin:0;margin-bottom:10px;padding:0;text-align:left">成员：xxx(xxx)、xxx(xxx)</p>
                                                                                                <p style="Margin:0;Margin-bottom:10px;background:#bec2c6;color:#0a0a0a;font-family:Microsoft Yahei;font-size:16px;font-weight:400;line-height:1.3;margin:0;margin-bottom:10px;padding:0;text-align:left">邮箱：xxx@xx.com、xxx@xx.com</p>
                                                                                            </th>
                                                                                        </tr>
                                                                                    </table>
                                                                                </th>
                                                                                <th class="small-12 large-6 columns last" valign="middle" style="Margin:0 auto;background:#bec2c6;color:#0a0a0a;font-family:Microsoft Yahei;font-size:16px;font-weight:400;line-height:1.3;margin:0 auto;padding:0;padding-bottom:16px;padding-left:0;padding-right:0;text-align:left;width:298px">
                                                                                    <table style="border-collapse:collapse;border-spacing:0;padding:0;text-align:left;vertical-align:top;width:100%(html)s">
                                                                                        <tr style="padding:0;text-align:left;vertical-align:top">
                                                                                            <th style="Margin:0;background:#bec2c6;color:#0a0a0a;font-family:Microsoft Yahei;font-size:16px;font-weight:400;line-height:1.3;margin:0;padding:0;text-align:left"></th>
                                                                                        </tr>
                                                                                    </table>
                                                                                </th>
                                                                            </tr>
                                                                            </tbody>
                                                                        </table>
                                                                    </td>
                                                                </tr>
                                                                </tbody>
                                                            </table>
                                                        </td>
                                                    </tr>
                                                    </tbody>
                                                </table>
                                            </td>
                                        </tr>
                                    </table>
                                </td>
                            </tr>
                        </table>
                    </center>
                </td>
            </tr>
        </table>
        <!-- prevent Gmail on iOS font size manipulation -->
        <div style="display:none;white-space:nowrap;font:15px courier;line-height:0">
            &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;
        </div>
        </body>
        </html>"""

    TABLE_TMPL = """
        <tr style="padding:0;text-align:left;vertical-align:top">
            <td style="-moz-hyphens:auto;-webkit-hyphens:auto;Margin:0;background:#fff;border-bottom:1px #f2f2f2 solid;border-collapse:collapse!important;color:#0a0a0a;font-family:Microsoft Yahei;font-size:11pt;font-weight:400;height:45px;hyphens:auto;line-height:1.3;margin:0;padding:0;padding-left:10px;text-align:left;vertical-align:middle;word-wrap:break-word">
                %(ip)s
            </td>
            <td style="-moz-hyphens:auto;-webkit-hyphens:auto;Margin:0;background:#fff;border-bottom:1px #f2f2f2 solid;border-collapse:collapse!important;color:#0a0a0a;font-family:Microsoft Yahei;font-size:11pt;font-weight:400;height:45px;hyphens:auto;line-height:1.3;margin:0;padding:0;padding-left:10px;text-align:left;vertical-align:middle;word-wrap:break-word">
                %(port)s
            </td>
            <td style="-moz-hyphens:auto;-webkit-hyphens:auto;Margin:0;background:#fff;border-bottom:1px #f2f2f2 solid;border-collapse:collapse!important;color:#0a0a0a;font-family:Microsoft Yahei;font-size:11pt;font-weight:400;height:45px;hyphens:auto;line-height:1.3;margin:0;padding:0;padding-left:10px;text-align:left;vertical-align:middle;word-wrap:break-word">
                %(service)s
            </td>
            <td style="-moz-hyphens:auto;-webkit-hyphens:auto;Margin:0;background:#fff;border-bottom:1px #f2f2f2 solid;border-collapse:collapse!important;color:#0a0a0a;font-family:Microsoft Yahei;font-size:11pt;font-weight:400;height:45px;hyphens:auto;line-height:1.3;margin:0;padding:0;padding-left:10px;text-align:left;vertical-align:middle;word-wrap:break-word">
                %(status)s
            </td>
            <td style="-moz-hyphens:auto;-webkit-hyphens:auto;Margin:0;background:#fff;border-bottom:1px #f2f2f2 solid;border-collapse:collapse!important;color:#0a0a0a;font-family:Microsoft Yahei;font-size:11pt;font-weight:400;height:45px;hyphens:auto;line-height:1.3;margin:0;padding:0;padding-left:10px;text-align:left;vertical-align:middle;word-wrap:break-word">
                %(time)s
            </td>
            <td style="-moz-hyphens:auto;-webkit-hyphens:auto;Margin:0;background:#fff;border-bottom:1px #f2f2f2 solid;border-collapse:collapse!important;color:#0a0a0a;font-family:Microsoft Yahei;font-size:11pt;font-weight:400;height:45px;hyphens:auto;line-height:1.3;margin:0;padding:0;padding-left:10px;text-align:left;vertical-align:middle;word-wrap:break-word">
                <a href="http://www.baidu.com" class="bt-blue" style="Margin:0;background:#0c90ff;border:none;border-radius:3px;color:#fff;display:inline-block;font-family:Helvetica,Arial,sans-serif;font-size:9pt;font-weight:400;height:20px;line-height:20px;margin:0;margin-left:5px;padding:5px;text-align:center;text-decoration:none;vertical-align:middle">&nbsp;确认修复&nbsp;</a><a href="http://www.baidu.com" class="bt-default" style="Margin:0;border:1px #f2f2f2 solid;border-radius:3px;color:#2199e8;display:inline-block;font-family:Helvetica,Arial,sans-serif;font-size:9pt;font-weight:400;height:20px;line-height:20px;margin:0;margin-left:5px;padding:5px;text-align:center;text-decoration:none;vertical-align:middle">忽略</a>
            </td>
        </tr>
        """

    def html_template(self, ip, status, deal):
        table_tr0 = ''
        sql = "select port,services,create_time from scan_port where ip = '%s' and status = '%s' and deal = '%s'" %(ip, status, deal)
        try:
            cursor.execute(sql)
            res = cursor.fetchall()
        except:
            res = []
            logging.info("Error: unable to fecth data")
        for raw in res:
            table_td = self.TABLE_TMPL % dict(
                ip = ip,
                port = raw[0],
                service = raw[1],
                status = "open",
                time = raw[2],
            )
            table_tr0 += table_td

        output = self.HTML_TMPL % dict(
            html = "%",
            time = time.strftime("%Y-%m-%d", time.localtime()),
            ip = ip,
            count = len(res),
            table_tr = table_tr0,
        )
        logging.info('write host %s html template to disk.' % ip)
        with open(os.path.dirname(os.path.realpath(__file__)) + "/%s.html" %ip, 'wb') as f:
            f.write(output)
        return output

def nmScan(host, portrange, whitelist = [80, 443]):
    nm = nmap.PortScanner()
    html = Template_html()
    logging.info('scan the ports for host %s' % host)
    tmp = nm.scan(host, portrange, arguments='-sV --host-timeout 10m')
    try:
        ports = tmp['scan'][host]['tcp'].keys()
        for port in ports:
            status = tmp['scan'][host]['tcp'][port]['state']
            service = tmp['scan'][host]['tcp'][port]['name']
            if port in whitelist:
                deal = 'YES'
            else:
                deal = 'NO'
            try:
                cursor.execute("insert into scan_port values (NULL, %s, %s, %s, %s, %s, NULL)",
                               (host, port, status, service, deal))
                conn.commit()
            except:
                conn.rollback()

        logging.info('To get host %s html template.' % host)
        rs = html.html_template(host, 'open', 'NO')
        sendemail(rs)

    except KeyError, e:
        logging.info("%s 扫描结果正常，无暴漏端口" % host)

def main(ip_list, port_list):
    p = Pool(32)
    for ip in ip_list:
        p.apply_async(nmScan, args=(ip, port_list,))

    logging.info('Task begining,Waiting for all subprocesses done...')
    start_time = time.strftime("%H:%M:%S", time.localtime())
    print start_time

    p.close()
    p.join()
    cursor.close()
    conn.close()

    end_time = time.strftime("%H:%M:%S", time.localtime())
    print start_time, end_time


if __name__ == '__main__':
    # ips = get_iplist()  #通过接口获取CMDB上所有主机列表
    # print len(ips), ips
    ips = ['xxx.xxx.xxx.xxx','xxx.xxx.xxx.xxx']
    ports = '1,2'   #or ports = '1-65535'
    if check_port(ports):
        main(ips, ports)
    else:
        logging.error('invaild port format.')


