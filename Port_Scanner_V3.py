# -*- coding:utf-8 -*-

import masscan, nmap, re, pycurl, json, time, pymysql, logging, smtplib, os, numpy
from email.mime.text import MIMEText
from email.header import Header
from multiprocessing import Queue, cpu_count, Process
from StringIO import StringIO

'''
    1.masscan只扫描出open的端口，速度快，扫描准，但是没有服务版本名。
    2.nmap扫描慢，设置速率太大可能被限制或者设置超时都会出现扫描被跳过，报tcp的错误。
    解决：先用masscan扫描。完成之后nmap指定端口范围扫描得到版本号。
'''

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

# PyMySQL连接操作的封装类
class ConDb():
    def openClose(fun):
        def run(self, sql=None):
            #创建数据库连接
            db = pymysql.connect(host='localhost', port=3306, user='root', passwd='root', db="test", charset="utf8")
            #创建游标
            cursor = db.cursor()
            try:
                #使用装饰器，fun是装饰器的参数。。。运行sql语句
                cursor.execute(fun(self,sql))
                #得到返回值
                li = cursor.fetchall()
                #提交事务
                db.commit()
            except Exception as e:
                li = []
                #如果出现错误，回滚事务
                db.rollback()
                #打印报错信息
                logging.info('运行'+str(fun)+'方法时出现错误，错误代码：%s' %e)
            finally:
                #关闭游标和数据库连接
                cursor.close()
                db.close()
            try:
                #返回sql执行信息
                return li
            except:
                logging.info('没有得到返回值，请检查代码，该信息出现在ConDb类中的装饰器方法')
        return run

    #runSql 未经封装，可直接运行sql，调用该方法执行sql
    @openClose
    def runSql(self, sql):
        logging.info('调试专用，显示sql：' + sql)
        return sql
    #切换数据库
    def tab(self, db):
        sql = 'use {}'.format(db)
        self.runSql(sql)
    #创建数据库
    def create_DB(self,name):
        sql = '''CREATE DATABASE {}'''.format(name)
        self.runSql(sql)
    #创建表
    def create_TB(self, dbname='', tbname='', enging="InnoDB",charset="utf8" ,**kwargs):
        '''
        :param dbname:  数据库名称
        :param tbname:  表名称
        :param enging:  数据引擎
        :param charset: 默认编码
        :param kwargs: 新建的列 和 索引
        :return:
        PRIMARY="KEY('id')"  设置主键索引 id 替换成要设置成主键的列
        UNIQUE = "KEY `name` (`name`)"  设置上下文索引，name 可替换
        '''
        self.runSql('''use {}'''.format(dbname))
        li = []
        for k, v in kwargs.items():
            li.append('{} {}'.format(k, v))
        sql = '''
            CREATE TABLE `{}` (
                "{}"
            ) ENGINE={}  DEFAULT CHARSET={}

            '''.format(tbname, li, enging, charset)
        sql = re.sub(r"""\'|\"|\[|\]""", '', sql)
        self.runSql(sql)
    # example:
    # con.create_TB('test','scan_port',id="int(11)",name="varchar(255)",PRIMARY="KEY('id')" ,UNIQUE = "KEY `name` (`name`)" )
    # create table scan_port(id int(11) not null auto_increment primary key,ip varchar(20) not null,port int(6) not null,status varchar(20),services varchar(255),deal varchar(20),create_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP);
    # conn = pymysql.connect(host='localhost',port=3306,user='root',passwd='root',db="test")
    # cursor = conn.cursor()
    #插入数据
    def insert_TB(self, tableName, items, *args):
        '''
        :param tableName:  插入的表名
        :param items: 数据源，是一个不嵌套的list
        :param args:  指定列，不填写不指定
        :return:
        '''
        args = str(args)
        args = re.sub("'",'',args)

        items=re.sub(r"\[|\]",'',str(items))
        if items:
            sql='''
            INSERT INTO {} {} VALUES ({})
            '''.format(tableName,args,items)
        else:
            sql = '''
            INSERT  INTO {}  VALUES ({})
            '''.format(tableName, items)
        self.runSql(sql)

    def update_TB(self, tableName, items, *args):
        '''
        :param tableName:  更新的表名
        :param items: 更新数据，是一个字符串
        :param args:  条件数据，是一个字符串，不填写更新全部
        :return:
        '''
        args = str(args)
        args = re.sub(",|'|\(|\)|u'",'',args)

        if args:
            sql='''
            UPDATE {} SET {} WHERE {}
            '''.format(tableName,items,args)
        else:
            sql = '''
            UPDATE {} SET {}
            '''.format(tableName, items)
        self.runSql(sql)

# 生成html格式的模板邮件内容
class Template_html(object):
    """html报告"""
    HTML_TMPL = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>服务器端口安全扫描报告</title>
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
                                                                                    <h2 class="text-center mail-title" style="Margin:0;Margin-bottom:10px;color:#fff;font-family:Microsoft Yahei;font-size:18pt;font-weight:400;line-height:1.3;margin:0;margin-bottom:10px;padding:0;text-align:center;word-wrap:normal">服务器端口漏洞预警通知</h2>
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
                                                                这是一封服务器端口漏洞提醒信，为了提醒您及时修复漏洞，我们发送此邮件。
                                                            </p>
                                                            <p class="text-body mail-dec-text" style="Margin:0;Margin-bottom:10px;background:#f4f4f4;color:#0a0a0a;font-family:Microsoft Yahei;font-size:11pt;font-weight:400;line-height:30px;margin:0;margin-bottom:0;padding:0;text-align:left;text-indent:30px;vertical-align:middle">
                                                                您名下 <strong style="color:red">%(ip)s</strong> 主机共存在 <strong style="color:red">%(count)s</strong> 个漏洞，<span style="color:#E7505A">请及时检查修复端口漏洞并点击确认修复按钮进行确认。</span>
                                                            </p>
                                                            <table width="100%(html)s" class="layout-table" cellspacing="0" cellpadding="0" border="0" style="background:#f4f4f4;border-collapse:collapse;border-spacing:0;padding:0;text-align:left;vertical-align:top">
                                                                <tbody style="background:#f4f4f4">
                                                                <tr style="background:#f4f4f4;padding:0;text-align:left;vertical-align:top">
                                                                    <th style="Margin:0;background:#f4f4f4;color:#0a0a0a;font-family:Microsoft Yahei;font-size:16px;font-weight:400;height:30px;line-height:1.3;margin:0;padding:0;text-align:right" valign="top">
                                                                        <a href="http://xxx.xxx.xxx.xxx:5000/security/%(ip)s/%(ports)s" class="bt-default" style="Margin:0;background:#0c90ff;border:1px #f2f2f2 solid;border-radius:3px;color:#fff;display:inline-block;font-family:Helvetica,Arial,sans-serif;font-size:9pt;font-weight:400;height:20px;line-height:20px;margin:0;margin-left:5px;padding:5px;text-align:center;text-decoration:none;vertical-align:middle">&nbsp;批量修复&nbsp;</a>
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
                                                            <div style="overflow-y: scroll;max-height: 300px;">
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
                                                                        研发负责人
                                                                    </th>
                                                                    <th class="top-orange" style="Margin:0;background:#fff;border-bottom:1px #f2f2f2 solid;border-top:2px #f60 solid;color:#0a0a0a;font-family:Microsoft Yahei;font-size:11pt;font-weight:700;height:45px;line-height:1.3;margin:0;padding:0;padding-left:10px;text-align:left;vertical-align:middle">
                                                                        运维负责人
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
                                                            </div>
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
                                                                                                <p style="Margin:0;Margin-bottom:10px;background:#bec2c6;color:#0a0a0a;font-family:Microsoft Yahei;font-size:16px;font-weight:400;line-height:1.3;margin:0;margin-bottom:10px;padding:0;text-align:left">运维：username(xxx)</p>
                                                                                                <p style="Margin:0;Margin-bottom:10px;background:#bec2c6;color:#0a0a0a;font-family:Microsoft Yahei;font-size:16px;font-weight:400;line-height:1.3;margin:0;margin-bottom:10px;padding:0;text-align:left">邮箱：xxx@xx.com</p>
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
                %(tech_admin)s
            </td>
            <td style="-moz-hyphens:auto;-webkit-hyphens:auto;Margin:0;background:#fff;border-bottom:1px #f2f2f2 solid;border-collapse:collapse!important;color:#0a0a0a;font-family:Microsoft Yahei;font-size:11pt;font-weight:400;height:45px;hyphens:auto;line-height:1.3;margin:0;padding:0;padding-left:10px;text-align:left;vertical-align:middle;word-wrap:break-word">
                %(sysop_admin)s
            </td>
            <td style="-moz-hyphens:auto;-webkit-hyphens:auto;Margin:0;background:#fff;border-bottom:1px #f2f2f2 solid;border-collapse:collapse!important;color:#0a0a0a;font-family:Microsoft Yahei;font-size:11pt;font-weight:400;height:45px;hyphens:auto;line-height:1.3;margin:0;padding:0;padding-left:10px;text-align:left;vertical-align:middle;word-wrap:break-word">
                %(time)s
            </td>
            <td style="-moz-hyphens:auto;-webkit-hyphens:auto;Margin:0;background:#fff;border-bottom:1px #f2f2f2 solid;border-collapse:collapse!important;color:#0a0a0a;font-family:Microsoft Yahei;font-size:11pt;font-weight:400;height:45px;hyphens:auto;line-height:1.3;margin:0;padding:0;padding-left:10px;text-align:left;vertical-align:middle;word-wrap:break-word">
                <a href="http://xxx.xxx.xxx.xxx:5000/security/%(ip)s/%(port)s" class="bt-blue" style="Margin:0;background:#0c90ff;border:none;border-radius:3px;color:#fff;display:inline-block;font-family:Helvetica,Arial,sans-serif;font-size:9pt;font-weight:400;height:20px;line-height:20px;margin:0;margin-left:5px;padding:5px;text-align:center;text-decoration:none;vertical-align:middle">&nbsp;确认修复&nbsp;</a><a href="http://xxx.xxx.xxx.xxx:5000/ignore/%(ip)s/%(port)s" class="bt-default" style="Margin:0;border:1px #f2f2f2 solid;border-radius:3px;color:#2199e8;display:inline-block;font-family:Helvetica,Arial,sans-serif;font-size:9pt;font-weight:400;height:20px;line-height:20px;margin:0;margin-left:5px;padding:5px;text-align:center;text-decoration:none;vertical-align:middle">忽略</a>
            </td>
        </tr>"""

    def html_template(self, ip, status, deal, conn):
        table_tr0 = ''
        sql = "select distinct port,services,create_time from scan_port where ip = '%s' and status = '%s' and deal = '%s'" % (
        ip, status, deal)
        res = conn.runSql(sql)
        if res:
            info_dict = get_hostuser_info(ip)
            htmlports = ','.join(str(p[0]) for p in res)
            for raw in res:
                table_td = self.TABLE_TMPL % dict(
                    ip = ip,
                    port = raw[0],
                    service = raw[1].encode('utf-8'),
                    status = "open",
                    time = raw[2],
                    tech_admin = info_dict['tech_admin'].encode('utf-8'),
                    sysop_admin = info_dict['sysop_admin'].encode('utf-8'),
                )
                table_tr0 += table_td

            output = self.HTML_TMPL % dict(
                html = "%",
                time = time.strftime("%Y-%m-%d", time.localtime()),
                ip = ip,
                count = len(res),
                table_tr = table_tr0,
                ports = htmlports,
            )

            logging.info('write host %s html template to disk.' % ip)
            with open(os.path.dirname(os.path.realpath(__file__)) + "/templates/%s.html" % ip, 'wb') as f:
                f.write(output)
            rs = [output, info_dict['user_email']]
        else:
            rs = []
        return rs

# 发送邮件函数
def sendemail(content, user=['xxx@xx.com']):
    sender = 'xxx@xx.com'
    receiver = user
    subject = '[这是一封测试邮件]服务器端口扫描报告'
    smtpserver = 'xx.xx.com'
    smtpuser = 'xxx@xx.com'
    smtppass = 'xxxxxx'

    # 中文需参数'utf-8'，单字节字符不需要
    msg = MIMEText(content,'html','utf-8')
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
        logging.info(e)

# 请求url并返回json格式结果的函数
def request_curl(url):
    buffer = StringIO()
    # indexfile = open(os.path.dirname(os.path.realpath(__file__)) + "/content.txt", "wb")
    c = pycurl.Curl()  # 创建一个curl对象
    c.setopt(pycurl.URL, url)
    c.setopt(pycurl.SSL_VERIFYPEER, 0)
    c.setopt(pycurl.SSL_VERIFYHOST, 0)
    # 连接超时时间,5秒
    c.setopt(pycurl.CONNECTTIMEOUT, 5)

    # 下载超时时间,20秒
    c.setopt(pycurl.TIMEOUT, 60)
    c.setopt(pycurl.FORBID_REUSE, 1)
    c.setopt(pycurl.MAXREDIRS, 1)
    c.setopt(pycurl.NOPROGRESS, 1)
    c.setopt(pycurl.DNS_CACHE_TIMEOUT, 30)

    # c.setopt(pycurl.WRITEDATA, indexfile)
    c.setopt(pycurl.WRITEDATA, buffer)
    try:
        c.perform()
    except Exception, e:
        logging.info("connecion error:" + str(e))
    finally:
        # indexfile.close()
        c.close()

    body = json.loads(buffer.getvalue())
    # file_object = open(os.path.dirname(os.path.realpath(__file__)) + "/content.txt")
    # try:
    #     file_context = file_object.read()
    #     body = json.loads(file_context)
    # finally:
    #     file_object.close()

    return body

# 解析json格式数据，获取想要的数据列表
def pars_body(body):
    i = 0
    iplist = []
    while i < len(body['object']['lists']):
        ip = body['object']['lists'][i]['tel_ip']
        if ip != None:
            if "," in ip:   #处理有vip或者多ip的情况
                ip = ip.split(',')[0]
            iplist.append(ip)
        i += 1

    return iplist

# 根据IP获取主机对应的负责人信息和邮箱地址
def get_hostuser_info(host):
    url = 'http://xxx/list.do?ips=%s' % (host)
    info = request_curl(url)['object']['lists']
    info_dict = {}
    if info:
        info_dict['tech_admin'] = info[0]['tech_admin'].split(',')[0]
        info_dict['sysop_admin'] = info[0]['sysop_admin'].split(',')[0]
        info_dict['dw_tech_admin'] = info[0]['dw_tech_admin'].split(',')[0]
        info_dict['dw_sysop_admin'] = info[0]['dw_sysop_admin'].split(',')[0]
        info_dict['tech_admin_email'] = info_dict['dw_tech_admin'].split('dw_')[1] + "@xx.com"
        info_dict['sysop_admin_email'] = info_dict['dw_sysop_admin'].split('dw_')[1] + "@xx.com"
        info_dict['user_email'] = [info_dict['tech_admin_email'],info_dict['sysop_admin_email']]
    else:
        logging.info(host + str(info))

    return info_dict

# 检查扫描的端口是否符合规则，支持连续和不连续的方式扫描，如：1-65535或80,443
def check_port(portrange):
    try:
        p1 = re.compile(r'(\d+)-(\d+)$')
        p2 = re.compile(r'((\d+,)+)(\d+)$')
        p3 = re.compile(r'(\d|\d{2}|\d{3}|\d{4}|\d{5})$')
        if p1.match(portrange):
            return True
        elif p2.match(portrange):
            return True
        elif p3.match(portrange):
            return True
        else:
            return False
    except Exception as err:
        logging.error(err)

# nmap扫描主机端口执行函数，将结果记录到数据库，nmap扫描UDP端口特别慢
def nmScan(host, portrange):
    nm = nmap.PortScanner()
    logging.info('nmap scan the port %s for host %s' % (portrange, host))
    tmp = []
    attempts = 0
    success = False
    # 如果出现异常重试，最多重试三次
    while attempts < 3 and not success:
        try:
            tmp = nm.scan(host, portrange, arguments='-sV -Pn -host-timeout 20m')  # 禁ping快速扫描，设置超时时间
            success = True
        except:
            attempts += 1
            if attempts == 3:
                break

    return tmp

# masscan扫描主机端口执行函数，将结果记录到数据库，速度比nmap要快许多，但是不能扫描端口服务版本
def masScan(host, portrange, whitelist = [80, 443]):
    mas = masscan.PortScanner()
    html = Template_html()
    conn = ConDb()
    logging.info('masscan scan the ports for host %s' % host)

    masports = ""
    attempts = 0
    success = False
    # 如果出现异常重试，最多重试三次
    while attempts < 3 and not success:
        try:
            mastmp = mas.scan(host, portrange, arguments='--rate=1000 --interface eth0 --router-mac 48-7a-da-78-f6-xx')
            logging.info(mastmp)
            success = True
            masports = str(mastmp['scan'][host]['tcp'].keys()).replace("[", "").replace("]", "").replace(", ", ",")
        except:
            attempts += 1
            if attempts == 3:
                break

    tmp = nmScan(host, masports)
    try:
        ports = tmp['scan'][host]['tcp'].keys()
        for port in ports:
            status = tmp['scan'][host]['tcp'][port]['state']
            service = tmp['scan'][host]['tcp'][port]['name']
            if port in whitelist:
                deal = 'YES'
            else:
                deal = 'NO'
            # 扫描出来的端口在入库之前先查询是否有记录，如果存在则更新，如果不存在则添加。
            # 以此多次执行全量扫描解决masscan少部分漏扫和nmap偶尔没有返回的情况。
            query_sql = "select ip from scan_port where ip = '%s' and port = '%s'" %(host, port)
            rs = conn.runSql(query_sql.encode('utf-8'))
            if rs:
                set = 'status = \"%s\", services = \"%s\", deal = \"%s\"' % (status, service, deal)
                where = 'ip = \"%s\" and port = \"%s\"' % (host, port)
                conn.update_TB('scan_port', set, where)
            else:
                insert_sql = [host, port, status, service, deal]
                conn.insert_TB('scan_port', insert_sql, 'ip', 'port', 'status', 'services', 'deal')

        logging.info('To get host %s html template.' % host)
        rs = html.html_template(host, 'open', 'NO', conn)
        # if rs:
        #     sendemail(rs[0], rs[1])
        # else:
        #     pass
    except Exception, e:
        logging.info("%s扫描结果正常，无暴漏端口: %s" % (host,e))

def task_run(q, port_list):
    while True:
        if not q.empty():
            masScan(q.get(), port_list)
        else:
            break

# gevent协程函数
def coroutine(q, port_list):
    # 导入补丁
    from gevent import monkey;monkey.patch_all()
    import gevent

    task = []

    for i in range(10):
        task.append(gevent.spawn(task_run, q, port_list))

    gevent.joinall(task)

# 主函数，多进程并行执行任务
def main(ip_list, port_list):
    cpu_num = cpu_count()
    names = locals()
    q = Queue()

    for i in ip_list:
        q.put(i.encode('utf-8'))

    for i in range(cpu_num):
        names['p' + str(i)] = Process(target=coroutine, args=(q, port_list,))
        names.get('p' + str(i)).start()

    logging.info('Task begining,Waiting for all subprocesses done...')
    start_time = time.strftime("%H:%M:%S", time.localtime())
    logging.info(start_time)

    for i in range(cpu_num):
        names.get('p' + str(i)).join()

    end_time = time.strftime("%H:%M:%S", time.localtime())
    logging.info(start_time + "--" + end_time)


# 执行入口函数
if __name__ == '__main__':
    ips = []
    '''
    根据cmdb业务模块的id获取全量公网电信IP地址：
    '''
    for id in ['000000022737','000000034830','000000032667','000000026895','000000024653',\
               '000000032678','000000024555','000000033087','000000033088','000000033639']:
        url = 'http://xxx/list.do?buss=%s&page=1' %(id)
        count = request_curl(url)['object']['count']
        url = 'http://xxx/list.do?buss=%s&page=1&displayRecord=%s' %(id, count)
        # 合并数组
        ips = numpy.r_[ips, pars_body(request_curl(url))]

    # print len(ips)

    ports = '1-65535'
    logging.info("start...")
    if check_port(ports):
        main(ips, ports)
    else:
        logging.error('invaild port format.')

