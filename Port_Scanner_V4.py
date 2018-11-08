# -*- coding:utf-8 -*-

import masscan, nmap, re, pycurl, json, time, pymysql, logging, smtplib, os, requests, md5
from email.mime.text import MIMEText
from email.header import Header
from multiprocessing import Queue, cpu_count, Process
from StringIO import StringIO

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
    EMAIL_TMPL = '''
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
                                                                    您名下 <strong style="color:red">%(gamename)s</strong> 这款游戏共存在 <strong style="color:red">%(count)s</strong> 个端口漏洞，<span style="color:#E7505A">请及时登录以下地址检查修复端口漏洞并点击已修复按钮进行确认。</span>
                                                                </p>
    															<hr/>
    															<p class="text-body mail-dec-text" style="Margin:0;Margin-bottom:10px;background:#f4f4f4;color:#0a0a0a;font-family:Microsoft Yahei;font-size:11pt;font-weight:400;line-height:30px;margin:0;margin-bottom:0;padding:0;text-align:left;text-indent:30px;vertical-align:middle">
                                                                    <span style="color:#E7505A">请点击链接处理：
    																<a href="http://xxxxxx/dev/serverSecurityRecord/index.do?projectId=%(gameid)s">%(gamename)s</a></span>
                                                                </p>
    															<hr/>
    															<p class="text-body mail-dec-text" style="Margin:0;Margin-bottom:10px;background:#f4f4f4;color:#0a0a0a;font-family:Microsoft Yahei;font-size:11pt;font-weight:400;line-height:30px;margin:0;margin-bottom:0;padding:0;text-align:left;text-indent:30px;vertical-align:middle">
    																<span style="color:#E7505A">说明：</span>
                                                                </p>
    															<p class="text-body mail-dec-text" style="Margin:0;Margin-bottom:10px;background:#f4f4f4;color:#0a0a0a;font-family:Microsoft Yahei;font-size:11pt;font-weight:400;line-height:30px;margin:0;margin-bottom:0;padding:0;text-align:left;text-indent:30px;vertical-align:middle">
    																点击链接登录到运维管理系统中查看扫描到的对外开放的端口，由于对外开放，所以增加服务器安全风险。
                                                                </p>
    															<p class="text-body mail-dec-text" style="Margin:0;Margin-bottom:10px;background:#f4f4f4;color:#0a0a0a;font-family:Microsoft Yahei;font-size:11pt;font-weight:400;line-height:30px;margin:0;margin-bottom:0;padding:0;text-align:left;text-indent:30px;vertical-align:middle">
    																强烈建议添加开放端口的iptable白名单，提高服务器端口安全性。
                                                                </p>

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
                                                                                                    <p style="Margin:0;Margin-bottom:10px;background:#bec2c6;color:#0a0a0a;font-family:Microsoft Yahei;font-size:16px;font-weight:400;line-height:1.3;margin:0;margin-bottom:10px;padding:0;text-align:left">游戏部运维：xxxxxx(xxxxxx)</p>
                                                                                                    <p style="Margin:0;Margin-bottom:10px;background:#bec2c6;color:#0a0a0a;font-family:Microsoft Yahei;font-size:16px;font-weight:400;line-height:1.3;margin:0;margin-bottom:10px;padding:0;text-align:left">xxxxxx@xxxxxx.com</p>
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
            </html>
            '''

    def email_temp(self, t, gameid, gamename, count):
        output = self.EMAIL_TMPL % dict(
            html = "%",
            time = time.strftime("%Y-%m-%d", time.localtime(int(t))),
            gameid = gameid,
            gamename = gamename,
            count = count,
        )
        with open(os.path.dirname(os.path.realpath(__file__)) + "/templates/email_%s.html" % gamename, 'wb') as f:
            f.write(output)

        return output

# 发送邮件函数
def sendemail(content, user=['xxxxxx@xxxxxx.com']):
    sender = 'xxxxxx@xxxxxx.com'
    receiver = user
    subject = '[这是一封测试邮件]服务器端口扫描报告'
    smtpserver = 'xxxxxx'
    smtpuser = 'xxxxxx@xxxxxx.com'
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
def request_curl(*args):
    timestamp = str(int(time.time()))
    m1 = md5.new()
    m1.update(timestamp + "bbb")
    sign = m1.hexdigest()
    header = {
        "Content-Type": "application/json",
        "timestamp": timestamp,
        "sign": sign
    }

    if len(args) == 1:
        res = requests.post(args[0], headers=(header)).json()
    else:
        res = requests.post(args[0], data=json.dumps(args[1]) , headers=(header)).json()

    return res

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
    conn = ConDb()
    logging.info('masscan scan the ports for host %s' % host)

    masports = ""
    attempts = 0
    success = False
    # 如果出现异常重试，最多重试三次
    while attempts < 3 and not success:
        try:
            mastmp = mas.scan(host, portrange, arguments='--rate=1000 --interface eth0 --router-mac 48-7a-da-78-f6-ae')
            logging.info(mastmp)
            success = True
            masports = str(mastmp['scan'][host]['tcp'].keys()).replace("[", "").replace("]", "").replace(", ", ",")
        except:
            attempts += 1
            if attempts == 3:
                break

    tmp = nmScan(host, masports)
    logging.info('=====%s' % tmp)
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

        logging.info('Scan host %s end.' % host)

    except Exception, e:
        logging.info("%s异常: %s" % (host,e))

def task_run(q, port_list):
    while True:
        if not q.empty():
            ip = q.get()
            if ip != "":
                masScan(ip, port_list)
        else:
            break

# gevent协程函数
def coroutine(q, port_list):
    # 导入补丁gevent是第三方库，通过greenlet实现协程，其基本思想是：
    # 当一个greenlet遇到IO操作时，比如访问网络，就自动切换到其他的greenlet，等到IO操作完成，再在适当的时候切换回来继续执行。由于IO操作非常耗时，经常使程序处于等待状态，有了gevent为我们自动切换协程，就保证总有greenlet在运行，而不是等待IO。
    # 由于切换是在IO操作时自动完成，所以gevent需要修改Python自带的一些标准库，它会自动替换你原来的thread、socket、time、multiprocessing等代码，全部变成gevent框架。这一切都是由gevent自动完成的。注意这个patch是在所有module都import了之后再打，否则没有效果。这一过程在启动时通过monkey patch完成.
    from gevent import monkey;monkey.patch_all()
    import gevent

    task = []

    for i in range(10):
        task.append(gevent.spawn(task_run, q, port_list))

    gevent.joinall(task)

# 主函数，多进程并行执行任务
def main(ip_list, port_list):
    cpu_num = cpu_count()
    if len(ip_list) < cpu_num:
        p_num = len(ip_list)
    else:
        p_num = cpu_num

    names = locals()
    q = Queue()

    for i in ip_list:
        q.put(i.encode('utf-8'))

    for i in range(p_num):
        names['p' + str(i)] = Process(target=coroutine, args=(q, port_list,))
        names.get('p' + str(i)).start()

    logging.info('Task begining,Waiting for all subprocesses done...')
    start_time = time.strftime("%H:%M:%S", time.localtime())

    for i in range(p_num):
        names.get('p' + str(i)).join()

    end_time = time.strftime("%H:%M:%S", time.localtime())
    logging.info(start_time + "--" + end_time)

def shangbao(batchNo, gameId, gameName, ip_list, email_user):
    conn = ConDb()
    html = Template_html()
    data = []
    scanData = []
    url3 = "http://xxxxxx/api/scanData/report.do"
    if len(ip_list) == 1:
        query_sql = "select ip,port,services,create_time from scan_port where ip = '{}' and deal = 'NO'".format(ip_list[0])
    else:
        query_sql = "select ip,port,services,create_time from scan_port where ip in {} and deal = 'NO'".format(tuple(ip_list))
    rs = conn.runSql(query_sql.encode('utf-8'))
    if rs:
        for raw in rs:
            one = {
                    "type": 1,
                    "ip": raw[0].encode('utf-8'),
                    "port": int(raw[1]),
                    "service": raw[2].encode('utf-8'),
                    "time": int(time.mktime(raw[3].timetuple()))
                }
            scanData.append(one)

        d = {
            "gameId": gameId,
            "gameName": gameName,
            "scanData": scanData
        }

        data.append(d)

        body = {
            "batchNo": batchNo,
            "data": data
        }

        # 设置每天扫描10次，每次扫描都上报数据，但是每天只发送一次邮件，用文件锁来控制次数
        with open(os.path.dirname(os.path.realpath(__file__)) + "/templates/lock.txt", 'r') as f:
            num = int(f.read())

        if num == 10:
            res = html.email_temp(batchNo, gameId, gameName, len(scanData))
            # sendemail(res, email_user)
            sendemail(res)
        else:
            pass

        return request_curl(url3, body)
    else:
        return json.dumps({
                    "status": 200,
                    "message": None,
                    "data": None
                })


# 执行入口函数
if __name__ == '__main__':
    batchNo = str(int(time.time()))
    
    # 初始化时templates/lock.txt文件设置为“0”
    with open(os.path.dirname(os.path.realpath(__file__)) + "/templates/lock.txt", 'r') as f:
        num = int(f.read())

    with open(os.path.dirname(os.path.realpath(__file__)) + "/templates/lock.txt", 'w') as f:
        if num <= 9:
            num += 1
            f.write("%s" % (str(num)))
        else:
            f.write("1")

    url1 = "http://xxxxxx/api/game/listAllAvailableGames.do"

    all_info = request_curl(url1)
    # print all_info['data']
    #
    all = []
    for i in range(0, len(all_info['data'])):
        url2 = "http://xxxxxx/api/game/listServers.do?gameId=%s" % all_info['data'][i]['gameId']
        email_user = [all_info['data'][i]["operatorEmail"].encode('utf-8'), all_info['data'][i]["maintainerEmail"].encode('utf-8')]
        gameId = all_info['data'][i]['gameId']
        gameName = all_info['data'][i]['gameName'].encode('utf-8')
        one_info = request_curl(url2)
        # print one_info
        ip_list = []
        for i in one_info['data']['serverData']:
            ip_list.append(i['ip'].encode('utf-8'))

        logging.info(ip_list)
        if ip_list == []:
            pass
        else:
            all.append([gameId, gameName, ip_list, email_user])

    all_ip = []
    for i in all:
        all_ip += i[2]

    main(all_ip, "1-65535")

    for i in all:
        gameId, gameName, ip_list, email_user = i[0], i[1], i[2], i[3]
        rs = shangbao(batchNo, gameId, gameName, ip_list, email_user)
        logging.info(rs)

        logging.info("over %s" % gameName)


