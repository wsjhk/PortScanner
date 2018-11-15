# -*- coding:utf-8 -*-

import pandas, masscan, os, json, time, md5
from functools import wraps
from Port_Scanner_V3 import ConDb
from flask import Flask, render_template, request

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

con = ConDb()

#通过双方约定盐值的方式验证token实现授权
def token_auth(func):
    @wraps(func)
    def wrapper(*arg, **kwargs):
        timestamp = request.headers.get("timestamp")
        sign = request.headers.get("sign")
        mytime = str(int(time.time()))
        m1 = md5.new()
        m1.update(timestamp + "bbb")
        if sign == m1.hexdigest():
            if int(mytime) > int(timestamp) + 24 * 60 * 60:
                data = {"status": 1, "results": "Token is expired."}
                return json.dumps(data)
            else:
                return func(*arg, **kwargs)
        else:
            data = {"status": 1, "results": "Token validate failed."}
            return json.dumps(data)
    return wrapper

# 使用pandas生成html表格的函数
def convertToHtml(result, title):
    d = {}
    index = 0
    for t in title:
        rs = []
        for v in result:
            rs.append(v[index])
        d[t] = rs
        index = index + 1
    df = pandas.DataFrame(d)
    df = df[title]
    h = df.to_html(index=False)
    return h

# 确认修复按钮和批量修复按钮调用的api接口入口
@app.route('/security/<string:ip>/<string:port>', methods=['GET', 'POST'])
@token_auth
def update(ip, port):
    mas = masscan.PortScanner()
    attempts = 0
    tmp = []
    success = False
    # 如果出现异常重试，最多重试三次
    while attempts < 3 and not success:
        try:
            tmp = mas.scan(ip, port, arguments='--rate=10000 --wait 0 --interface eth0 --router-mac 48-7a-da-78-f6-ae', sudo=True)
            success = True
        except:
            attempts += 1
            if attempts == 3:
                break
    try:
        if "," in port:
            ps = port.split(',')
        else:
            ps = [int(port)]

        ports = tmp['scan'][ip]['tcp'].keys()

        for p in ps:
            if int(p) not in ports:
                set = 'status = \"%s\", deal = \"%s\"' % ('closed', 'YES')
                where = 'ip = \"%s\" and port = \"%s\"' % (ip, p)
                con.update_TB('scan_port', set, where)

        for p in ports:
            state = tmp['scan'][ip]['tcp'][p]['state']
            if state != 'open':
                set = 'status = \"%s\", deal = \"%s\"' % (state, 'YES')
            else:
                set = 'status = \"%s\", deal = \"%s\"' % (state, 'NO')

            where = 'ip = \"%s\" and port = \"%s\"' % (ip, p)
            con.update_TB('scan_port', set, where)
    except Exception, e:
        print e

    sql = "select distinct ip,port,services,status,deal,create_time from scan_port where ip = '%s' and port in (%s)" % (
        ip, port)
    res = con.runSql(sql.encode('utf-8'))
    title = [u'IP地址', u'端口', u'服务', u'状态', u'是否修复', u'更新时间']

    return convertToHtml(res, title)

# 忽略按钮调用的api接口入口
@app.route('/ignore/<string:ip>/<string:port>', methods=['GET', 'POST'])
@token_auth
def ignore(ip, port, time):
    set = 'deal = \"%s\"' % ('ignore')
    where = 'ip = \"%s\" and port = \"%s\"' % (ip, port)
    con.update_TB('scan_port', set, where)

    sql = "select distinct ip,port,services,status,deal,create_time from scan_port where ip = '%s' and port in (%s)" % (
        ip, port)
    res = con.runSql(sql.encode('utf-8'))
    title = [u'IP地址', u'端口', u'服务', u'状态', u'是否修复', u'更新时间']

    return convertToHtml(res, title)

@app.route('/all', methods=['GET'])
def get_all_html():
    sql = "select distinct ip from scan_port order by ip limit 5000"
    rs = con.runSql(sql.encode('utf-8'))

    res = u'''
        <table border="1" class="dataframe">
          <thead>
            <tr style="text-align: right;">
              <th>HTML文件链接(共%s个)</th>
            </tr>
          </thead>
          <tbody>''' % (len(rs))

    for raw in rs:
        td = '''<tr><th><a href="http://xxx:5000/one/%s.html">%s.html</a></th></tr>''' %(raw[0], raw[0])
        res += td

    res += u'''
          </tbody>
        </table>'''

    return res

@app.route('/one/<string:filename>', methods=['GET'])
def get_one_html(filename):
    try:
        html = render_template(filename)
    except Exception:
        html = u"页面不存在！！！"

    return html

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)
    
    
