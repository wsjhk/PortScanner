# -*- coding:utf-8 -*-

import pandas, masscan, os
from Port_Scanner import ConDb
from flask import Flask

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

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
def update(ip, port):
    con = ConDb()
    mas = masscan.PortScanner()
    try:
        tmp = mas.scan(ip, port, arguments='--rate=10000 --interface eth0 --router-mac 48-7a-da-78-f6-ae')
        ports = tmp['scan'][ip]['tcp'].keys()
        for p in ports:
            state = tmp['scan'][ip]['tcp'][p]['state']
            if state != 'open':
                set = 'status = \"%s\", deal = \"%s\"' % (state, 'YES')
                where = 'ip = \"%s\" and port = \"%s\"' % (ip, p)
                con.update_TB('scan_port', set, where)
            else:
                pass
    except Exception, e:
        print e

    sql = "select distinct ip,port,services,status,deal,create_time from scan_port where ip = '%s' and port in (%s)" % (
        ip, port)
    res = con.runSql(sql.encode('utf-8'))
    title = [u'IP地址', u'端口', u'服务', u'状态', u'是否修复', u'更新时间']

    return convertToHtml(res, title)

# 忽略按钮调用的api接口入口
@app.route('/ignore/<string:ip>/<string:port>', methods=['GET', 'POST'])
def ignore(ip, port, time):
    con = ConDb()
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
    sql = "select distinct ip from scan_port limit 5000"
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
    
    
