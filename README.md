# PortScanner
批量扫描端口，并发送漏洞端口html格式邮件

1）Port_Scanner_V1.py是一个多进程的版本，指定进程数，nmap扫描设置超时时间。优点：扫描全面；缺点：扫描太慢，若设置超时时间或者速率太大容易被封导致扫描不到数据。

2）Port_Scanner_V2.py是一个多进程+协程的版本，自动获取cpu核数来设置进程数，有nmap和masscan（更快，但是不能扫描服务名）两个工具的扫描方法，可以自行选择，并做了适当的一点优化。优点：扫描贼快；缺点：扫描不全面，不能获取端口进程名。

3）Port_Scanner_V3.py是在V2版本的基础上结合masscan和nmap的优缺点整合的，先使用masscan扫描，然后使用nmap指定端口扫描，然后添加了Port_Scan_Update_api.py使用Flask实现发送邮件的确认修复功能api接口。Port_Scanner_V3.py+Port_Scan_Update_api.py结合使用。



