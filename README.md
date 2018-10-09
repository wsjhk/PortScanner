# PortScanner
批量扫描端口，并发送漏洞端口html格式邮件

1）Port_Scanner_V1.py是一个多进程的版本，指定进程数，nmap扫描设置超时时间。

2）Port_Scanner_V2.py是一个多进程+协程的版本，自动获取cpu核数来设置进程数，有nmap和masscan（更快，但是不能扫描服务名）两个工具的扫描方法，可以自行选择，并做了适当的一点优化。
