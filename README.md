# 功能场景

目前r0capture是以pcap和print的方式查看数据包，有时在应对渗透测试的场景下，需要用到burpsuite或yakit此类工具进行改包，方便进行数据包的分析和修改。

# 新增参数

`-F http://127.0.0.1:8080` 或 `--isForward http://127.0.0.1:8080`

`python r0capture.py -U -f package -F http://127.0.0.1:8080 -p test.pcap`

# 演示效果

![image](https://user-images.githubusercontent.com/30547741/215651947-a84a2152-96bb-4c28-837c-f8117bc08445.png)

![image](https://user-images.githubusercontent.com/30547741/215652029-9ae633da-1152-4721-93c6-9d5f7a919937.png)

# Tip

实现的forward只是对r0capture的SSL_write类型的function进行了处理，同时因为是hook的原因，并不能达到像平常代理那样的阻塞方式的拦截数据包。不过这也方便渗透测试人员对数据包的分析和测试 :)