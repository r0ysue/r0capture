# r0capture

安卓应用层抓包通杀脚本

## 简介

- 仅限安卓平台，测试安卓7、8、9、10 可用 ；
- 无视所有证书校验或绑定，不用考虑任何证书的事情；
- 通杀TCP/IP四层模型中的应用层中的全部协议；
- 通杀协议包括：Http,WebSocket,Ftp,Xmpp,Imap,Smtp,Protobuf等等、以及它们的SSL版本；
- 通杀所有应用层框架，包括HttpUrlConnection、Okhttp1/3/4、Retrofit/Volley等等；
- 如果有抓不到的情况欢迎提issue，或者直接加vx：r0ysue，进行反馈~

## 用法

- Spawn 模式：

`$ python3 r0capture.py -U -f com.qiyi.video`

- Attach 模式，抓包内容保存成pcap文件供后续分析：

`$ python3 r0capture.py -U com.qiyi.video -p iqiyi.pcap`

建议使用`Attach`模式，从感兴趣的地方开始抓包，并且保存成`pcap`文件，供后续使用Wireshark进行分析。

![](Sample.PNG)



PS：

> 这个项目基于[frida_ssl_logger](https://github.com/BigFaceCat2017/frida_ssl_logger)，之所以换个名字，只是侧重点不同。

> 原项目的侧重点在于抓ssl和跨平台，本项目的侧重点是抓到所有的包。

## 以下是原项目的简介：

[https://github.com/BigFaceCat2017/frida_ssl_logger](https://github.com/BigFaceCat2017/frida_ssl_logger)

### frida_ssl_logger
ssl_logger based on frida
for from https://github.com/google/ssl_logger

### 修改内容
1. 优化了frida的JS脚本，修复了在新版frida上的语法错误；
2. 调整JS脚本，使其适配iOS和macOS，同时也兼容了Android；
3. 增加了更多的选项，使其能在多种情况下使用；

### Usage
  ```shell
    python3 ./ssl_logger.py  -U -f com.bfc.mm
    python3 ./ssl_logger.py -v  -p test.pcap  6666
  ````
