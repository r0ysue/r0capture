# r0capture

Android application layer packet capture script

## Introduction

- Android platform only, tested on Android 7, 8, 9, 10, 11;
- Ignore all certificate verification or binding, regardless of any certificate matters;
- Through capturing all protocols in the application layer in the TCP/IP four-layer model;
- Captures all protocols including: Http, WebSocket, Ftp, Xmpp, Imap, Smtp, Protobuf, etc., and their SSL versions;
- Captures all application layer frameworks, including HttpUrlConnection, Okhttp1/3/4, Retrofit/Volley, etc.;

## Usage

- Recommended environment: [https://github.com/r0ysue/AndroidSecurityStudy/blob/master/FRIDA/A01/README.md](https://github.com/r0ysue/AndroidSecurityStudy/blob/master/FRIDA/A01/README.md)

Remember that it is only available on Android platforms 7, 8, 9, 10, 11, and emulators are prohibited.

- Spawn mode:

```
$ python3 r0capture.py -U -f com.qiyi.video -v
```

- In Attach mode, the captured packet content is saved as a pcap file for subsequent analysis:

```
$ python3 r0capture.py -U com.qiyi.video -v -p iqiyi.pcap
```

It is recommended to use the `Attach` mode, start capturing packets from the place of interest, and save it as a `pcap` file for subsequent analysis with Wireshark.

![](pic/Sample.PNG)

- Send and receive packet function positioning: `Spawn`and `attach`mode are enabled by default;

> The output of `python r0capture.py -U -f cn.soulapp.android -v >> soul3.txt` can be redirected to a txt file with a command like this to filter the content later.

![](pic/locator.png)

- Client certificate export function: enabled by default; must run in Spawm mode;

> Before running the script, you must manually add read and write permissions to the memory card to the App;

> Not all apps have deployed a mechanism for the server to verify the client, only the configured ones will include the client certificate in the Apk

> The exported certificate is located in the path /sdcard/Download/package name xxx.p12. After exporting multiple times, each copy is available. The default password is: r0ysue. It is recommended to use [keystore-explorer](http://keystore-explorer.org/) to open and view the certificate.

![](pic/clientcer.png)

- Added host connection method "-H" for Frida-server to monitor connections on non-standard ports. Some apps will detect Frida standard ports, so opening frida-server on non-standard ports can bypass the detection.

![](pic/difport.png)

> This project is based on [frida_ssl_logger](https://github.com/BigFaceCat2017/frida_ssl_logger), the reason for the name change is that the focus is different. The focus of the original project is to capture ssl and cross-platform, the focus of this project is to capture all packets.

> Limitations: Some major manufacturers or frameworks with strong development capabilities use their own SSL frameworks, such as WebView, applet or Flutter, which are not currently supported. Some integrated apps are not Android apps in essence, they do not use the framework of the Android system and cannot be supported. Of course, this part of the app is also a minority. It does not support HTTP/2 or HTTP/3 at the moment. This part of the API has not yet been popularized or deployed on the Android system. It comes with the App and cannot be used for general hooking. The architecture, implementation and environment of various simulators are relatively complex. It is recommended to cherish life and use real machines. Multi-process support has not been added yet, such as child processes such as :service or :push, you can use Frida's Child-gating to support it. After supporting multiple processes, the write lock of the pcap file should be considered. You can use the Reactor thread lock of frida-tool to support it.

### What's improved

1. Optimized frida JS script and fixed syntax errors on the new version of frida;
2. Adjusted the JS script to make it compatible with iOS and macOS, and also compatible with Android;
3. Added more options so that it can be used in a variety of situations;


### Install dependencies

```shell
Python version >= 3.6
pip install loguru
pip install click
```


### Usage

```shell
python ./ssl_logger.py -U -f com.bfc.mm
python ./ssl_logger.py -v -p test.pcap  6666
```
### References:

[**frida_ssl_logger**](https://github.com/BigFaceCat2017/frida_ssl_logger)  
ssl_logger based on https://github.com/google/ssl_logger

