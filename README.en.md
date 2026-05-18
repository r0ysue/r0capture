# r0capture

[中文](README.md) | **English** | [Tiếng Việt](README.vi.md)

Universal packet-capture script for the Android application layer.

## Introduction

- Android only. Tested and available on Android 7, 8, 9, 10, 11, 12, 13, 14, 15, and 16.
- Ignores all certificate validation or pinning. You do not need to worry about certificates.
- Captures all application-layer protocols in the TCP/IP four-layer model.
- Supported protocols include HTTP, WebSocket, FTP, XMPP, IMAP, SMTP, Protobuf, and their SSL versions.
- Supports all application-layer frameworks, including HttpUrlConnection, OkHttp 1/3/4, Retrofit, Volley, and more.
- Ignores app hardening, including full shells, second-generation shells, and VMP. You do not need to worry about hardening.
- If there are cases where packets cannot be captured, open an issue or contact WeChat: `r0ysue`.

### March 2026 update: Frida 17 support

Recommended combinations: Frida 17 / Android 16, Frida 16.5.2 / Android 14, Frida 15.2.2 / Android 12.

### June 18, 2023 update

Tested on Pixel 4 / Android 13 / KernelSU / Frida 16. Packet capture and certificate export work normally.

### January 14, 2021 update: Added several helper features

- Added a feature to locate app send/receive packet functions.
- Added a feature to export app client certificates.
- Added the `-H` host connection mode for connecting to Frida server when it listens on a non-standard port.

## Usage

- Recommended environment: [https://github.com/r0ysue/AndroidSecurityStudy/blob/master/FRIDA/A01/README.md](https://github.com/r0ysue/AndroidSecurityStudy/blob/master/FRIDA/A01/README.md)

Remember: this is only available on Android 7, 8, 9, 10, and 11. Do not use an emulator.

- Spawn mode:

`$ python3 r0capture.py -U -f com.coolapk.market -v`

- Attach mode, saving captured packets to a pcap file for later analysis:

`$ python3 r0capture.py -U 酷安 -v -p iqiyi.pcap`

Using `Attach` mode is recommended. Start capturing from the part you are interested in, and save the output as a `pcap` file for later analysis in Wireshark.

> Older Frida versions use the package name. Newer Frida versions use the app name. The app name must be the name shown by `frida-ps -U` after opening the app.

![](pic/Sample.PNG)

- Send/receive packet function locating: enabled by default in both `Spawn` and `Attach` modes.

> You can redirect output to a txt file and filter it later, for example: `python r0capture.py -U -f cn.soulapp.android -v >> soul3.txt`.

![](pic/locator.png)

- Client certificate export: enabled by default. It must be run in Spawn mode.

> Before running the script, you must manually grant the app read/write permission for storage.

> Not every app deploys a mechanism where the server verifies the client. Only apps that configure this will include a client certificate in the APK.

> Exported certificates are located at `/sdcard/Download/package_name_xxx.p12`. If exported multiple times, every copy is usable. The default password is `r0ysue`. [keystore-explorer](http://keystore-explorer.org/) is recommended for opening and viewing the certificate.

![](pic/clientcer.png)

- Added the `-H` host connection mode for connecting to Frida server when it listens on a non-standard port. Some apps detect Frida's standard port, so running Frida server on a non-standard port can bypass detection.

![](pic/difport.png)

## Thanks to [爱吃菠菜](https://bbs.pediy.com/user-760871.htm) for summarizing the knowledge points of this project

![](pic/summary1.jpg)
![](pic/summary2.jpg)

PS:

> This project is based on [frida_ssl_logger](https://github.com/BigFaceCat2017/frida_ssl_logger). The name was changed only because the focus is different. The original project focuses on SSL capture and cross-platform support, while this project focuses on capturing all packets.

> Limitations: Some large companies or frameworks with strong development capabilities use their own SSL frameworks, such as WebView, mini-programs, or Flutter. These are not currently supported. Some hybrid apps are essentially no longer Android apps and do not use Android system frameworks, so they cannot be supported. These apps are a minority. HTTP/2 and HTTP/3 are not currently supported. Their APIs are not yet widespread or deployed on Android systems, and are bundled by apps themselves, so they cannot be hooked generically. Emulator architectures, implementations, and environments are complex, so using a real device is strongly recommended. Multi-process support has not been added yet, such as `:service` or `:push` subprocesses. Frida Child Gating can be used for partial support. After multi-process support is added, pcap file write locks need to be considered; this can be supported with the Reactor thread lock in frida-tool.

## Original project introduction

[https://github.com/BigFaceCat2017/frida_ssl_logger](https://github.com/BigFaceCat2017/frida_ssl_logger)

### frida_ssl_logger

ssl_logger based on frida, forked from https://github.com/google/ssl_logger

### Changes

1. Optimized Frida's JS script and fixed syntax errors on newer Frida versions.
2. Adjusted the JS script to support iOS and macOS while remaining compatible with Android.
3. Added more options so it can be used in more scenarios.

### Install Dependencies

```text
Python version >= 3.6
pip install loguru
pip install click
```

### Usage

```shell
python3 ./ssl_logger.py -U -f com.bfc.mm
python3 ./ssl_logger.py -v -p test.pcap 6666
```
