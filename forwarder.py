# -*- coding: utf-8 -*-
# !/usr/bin/env python

__author__ = "RichardTang"
__version__ = "1.0"

import httpx
from loguru import logger
from urllib3.exceptions import InsecureRequestWarning

class Forwarder:


    def __init__(self, proxies):
        self.httpx_client = httpx.Client(proxies={"https://":proxies,"http://":proxies}, verify=False, timeout=3, http2=True)


    # int值转ip地址字符串
    def int_to_ip(self, num):
        s = []
        for i in range(4):
            s.append(str(num % 256))
            num //= 256
        return '.'.join(s[::-1])


    # 处理转发请求
    def forward(self, message, data):
        try:
            # 只处理Http协议的发送包
            if (message["payload"]["function"] == "SSL_write") and (bytes("HTTP/", encoding="utf-8") in data):

                # 忽略Http2的PRI请求，一般代理工具都支持处理Http2，所以这里不需要另外处理。没理解错的话 :)
                if bytes("PRI * HTTP/2.0", encoding="utf-8") in data:
                    return

                p = message["payload"]

                # 分割header和body原始数据
                split_index_position = data.index(b'\r\n\r\n')
                http_header_raw = data[:split_index_position]
                http_body_raw = data[split_index_position + 4:]

                # 解码HttpHeader
                http_header = str(http_header_raw, 'utf-8').split('\r\n')
                http_post_and_uri = http_header[0].split(" ")
                http_method = http_post_and_uri[0]
                http_target = "https://{}:{}{}".format(
                    self.int_to_ip(p["dst_addr"]),
                    p["dst_port"],
                    http_post_and_uri[1].split(" ")[0]
                )

                # logger.info(http_header[0])
                # logger.info(http_target)

                # 解码HttpBody
                http_body = ""
                if len(http_body_raw.strip()) >= 1:
                    http_body = http_body_raw

                # 需要转换为dict
                headers = {}
                for index in range(1, len(http_header)):
                    # 根据 : 进行切割，重新组装成dict。
                    item = http_header[index].split(":")
                    headers[str(item[0])] = str(item[1]).lstrip()

                # 转发请求
                self.httpx_client.request(http_method, http_target, headers=headers, data=http_body)

        except Exception as e:
            logger.info(e)
            # logger.info(data)
            pass
