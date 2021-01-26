# Copyright 2017 Google Inc. All Rights Reserved.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Decrypts and logs a process's SSL traffic.
Hooks the functions SSL_read() and SSL_write() in a given process and logs the
decrypted data to the console and/or to a pcap file.
  Typical usage example:
  ssl_log("wget", "log.pcap", True)
Dependencies:
  frida (https://www.frida.re/):
    sudo pip install frida
  hexdump (https://bitbucket.org/techtonik/hexdump/) if using verbose output:
    sudo pip install hexdump
"""

__author__ = "geffner@google.com (Jason Geffner)"
__version__ = "2.0"

"""
# r0capture

ID: r0ysue 

安卓应用层抓包通杀脚本

https://github.com/r0ysue/r0capture

## 简介

- 仅限安卓平台，测试安卓7、8、9、10 可用 ；
- 无视所有证书校验或绑定，无视任何证书；
- 通杀TCP/IP四层模型中的应用层中的全部协议；
- 通杀协议包括：Http,WebSocket,Ftp,Xmpp,Imap,Smtp,Protobuf等等、以及它们的SSL版本；
- 通杀所有应用层框架，包括HttpUrlConnection、Okhttp1/3/4、Retrofit/Volley等等；
"""


# Windows版本需要安装库：
# pip install 'win_inet_pton'
# pip install hexdump
import argparse
import os
import platform
import pprint
import random
import signal
import socket
import struct
import time
import sys

import frida

try:
    if os.name == 'nt':
        import win_inet_pton
except ImportError:
    # win_inet_pton import error
    pass

try:
    import hexdump  # pylint: disable=g-import-not-at-top
except ImportError:
    pass
try:
    from shutil import get_terminal_size as get_terminal_size
except:
    try:
        from backports.shutil_get_terminal_size import get_terminal_size as get_terminal_size
    except:
        pass


try:
    import click
except:
    class click:
        @staticmethod
        def secho(message=None, **kwargs):
            print(message)
        @staticmethod
        def style(**kwargs):
            raise Exception("unsupported style")

banner = """
--------------------------------------------------------------------------------------------
           .oooo.                                      .                                  
          d8P'`Y8b                                   .o8                                  
oooo d8b 888    888  .ooooo.   .oooo.   oo.ooooo.  .o888oo oooo  oooo  oooo d8b  .ooooo.  
`888""8P 888    888 d88' `"Y8 `P  )88b   888' `88b   888   `888  `888  `888""8P d88' `88b 
 888     888    888 888        .oP"888   888   888   888    888   888   888     888ooo888 
 888     `88b  d88' 888   .o8 d8(  888   888   888   888 .  888   888   888     888    .o 
d888b     `Y8bd8P'  `Y8bod8P' `Y888""8o  888bod8P'   "888"  `V88V"V8P' d888b    `Y8bod8P' 
                                         888                                              
                                        o888o                                                                                                                                       
                    https://github.com/r0ysue/r0capture
--------------------------------------------------------------------------------------------\n
"""


def show_banner():
    colors = ['bright_red', 'bright_green', 'bright_blue', 'cyan', 'magenta']
    try:
        click.style('color test', fg='bright_red')
    except:
        colors = ['red', 'green', 'blue', 'cyan', 'magenta']
    try:
        columns = get_terminal_size().columns
        if columns >= len(banner.splitlines()[1]):
            for line in banner.splitlines():
                click.secho(line, fg=random.choice(colors))
    except:
        pass

# ssl_session[<SSL_SESSION id>] = (<bytes sent by client>,
#                                  <bytes sent by server>)
ssl_sessions = {}


def ssl_log(process, pcap=None, host=False, verbose=False, isUsb=False, ssllib="", isSpawn=True, wait=0):
    """Decrypts and logs a process's SSL traffic.
    Hooks the functions SSL_read() and SSL_write() in a given process and logs
    the decrypted data to the console and/or to a pcap file.
    Args:
      process: The target process's name (as a string) or process ID (as an int).
      pcap: The file path to which the pcap file should be written.
      verbose: If True, log the decrypted traffic to the console.
    Raises:
      NotImplementedError: Not running on a Linux or macOS system.
    """

    # if platform.system() not in ("Darwin", "Linux"):
    #   raise NotImplementedError("This function is only implemented for Linux and "
    #                             "macOS systems.")

    def log_pcap(pcap_file, ssl_session_id, function, src_addr, src_port,
                 dst_addr, dst_port, data):
        """Writes the captured data to a pcap file.
        Args:
          pcap_file: The opened pcap file.
          ssl_session_id: The SSL session ID for the communication.
          function: The function that was intercepted ("SSL_read" or "SSL_write").
          src_addr: The source address of the logged packet.
          src_port: The source port of the logged packet.
          dst_addr: The destination address of the logged packet.
          dst_port: The destination port of the logged packet.
          data: The decrypted packet data.
        """
        t = time.time()

        if ssl_session_id not in ssl_sessions:
            ssl_sessions[ssl_session_id] = (random.randint(0, 0xFFFFFFFF),
                                            random.randint(0, 0xFFFFFFFF))
        client_sent, server_sent = ssl_sessions[ssl_session_id]

        if function == "SSL_read":
            seq, ack = (server_sent, client_sent)
        else:
            seq, ack = (client_sent, server_sent)

        for writes in (
                # PCAP record (packet) header
                ("=I", int(t)),  # Timestamp seconds
                ("=I", int((t * 1000000) % 1000000)),  # Timestamp microseconds
                ("=I", 40 + len(data)),  # Number of octets saved
                ("=i", 40 + len(data)),  # Actual length of packet
                # IPv4 header
                (">B", 0x45),  # Version and Header Length
                (">B", 0),  # Type of Service
                (">H", 40 + len(data)),  # Total Length
                (">H", 0),  # Identification
                (">H", 0x4000),  # Flags and Fragment Offset
                (">B", 0xFF),  # Time to Live
                (">B", 6),  # Protocol
                (">H", 0),  # Header Checksum
                (">I", src_addr),  # Source Address
                (">I", dst_addr),  # Destination Address
                # TCP header
                (">H", src_port),  # Source Port
                (">H", dst_port),  # Destination Port
                (">I", seq),  # Sequence Number
                (">I", ack),  # Acknowledgment Number
                (">H", 0x5018),  # Header Length and Flags
                (">H", 0xFFFF),  # Window Size
                (">H", 0),  # Checksum
                (">H", 0)):  # Urgent Pointer
            pcap_file.write(struct.pack(writes[0], writes[1]))
        pcap_file.write(data)

        if function == "SSL_read":
            server_sent += len(data)
        else:
            client_sent += len(data)
        ssl_sessions[ssl_session_id] = (client_sent, server_sent)

    def on_message(message, data):
        """Callback for errors and messages sent from Frida-injected JavaScript.
        Logs captured packet data received from JavaScript to the console and/or a
        pcap file. See https://www.frida.re/docs/messages/ for more detail on
        Frida's messages.
        Args:
          message: A dictionary containing the message "type" and other fields
              dependent on message type.
          data: The string of captured decrypted data.
        """
        if message["type"] == "error":
            pprint.pprint(message)
            os.kill(os.getpid(), signal.SIGTERM)
            return
        if len(data) == 1:
            print(message["payload"]["function"])
            print(message["payload"]["stack"])
            return
        p = message["payload"]        
        if verbose:
            src_addr = socket.inet_ntop(socket.AF_INET,
                                        struct.pack(">I", p["src_addr"]))
            dst_addr = socket.inet_ntop(socket.AF_INET,
                                        struct.pack(">I", p["dst_addr"]))
            print("SSL Session: " + p["ssl_session_id"])
            print("[%s] %s:%d --> %s:%d" % (
                p["function"],
                src_addr,
                p["src_port"],
                dst_addr,
                p["dst_port"]))
            hexdump.hexdump(data)
            print(p["stack"])
        if pcap:
            log_pcap(pcap_file, p["ssl_session_id"], p["function"], p["src_addr"],
                     p["src_port"], p["dst_addr"], p["dst_port"], data)

    if isUsb:
        try:
            device = frida.get_usb_device()
        except:
            device = frida.get_remote_device()
    else:
        if host:
            manager = frida.get_device_manager()
            device = manager.add_remote_device(host)
        else:
            device = frida.get_local_device()

    if isSpawn:
        pid = device.spawn([process])
        time.sleep(1)
        session = device.attach(pid)
        time.sleep(1)
        device.resume(pid)
    else:
        print("attach")
        session = device.attach(process)
    if wait > 0:
        print("wait for {} seconds".format(wait))
        time.sleep(wait)

    # session = frida.attach(process)

    # pid = device.spawn([process])
    # pid = process
    # session = device.attach(pid)
    # device.resume(pid)
    if pcap:
        pcap_file = open(pcap, "wb", 0)
        for writes in (
                ("=I", 0xa1b2c3d4),  # Magic number
                ("=H", 2),  # Major version number
                ("=H", 4),  # Minor version number
                ("=i", time.timezone),  # GMT to local correction
                ("=I", 0),  # Accuracy of timestamps
                ("=I", 65535),  # Max length of captured packets
                ("=I", 228)):  # Data link type (LINKTYPE_IPV4)
            pcap_file.write(struct.pack(writes[0], writes[1]))

    with open("./script.js", encoding="utf-8") as f:
        _FRIDA_SCRIPT = f.read()
        # _FRIDA_SCRIPT = session.create_script(content)
        # print(_FRIDA_SCRIPT)
    script = session.create_script(_FRIDA_SCRIPT)
    script.on("message", on_message)
    script.load()

    if ssllib != "":
        script.exports.setssllib(ssllib)

    print("Press Ctrl+C to stop logging.")

    def stoplog(signum, frame):
        print('You have stoped logging.')
        session.detach()
        if pcap:
            pcap_file.flush()
            pcap_file.close()
        exit()
    signal.signal(signal.SIGINT, stoplog)
    signal.signal(signal.SIGTERM, stoplog)
    sys.stdin.read()

if __name__ == "__main__":
    show_banner()
    class ArgParser(argparse.ArgumentParser):

        def error(self, message):
            print("ssl_logger v" + __version__)
            print("by " + __author__)
            print("Modified by BigFaceCat")
            print("Error: " + message)
            print()
            print(self.format_help().replace("usage:", "Usage:"))
            self.exit(0)


    parser = ArgParser(
        add_help=False,
        description="Decrypts and logs a process's SSL traffic.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=r"""
Examples:
    %(prog)s -pcap ssl.pcap openssl
    %(prog)s -verbose 31337
    %(prog)s -pcap log.pcap -verbose wget
    %(prog)s -pcap log.pcap -ssl "*libssl.so*" com.bigfacecat.testdemo
""")

    args = parser.add_argument_group("Arguments")
    args.add_argument("-pcap", '-p', metavar="<path>", required=False,
                      help="Name of PCAP file to write")
    args.add_argument("-host", '-H', metavar="<192.168.1.1:27042>", required=False,
                      help="connect to remote frida-server on HOST")
    args.add_argument("-verbose","-v",  required=False, action="store_const", default=True,
                      const=True, help="Show verbose output")
    args.add_argument("process", metavar="<process name | process id>",
                      help="Process whose SSL calls to log")
    args.add_argument("-ssl", default="", metavar="<lib>",
                      help="SSL library to hook")
    args.add_argument("--isUsb", "-U", default=False, action="store_true",
                      help="connect to USB device")
    args.add_argument("--isSpawn", "-f", default=False, action="store_true",
                      help="if spawned app")
    args.add_argument("-wait", "-w", type=int, metavar="<seconds>", default=0,
                      help="Time to wait for the process")

    parsed = parser.parse_args()
    ssl_log(
        int(parsed.process) if parsed.process.isdigit() else parsed.process, 
    parsed.pcap, 
    parsed.host,
    parsed.verbose, 
    isUsb=parsed.isUsb, 
    isSpawn=parsed.isSpawn, 
    ssllib=parsed.ssl, 
    wait=parsed.wait
    )
