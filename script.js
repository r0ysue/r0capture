/**
   * Initializes 'addresses' dictionary and NativeFunctions.
   */
"use strict";
rpc.exports = {
  setssllib: function (name) {
    console.log("setSSLLib => " + name);
    libname = name;
    initializeGlobals();
    return;
  }
};

var addresses = {};
var SSL_get_fd = null;
var SSL_get_session = null;
var SSL_SESSION_get_id = null;
var getpeername = null;
var getsockname = null;
var ntohs = null;
var ntohl = null;

var libname = "*libssl*";



function return_zero(args) {
  return 0;
}
function initializeGlobals() {
  var resolver = new ApiResolver("module");
  var exps = [
    [Process.platform == "darwin" ? "*libboringssl*" : "*libssl*", ["SSL_read", "SSL_write", "SSL_get_fd", "SSL_get_session", "SSL_SESSION_get_id"]], // for ios and Android
    [Process.platform == "darwin" ? "*libsystem*" : "*libc*", ["getpeername", "getsockname", "ntohs", "ntohl"]]
  ];
  // console.log(exps)
  for (var i = 0; i < exps.length; i++) {
    var lib = exps[i][0];
    var names = exps[i][1];
    for (var j = 0; j < names.length; j++) {
      var name = names[j];
      // console.log("exports:" + lib + "!" + name)
      var matches = resolver.enumerateMatchesSync("exports:" + lib + "!" + name);
      if (matches.length == 0) {
        if (name == "SSL_get_fd") {
          addresses["SSL_get_fd"] = 0;
          continue;
        }
        throw "Could not find " + lib + "!" + name;
      }
      else if (matches.length != 1) {
        // Sometimes Frida returns duplicates.
        var address = 0;
        var s = "";
        var duplicates_only = true;
        for (var k = 0; k < matches.length; k++) {
          if (s.length != 0) {
            s += ", ";
          }
          s += matches[k].name + "@" + matches[k].address;
          if (address == 0) {
            address = matches[k].address;
          }
          else if (!address.equals(matches[k].address)) {
            duplicates_only = false;
          }
        }
        if (!duplicates_only) {
          throw "More than one match found for " + lib + "!" + name + ": " + s;
        }
      }
      addresses[name] = matches[0].address;
    }
  }
  if (addresses["SSL_get_fd"] == 0) {
    SSL_get_fd = return_zero;
  } else {
    SSL_get_fd = new NativeFunction(addresses["SSL_get_fd"], "int", ["pointer"]);
  }
  SSL_get_session = new NativeFunction(addresses["SSL_get_session"], "pointer", ["pointer"]);
  SSL_SESSION_get_id = new NativeFunction(addresses["SSL_SESSION_get_id"], "pointer", ["pointer", "pointer"]);
  getpeername = new NativeFunction(addresses["getpeername"], "int", ["int", "pointer", "pointer"]);
  getsockname = new NativeFunction(addresses["getsockname"], "int", ["int", "pointer", "pointer"]);
  ntohs = new NativeFunction(addresses["ntohs"], "uint16", ["uint16"]);
  ntohl = new NativeFunction(addresses["ntohl"], "uint32", ["uint32"]);
}
initializeGlobals();

function ipToNumber(ip) {
  var num = 0;
  if (ip == "") {
    return num;
  }
  var aNum = ip.split(".");
  if (aNum.length != 4) {
    return num;
  }
  num += parseInt(aNum[0]) << 0;
  num += parseInt(aNum[1]) << 8;
  num += parseInt(aNum[2]) << 16;
  num += parseInt(aNum[3]) << 24;
  num = num >>> 0;//这个很关键，不然可能会出现负数的情况
  return num;
}

/**
 * Returns a dictionary of a sockfd's "src_addr", "src_port", "dst_addr", and
 * "dst_port".
 * @param {int} sockfd The file descriptor of the socket to inspect.
 * @param {boolean} isRead If true, the context is an SSL_read call. If
 *     false, the context is an SSL_write call.
 * @return {dict} Dictionary of sockfd's "src_addr", "src_port", "dst_addr",
 *     and "dst_port".
 */
function getPortsAndAddresses(sockfd, isRead) {
  var message = {};
  var src_dst = ["src", "dst"];
  for (var i = 0; i < src_dst.length; i++) {
    if ((src_dst[i] == "src") ^ isRead) {
      var sockAddr = Socket.localAddress(sockfd)
    }
    else {
      var sockAddr = Socket.peerAddress(sockfd)
    }
    if (sockAddr == null) {
      // 网络超时or其他原因可能导致socket被关闭
      message[src_dst[i] + "_port"] = 0
      message[src_dst[i] + "_addr"] = 0
    } else {
      message[src_dst[i] + "_port"] = (sockAddr.port & 0xFFFF)
      message[src_dst[i] + "_addr"] = ntohl(ipToNumber(sockAddr.ip.split(":").pop()))
    }
  }
  return message;
}
/**
 * Get the session_id of SSL object and return it as a hex string.
 * @param {!NativePointer} ssl A pointer to an SSL object.
 * @return {dict} A string representing the session_id of the SSL object's
 *     SSL_SESSION. For example,
 *     "59FD71B7B90202F359D89E66AE4E61247954E28431F6C6AC46625D472FF76336".
 */
function getSslSessionId(ssl) {
  var session = SSL_get_session(ssl);
  if (session == 0) {
    return 0;
  }
  var len = Memory.alloc(4);
  var p = SSL_SESSION_get_id(session, len);
  len = Memory.readU32(len);
  var session_id = "";
  for (var i = 0; i < len; i++) {
    // Read a byte, convert it to a hex string (0xAB ==> "AB"), and append
    // it to session_id.
    session_id +=
      ("0" + Memory.readU8(p.add(i)).toString(16).toUpperCase()).substr(-2);
  }
  return session_id;
}

Interceptor.attach(addresses["SSL_read"],
  {
    onEnter: function (args) {
      var message = getPortsAndAddresses(SSL_get_fd(args[0]), true);
      message["ssl_session_id"] = getSslSessionId(args[0]);
      message["function"] = "SSL_read";
      this.message = message;
      this.buf = args[1];
    },
    onLeave: function (retval) {
      retval |= 0; // Cast retval to 32-bit integer.
      if (retval <= 0) {
        return;
      }
      send(this.message, Memory.readByteArray(this.buf, retval));
    }
  });

Interceptor.attach(addresses["SSL_write"],
  {
    onEnter: function (args) {
      var message = getPortsAndAddresses(SSL_get_fd(args[0]), false);
      message["ssl_session_id"] = getSslSessionId(args[0]);
      message["function"] = "SSL_write";
      send(message, Memory.readByteArray(args[1], parseInt(args[2])));
    },
    onLeave: function (retval) {
    }
  });

if (Java.available) {
  Java.perform(function () {
    Java.use("java.net.SocketOutputStream").socketWrite0.overload('java.io.FileDescriptor', '[B', 'int', 'int').implementation = function (fd, bytearry, offset, byteCount) {
      var result = this.socketWrite0(fd, bytearry, offset, byteCount);
      var message = {};
      message["function"] = "HTTP_send";
      message["ssl_session_id"] = "";
      message["src_addr"] = ntohl(ipToNumber((this.socket.value.getLocalAddress().toString().split(":")[0]).split("/").pop()));
      message["src_port"] = parseInt(this.socket.value.getLocalPort().toString());
      message["dst_addr"] = ntohl(ipToNumber((this.socket.value.getRemoteSocketAddress().toString().split(":")[0]).split("/").pop()));
      message["dst_port"] = parseInt(this.socket.value.getRemoteSocketAddress().toString().split(":").pop());
      var ptr = Memory.alloc(byteCount);
      for (var i = 0; i < byteCount; ++i)
        Memory.writeS8(ptr.add(i), bytearry[offset + i]);
      send(message, Memory.readByteArray(ptr, byteCount))
      return result;
    }
    Java.use("java.net.SocketInputStream").socketRead0.overload('java.io.FileDescriptor', '[B', 'int', 'int', 'int').implementation = function (fd, bytearry, offset, byteCount, timeout) {
      var result = this.socketRead0(fd, bytearry, offset, byteCount, timeout);
      var message = {};
      message["function"] = "HTTP_recv";
      message["ssl_session_id"] = "";
      message["src_addr"] = ntohl(ipToNumber((this.socket.value.getRemoteSocketAddress().toString().split(":")[0]).split("/").pop()));
      message["src_port"] = parseInt(this.socket.value.getRemoteSocketAddress().toString().split(":").pop());
      message["dst_addr"] = ntohl(ipToNumber((this.socket.value.getLocalAddress().toString().split(":")[0]).split("/").pop()));
      message["dst_port"] = parseInt(this.socket.value.getLocalPort());
      if (result > 0) {
        var ptr = Memory.alloc(result);
        for (var i = 0; i < result; ++i)
          Memory.writeS8(ptr.add(i), bytearry[offset + i]);
        send(message, Memory.readByteArray(ptr, result))
      }
      return result;
    }
  })
}
