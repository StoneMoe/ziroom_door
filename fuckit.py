# coding=utf-8
from mitmproxy import ctx
from mitmproxy import contentviews
import json
import typing
import base64
from mitmproxy.utils import human
from Crypto import Random
from Crypto.Cipher import AES
import mitmproxy.addonmanager
import mitmproxy.connections
import mitmproxy.http
from mitmproxy import command
import mitmproxy.log
import mitmproxy.tcp
from mitmproxy import ctx
import mitmproxy.websocket
import mitmproxy.proxy.protocol
from mitmproxy.flow import Flow as GenericFlow


class AESCipher(object):
    def __init__(self, key, mode=AES.MODE_CCM, bs=16):
        self.bs = bs
        self.cipher = AES.new(key, mode)

    def encrypt(self, raw):
        raw = self._pad(raw)
        encrypted = self.cipher.encrypt(raw)
        encoded = base64.b64encode(encrypted)
        return str(encoded, 'utf-8')

    def decrypt(self, raw):
        decoded = base64.b64decode(raw)
        decrypted = self.cipher.decrypt(decoded)
        return str(self._unpad(decrypted), 'utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    def _unpad(self, s):
        return s[:-ord(s[len(s) - 1:])]


class Events:
    # HTTP lifecycle
    def http_connect(self, flow: mitmproxy.http.HTTPFlow):
        """
            An HTTP CONNECT request was received. Setting a non 2xx response on
            the flow will return the response to the client abort the
            connection. CONNECT requests and responses do not generate the usual
            HTTP handler events. CONNECT requests are only valid in regular and
            upstream proxy modes.
        """

    def requestheaders(self, flow: mitmproxy.http.HTTPFlow):
        """
            HTTP request headers were successfully read. At this point, the body
            is empty.
        """

    def request(self, flow: mitmproxy.http.HTTPFlow):
        """
            The full HTTP request has been read.
        """

    def responseheaders(self, flow: mitmproxy.http.HTTPFlow):
        """
            HTTP response headers were successfully read. At this point, the body
            is empty.
        """

    def response(self, flow: mitmproxy.http.HTTPFlow):
        """
            The full HTTP response has been read.
        """

    def error(self, flow: mitmproxy.http.HTTPFlow):
        """
            An HTTP error has occurred, e.g. invalid server responses, or
            interrupted connections. This is distinct from a valid server HTTP
            error response, which is simply a response with an HTTP error code.
        """

    # TCP lifecycle
    def tcp_start(self, flow: mitmproxy.tcp.TCPFlow):
        """
            A TCP connection has started.
        """

    def tcp_message(self, flow: mitmproxy.tcp.TCPFlow):
        """
            A TCP connection has received a message. The most recent message
            will be flow.messages[-1]. The message is user-modifiable.
        """

    def tcp_error(self, flow: mitmproxy.tcp.TCPFlow):
        """
            A TCP error has occurred.
        """

    def tcp_end(self, flow: mitmproxy.tcp.TCPFlow):
        """
            A TCP connection has ended.
        """

    # Websocket lifecycle
    def websocket_handshake(self, flow: mitmproxy.http.HTTPFlow):
        """
            Called when a client wants to establish a WebSocket connection. The
            WebSocket-specific headers can be manipulated to alter the
            handshake. The flow object is guaranteed to have a non-None request
            attribute.
        """

    def websocket_start(self, flow: mitmproxy.websocket.WebSocketFlow):
        """
            A websocket connection has commenced.
        """

    def websocket_message(self, flow: mitmproxy.websocket.WebSocketFlow):
        """
            Called when a WebSocket message is received from the client or
            server. The most recent message will be flow.messages[-1]. The
            message is user-modifiable. Currently there are two types of
            messages, corresponding to the BINARY and TEXT frame types.
        """
        ctx.log.alert('========Flow start========')
        data = flow.messages[-1]
        msg = data.content
        msg_obj = json.loads(msg)
        cmd = msg_obj['cmd']
        del msg_obj['cmd']
        req_id = msg_obj['reqid']
        del msg_obj['reqid']

        direction = ' 发送 > ' if data.from_client else ' 接收 < '
        log = direction + f'[{cmd}][{req_id}] %s'

        # Output
        if cmd == 'breath' or cmd == 'breath_res':
            log = log % (
                    '[心跳包] %s' % msg_obj
            )
            return
        elif cmd == 'register':
            log = log % ('[注册设备] SN/dev_id: %s' % msg_obj['data']['devid'])
        elif cmd == 'register_res':
            log = log % (
                    '[注册设备] %s' % msg_obj['data']
            )
        elif 'userData' in msg_obj:
            # Force OTA not work
            # if 'OTA_Check' in msg:
            #     ctx.log.alert(msg)
            #     flow.server_conn.send("""{"cmd":"request","reqid":"%s","userData":{"system":{"ddinglink":"1.0","jsonrpc":"1.0","lang":"en","sign":"8809259e27630a474e63b50422915582","key":"50d655ee510790acfd12","time":"1535721910"},"id":56,"request":{"uuid":"6cbeb0e4edb01bdad97d25349867a2a5","cid":"cidcenter001"},"method":"getServerStatus","params":{"uuid":"6cbeb0e4edb01bdad97d25349867a2a5","attrSet":["OTA_Check"],"OTA_Check":{"set":{"hardware_version":"1.0.4.0","app_version":"1.0.0.0","zigbee_version":"0.0.0.0","zigbee_router_version":"0.0.0.0","kernel_version":"0.0.0.0","media_version":"0.0.0.0"}}}}}""" % (int(req_id) + 1))
            user_data = msg_obj['userData']
            log = log % user_data
        else:
            log = log % msg_obj

        ctx.log.info(log)

        ctx.log.alert('========Flow end========')

    def websocket_error(self, flow: mitmproxy.websocket.WebSocketFlow):
        """
            A websocket connection has had an error.
        """

    def websocket_end(self, flow: mitmproxy.websocket.WebSocketFlow):
        """
            A websocket connection has ended.
        """

    # Network lifecycle
    def clientconnect(self, layer: mitmproxy.proxy.protocol.Layer):
        """
            A client has connected to mitmproxy. Note that a connection can
            correspond to multiple HTTP requests.
        """

    def clientdisconnect(self, layer: mitmproxy.proxy.protocol.Layer):
        """
            A client has disconnected from mitmproxy.
        """

    def serverconnect(self, conn: mitmproxy.connections.ServerConnection):
        """
            Mitmproxy has connected to a server. Note that a connection can
            correspond to multiple requests.
        """

    def serverdisconnect(self, conn: mitmproxy.connections.ServerConnection):
        """
            Mitmproxy has disconnected from a server.
        """

    def next_layer(self, layer: mitmproxy.proxy.protocol.Layer):
        """
            Network layers are being switched. You may change which layer will
            be used by returning a new layer object from this event.
        """

    # General lifecycle
    def configure(self, updated: typing.Set[str]):
        """
            Called when configuration changes. The updated argument is a
            set-like object containing the keys of all changed options. This
            event is called during startup with all options in the updated set.
        """

    def done(self):
        """
            Called when the addon shuts down, either by being removed from
            the mitmproxy instance, or when mitmproxy itself shuts down. On
            shutdown, this event is called after the event loop is
            terminated, guaranteeing that it will be the final event an addon
            sees. Note that log handlers are shut down at this point, so
            calls to log functions will produce no output.
        """

    def load(self, entry: mitmproxy.addonmanager.Loader):
        """
            Called when an addon is first loaded. This event receives a Loader
            object, which contains methods for adding options and commands. This
            method is where the addon configures itself.
        """

    def log(self, entry: mitmproxy.log.LogEntry):
        """
            Called whenever a new log entry is created through the mitmproxy
            context. Be careful not to log from this event, which will cause an
            infinite loop!
        """

    def running(self):
        """
            Called when the proxy is completely up and running. At this point,
            you can expect the proxy to be bound to a port, and all addons to be
            loaded.
        """

    def update(self, flows: typing.Sequence[GenericFlow]):
        """
            Update is called when one or more flow objects have been modified,
            usually from a different addon.
        """


addons = [
    Events()
]

if __name__ == '__main__':
    # Try to find the key, but no luck
    # keys = [
    #     b'\x01\x03\x05\x07\x09\x0B\x0D\x0F\x00\x02\x04\x06\x08\x0A\x0C\x0D',
    #     b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F',
    #     b'\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa',
    #     b'\x00\x00\x00\x00\x00\x00\x00\x00\x89\x67\x45\x23\x01\xEF\xCD\xAB',
    #     b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F',
    #     b'3c31cba776670e712871bafe216c2d4c',
    #     b'00000000000050d655ee510790acfd12',
    #     b'50d655ee510790acfd12000000000000',
    #     b'50d655ee510790ac',
    #     b'55ee510790acfd12',
    #     b'3f51435ceea74a6b3497d76c9049305a'
    # ]
    # modes = [
    #     AES.MODE_ECB,
    #     AES.MODE_CBC,
    #     AES.MODE_CFB,
    #     AES.MODE_OFB,
    #     AES.MODE_CTR,
    #     AES.MODE_OPENPGP,
    #     AES.MODE_CCM,
    #     AES.MODE_EAX,
    #     AES.MODE_SIV,
    #     AES.MODE_GCM,
    #     AES.MODE_OCB
    # ]
    # for key in keys:
    #     for mode in modes:
    #         for bs in range(1, 65):
    #             try:
    #                 cipher = AESCipher(key=key, mode=mode, bs=bs)
    #                 decrypted = cipher.decrypt(
    #                     'q0AAT6VAgFMGYBmqFTRistLlcsCD60epAwvAPGJ8Naxp0ysiToOs9eoVmanqXWI0v71C/6DbMqoXAeY8YamN63+qbiN+hqzcsRKcqhE0LDKAm3XBm+NYAAA=')
    #                 if decrypted:
    #                     print('Decrypted: %s' % decrypted)
    #             except Exception as e:
    #                 pass
    #                 print('err', e)
