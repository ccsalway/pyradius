import socket
from logger import clientlog
from collections import OrderedDict
from hashlib import md5
from struct import pack, unpack
from attributes import *
from error import Error
import six
from netaddr import IPAddress, IPNetwork
import os

addr = '127.0.0.1'
auth_port = 1812

attributes = Attributes()

class Client(object):
    def request_authenticator(self):
        return os.urandom(16)

    def pack_header(self, code, length_attrs, authenticator):
        return pack('!BBH16s', code, self.req_ident, 20 + length_attrs, authenticator)

    def pack_attributes(self, attrs):
        if not attrs:
            return b''
        data = []
        for name, values in attrs.items():
            if not isinstance(values, list):
                values = [values]
            for value in values:
                code = attributes.get_code(name)
                if code is None:
                    raise AttributeError("Unknown attribute name '{}'".format(name))
                val = self.encode_attribute(code, value)
                length = len(val)
                data.append(pack('!BB{}s'.format(length), code, length + 2, val))
        return b''.join(data)

    def encode_attribute(self, code, value):
        typ = attributes.get_type(code)
        if typ in ('text', 'string', 'concat'):
            if typ == 'concat':
                value = b''.join(value)
            try:
                return value.encode('utf-8')
            except UnicodeDecodeError:
                return value
        elif typ == 'integer':
            return pack('!I', int(value))
        elif typ == "ipv4addr":
            return IPAddress(value).packed
        elif typ == "enum":
            return pack('!I', attributes.get_enum_code(code, value))
        raise Error("{2}.{3} Discarding request. Unhandled attribute '{0} {1}'.".format(code, typ, *self.raddr))

    def send_auth(self):
        attrs = OrderedDict[{}]

        pattrs = self.pack_attributes(attrs)
        req_auth = self.request_authenticator()

        data = []
        data.append(self.pack_header(AUTH_REQUEST, len(pattrs), req_auth))
        data.append(pattrs)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto('', (addr, auth_port))
        except socket.error as e:
            exit(e)
        except KeyboardInterrupt:
            clientlog.info("Received Keyboard Interrupt. Shutting down.")
        finally:
            sock.close()
