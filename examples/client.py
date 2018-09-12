import os
import random
import socket
from hashlib import md5
from select import select

import six

from radius.attributes import *
from radius.logger import clientlog

addr = '127.0.0.1'
auth_port = 1812
buff_size = 4096

secret = 'aXY8mAc4Bqi4G4tyyRgb0cwn8F1ee3oqyQWi8GE81#cANOuxAtCCL6LxxoVHwDrB'

attributes = Attributes()


def request_ident():
    return random.randint(0, 255)


def request_authenticator():
    return os.urandom(16)


def pack_header(code, ident, length_attrs, authenticator):
    return pack('!BBH16s', code, ident, 20 + length_attrs, authenticator)


def encrypt_pap_password(password, secret, authenticator):
    buf = password
    if len(password) % 16 != 0:
        buf += six.b('\x00') * (16 - (len(password) % 16))
    result = six.b('')
    last = authenticator
    while buf:
        hash = md5(secret + last).digest()
        if six.PY3:
            for i in range(16):
                result += bytes((hash[i] ^ buf[i],))
        else:
            for i in range(16):
                result += chr(ord(hash[i]) ^ ord(buf[i]))
        last, buf = result[-16:], buf[16:]
    return result


ident = request_ident()

authenticator = request_authenticator()

attrs = OrderedDict({
    'NAS-Identifier': 'client',
    'User-Name': 'fakeusername',
    'User-Password': encrypt_pap_password('fakepassword', secret, authenticator),
})

pattrs = attributes.pack_attributes(attrs)

data = [pack_header(AUTH_REQUEST, ident, len(pattrs), authenticator), pattrs]

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    print("Sending: {0}".format(', '.join(['{}: {}'.format(k, attrs[k]) for k in attrs])))
    sock.sendto(b''.join(data), (addr, auth_port))

    r, w, x = select([sock], [], [], 10)
    if sock in r:
        data, raddr = sock.recvfrom(buff_size)
        attrs = attributes.unpack_attributes(data[20:])
        print("Received: {0}".format(', '.join(['{}: {}'.format(k, attrs[k]) for k in attrs])))
    else:
        print("Timed out waiting for response.")

except socket.error as e:
    exit(e)
except KeyboardInterrupt:
    clientlog.info("Received Keyboard Interrupt. Shutting down.")
finally:
    sock.close()
    print("Closed connection.")
