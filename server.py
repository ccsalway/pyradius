import socket
from collections import OrderedDict
from hashlib import md5
from struct import pack, unpack

import six
from netaddr import IPAddress, IPNetwork

from config import *
from models.connections import *
from models.states import *
from values import *


class Error(Exception):
    """Custom Exception class."""
    pass


class AuthRequest(object):
    sock = None
    laddr = None
    raddr = None
    data = None
    secret = None

    attributes = Attributes()

    req_code = None
    req_ident = None
    req_length = 0
    req_authenticator = None
    req_attrs = OrderedDict({})

    username = None

    eap_code = None
    eap_reqid = None
    eap_type = None
    eap_data = None
    eap_identity = None

    def __init__(self, sock, local_addr, remote_addr, data):
        self.sock = sock
        self.laddr = local_addr
        self.raddr = remote_addr
        self.data = data

    def lookup_host(self):
        ip_addr = IPAddress(self.raddr[0])
        for cidr, secret in CLIENTS.items():
            if ip_addr in IPNetwork(cidr):
                self.secret = secret
                return secret
        raise Error("Dropping packet from unknown host {}".format(self.raddr[0]))

    def decode_attribute(self, code, value):
        typ = self.attributes.get_type(code)
        if typ in ('text', 'string'):
            try:
                value = value.decode('utf-8')
            except UnicodeDecodeError:
                pass
        elif typ == 'integer':
            value = unpack('!I', value)[0]
        elif typ == 'ipv4addr':
            value = '.'.join(map(str, unpack('!BBBB', value)))
        elif typ == 'ipv6addr':
            addr = value + b'\x00' * (16 - len(value))
            prefix = ':'.join(map('{0:x}'.format, unpack('!' + 'H' * 8, addr)))
            value = str(IPAddress(prefix))
        elif typ == 'ipv6prefix':
            addr = value + b'\x00' * (18 - len(value))
            _, length, prefix = ':'.join(map('{0:x}'.format, unpack('!BB' + 'H' * 8, addr))).split(":", 2)
            value = str(IPNetwork("%s/%s" % (prefix, int(length, 16))))
        elif typ == 'ifid':
            pass  # ??
        elif typ == 'enum':
            key = unpack('!I', value)[0]
            value = self.attributes.get_enum_text(code, key)
        return value

    def encode_attribute(self, code, value):
        typ = self.attributes.get_type(code)
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
            return pack('!I', self.attributes.get_enum_code(code, value))
        raise Error("Unhandled attribute '{0} {1}' from {3}.{4}:{2}".format(code, typ, self.req_ident, *self.raddr))

    def unpack_request(self):
        self.req_code, self.req_ident, self.req_length = unpack('!BBH', self.data[:4])
        self.req_authenticator = unpack('!16s', self.data[4:20])[0]
        self.unpack_attributes()

    def unpack_attributes(self):
        # code(1), length(2), value(length-3)
        pos, attrs = 20, OrderedDict({})
        while pos < len(self.data):
            code, length = unpack('!BB', self.data[pos:pos + 2])
            value = self.decode_attribute(code, self.data[pos + 2:pos + length])
            name = self.attributes.get_name(code)
            attrs.setdefault(name, []).append(value)
            pos += length
        logger.debug(', '.join(['{}: {}'.format(k, attrs[k]) for k in attrs]))
        self.req_attrs = attrs

    def unpack_eap_message(self):
        eap_msg = ''.join(self.req_attrs['EAP-Message'])  # EAP-Message attribute (concat)
        self.eap_code, self.eap_reqid, length, self.eap_type = unpack('!BBHB', eap_msg[:5])
        self.eap_data = unpack('!{}s'.format(length - 5), eap_msg[5:length])[0]

    def get_user_password(self):
        # Default password. Override in production.
        return u'Pa$$word123'.decode('utf-8')

    def verify_pap_password(self):
        plain_pswd = self.get_user_password()
        buf = self.req_attrs['User-Password'][0]
        pw = six.b('')
        last = self.req_authenticator
        while buf:
            hash = md5(self.secret + last).digest()
            for i in range(16):
                pw += chr(ord(hash[i]) ^ ord(buf[i]))
            (last, buf) = (buf[:16], buf[16:])
        while pw.endswith(six.b('\x00')):
            pw = pw[:-1]
        return plain_pswd == pw.decode('utf-8')

    def verify_chap_password(self):
        plain_pswd = self.get_user_password()
        # id, password
        chap_password = self.req_attrs['CHAP-Password'][0]
        chapid, password = chap_password[0], chap_password[1:]
        # challenge
        chap_challenge = self.req_authenticator
        if 'CHAP-Challenge' in self.req_attrs:
            chap_challenge = self.req_attrs['CHAP-Challenge'][0]
        # comparison
        return password == md5("{}{}{}".format(chapid, plain_pswd, chap_challenge)).digest()

    def response_authenticator(self, code, attrs):
        # ResponseAuth = MD5(Code + ID + Length + RequestAuth + Attributes + Secret) [RFC2865]
        len_attrs, len_secret = len(attrs), len(self.secret)
        p = pack('!BBH16s{}s{}s'.format(len_attrs, len_secret),
                 code,
                 self.req_ident,
                 20 + len_attrs,
                 self.req_authenticator,
                 attrs,
                 self.secret)
        return md5(p).digest()

    def pack_header(self, code, length_attrs, resp_authenticator):
        return pack('!BBH16s', code, self.req_ident, 20 + length_attrs, resp_authenticator)

    def pack_attributes(self, attrs):
        if not attrs: return b''
        data = []
        for name, values in attrs.items():
            for value in values:
                code = self.attributes.get_code(name)
                val = self.encode_attribute(code, value)
                length = len(val)
                data.append(pack('!BB{}s'.format(length), code, length + 2, val))
        return b''.join(data)

    #
    # REQUEST
    #

    def __call__(self, *args, **kwargs):
        logger.info("Received request from {0}.{1}".format(*self.raddr))
        try:
            self.lookup_host()
            self.unpack_request()
            if status_isprocessing(self.raddr, self.req_ident):
                logger.info("Ignoring repeat request from {1}.{2}:{0}".format(self.req_ident, *self.raddr))
            else:
                status_starting(self.raddr, self.req_ident)
                try:
                    time.sleep(9)
                    if self.req_code == ACCESS_REQUEST:
                        self.process_access_request()
                finally:
                    status_finished(self.raddr, self.req_ident)
        except Error as e:
            logger.warning(e.message)
        except Exception as e:
            logger.exception(e)

    def process_access_request(self):
        # Username
        if 'User-Name' in self.req_attrs:
            self.username = self.req_attrs['User-Name'][0]
        # EAP
        if 'EAP-Message' in self.req_attrs:
            if 'Message-Authenticator' not in self.req_attrs:
                raise Error("EAP-Message received without Message-Authenticator from {1}.{2}:{0}".format(self.req_ident, *self.raddr))
            self.unpack_eap_message()
            if not 1 <= self.eap_code <= 4:
                raise Error("Invalid EAP-Message code '{0}' from {2}.{3}:{1}".format(self.eap_code, self.req_ident, *self.raddr))
            if not (1 <= self.eap_type <= 6 or self.eap_type == 254 or self.eap_type == 255):
                raise Error("Invalid EAP-Message type '{0}' from {2}.{3}:{1}".format(self.eap_type, self.req_ident, *self.raddr))
            if self.eap_type == 1:  # Identity
                self.eap_identity = self.eap_data
                logger.debug("EAP-Identity: {0} from {2}.{3}:{1}".format(repr(self.eap_identity), self.req_ident, *self.raddr))
        # CHAP
        elif 'CHAP-Password' in self.req_attrs:
            if self.verify_chap_password():
                return self.process_access_response(ACCESS_ACCEPT)
        # PAP
        elif 'User-Password' in self.req_attrs:
            if self.verify_pap_password():
                return self.process_access_response(ACCESS_ACCEPT)
        # default reject
        return self.process_access_response(ACCESS_REJECT)

    #
    # RESPONSE
    #

    def process_access_response(self, code):
        attrs = OrderedDict({})
        # response
        if code == ACCESS_ACCEPT:
            self.response_accept(attrs)
        elif code == ACCESS_REJECT:
            self.response_reject(attrs)
        elif code == ACCESS_CHALLENGE:
            self.response_reject(attrs)

    def response_accept(self, attrs):
        logger.info("ACCESS_ACCEPT for '{0}' from {2}.{3}:{1}".format(self.username, self.req_ident, *self.raddr))
        attrs = self.pack_attributes(attrs)
        resp_auth = self.response_authenticator(ACCESS_ACCEPT, attrs)
        data = [self.pack_header(ACCESS_ACCEPT, len(attrs), resp_auth), attrs]
        sock.sendto(b''.join(data), self.raddr)

    def response_reject(self, attrs):
        logger.info("ACCESS_REJECT for '{0}' from {2}.{3}:{1}".format(self.username, self.req_ident, *self.raddr))
        attrs = self.pack_attributes(attrs)
        resp_auth = self.response_authenticator(ACCESS_REJECT, attrs)
        data = [self.pack_header(ACCESS_REJECT, len(attrs), resp_auth), attrs]
        sock.sendto(b''.join(data), self.raddr)

    def response_challenge(self, attrs):
        logger.info("ACCESS_CHALLENGE for '{0}' from {2}.{3}:{1}".format(self.username, self.req_ident, *self.raddr))
        attrs['State'] = '{2}.{3}.{1}'.format(self.req_ident, *self.raddr)
        attrs['Reply-Message'] = 'Challenge to your auth request.'
        attrs = self.pack_attributes(attrs)
        resp_auth = self.response_authenticator(ACCESS_CHALLENGE, attrs)
        data = [self.pack_header(ACCESS_CHALLENGE, len(attrs), resp_auth), attrs]
        sock.sendto(b''.join(data), self.raddr)


if __name__ == "__main__":
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        logger.info("Starting Radius Server on {}:{}".format(BIND_ADDR, AUTH_PORT))
        sock.bind((BIND_ADDR, AUTH_PORT))
        local_addr = sock.getsockname()
        logger.info("Started Radius Server on {}:{}".format(*local_addr))
        while True:
            data, remote_addr = sock.recvfrom(BUFF_SIZE)
            threading.Thread(target=AuthRequest(sock, local_addr, remote_addr, data)).start()
    except socket.error as e:
        exit(e)
    except KeyboardInterrupt:
        logger.info("Received KeyboardInterrupt. Shutting down.")
    finally:
        sock.close()
