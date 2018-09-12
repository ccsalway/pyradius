from collections import OrderedDict
from hashlib import md5
from struct import pack, unpack

import six
from netaddr import IPAddress, IPNetwork

from attributes import *
from error import Error, Info
from logger import serverlog, auditlog

attributes = Attributes()


class AuthRequest(object):
    def __init__(self, server, sock, remote_addr, data):
        self.server = server
        self.clients = server.clients
        self.sock = sock
        self.raddr = remote_addr
        self.data = data
        self.length = len(data)

    def lookup_host(self):
        ip_addr = IPAddress(self.raddr[0])
        for cidr, secret in self.clients.items():
            if ip_addr in IPNetwork(cidr):
                if len(secret) == 0:
                    raise Error("{0}.{1} Discarding request. Secret is empty (length 0).".format(*self.raddr))
                self.secret = secret
                return
        raise Error("{0}.{1} Discarding request. Unknown Host.".format(*self.raddr))

    def decode_attribute(self, code, value):
        typ = attributes.get_type(code)
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
            value = attributes.get_enum_text(code, key)
        return value

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

    def unpack_request(self):
        self.req_code, self.req_ident, self.req_length = unpack('!BBH', self.data[:4])
        if self.length < self.req_length:
            raise Error("{0}.{1} Discarding request. Actual length of data is less than specified.".format(*self.raddr))
        self.req_authenticator = unpack('!16s', self.data[4:20])[0]
        self.unpack_attributes()

    def unpack_attributes(self):
        # code(1), length(2), value(length-3)
        pos, attrs = 20, OrderedDict({})
        while pos < self.req_length:  # ignore out-of-bounds data which could be padding
            code, length = unpack('!BB', self.data[pos:pos + 2])
            value = self.decode_attribute(code, self.data[pos + 2:pos + length])
            name = attributes.get_name(code)
            attrs.setdefault(name, []).append(value)
            pos += length
        auditlog.debug("{1}.{2} Received: {0}".format(', '.join(['{}: {}'.format(k, attrs[k]) for k in attrs]), *self.raddr))
        self.req_attrs = attrs

    def unpack_eap_message(self):
        eap_msg = ''.join(self.req_attrs['EAP-Message'])  # EAP-Message attribute (concat)
        self.eap_code, self.eap_reqid, length, self.eap_type = unpack('!BBHB', eap_msg[:5])
        self.eap_data = unpack('!{}s'.format(length - 5), eap_msg[5:length])[0]

    def get_user_password(self):
        # Default password. Override method in production.
        return 'fakepassword'

    def verify_pap_password(self):
        plain_pswd = self.get_user_password()
        buf = self.req_attrs['User-Password'][0]
        # RFC says length max length == 128 characters but ignoring restriction
        if len(buf) % 16 != 0:
            raise Error("{0}.{1} Invalid User-Password length.".format(*self.raddr))
        pw = six.b('')
        last = self.req_authenticator
        while buf:
            _hash = md5(self.secret + last).digest()
            if six.PY3:
                for i in range(16):
                    pw += bytes((_hash[i] ^ buf[i],))
            else:
                for i in range(16):
                    pw += chr(ord(_hash[i]) ^ ord(buf[i]))
            (last, buf) = (buf[:16], buf[16:])
        while pw.endswith(six.b('\x00')):
            pw = pw[:-1]
        try:
            return plain_pswd == pw.decode('utf-8')
        except UnicodeDecodeError:
            raise Error("{0}.{1} Invalid secret or User-Password.".format(*self.raddr))

    def verify_chap_password(self):
        """With CHAP, the Secret is not used!"""
        plain_pswd = self.get_user_password()
        # id, password
        chap_password = self.req_attrs['CHAP-Password'][0]
        if len(chap_password) != 19:  # RFC2865
            # raise Error("{1}.{2} Invalid CHAP-Password length ({0}).".format(len(chap_password), *self.raddr))
            auditlog.warning("{1}.{2} Invalid CHAP-Password length {0}, should be 19.".format(len(chap_password), *self.raddr))
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

    #
    # REQUEST
    #

    def __call__(self, *args, **kwargs):
        try:
            auditlog.debug("{1}.{2} Received {0} bytes".format(self.length, *self.raddr))
            if self.length < 20:
                raise Error("{0}.{1} Discarding request. Data length less than minimum length of 20.".format(*self.raddr))
            # if len(data) > 4096:  # as per RFC but restricts the size of secrets
            #     raise Error("Discarding request from {0}.{1}. Data length more than maximum length of 4096.".format(*self.raddr))
            self.lookup_host()
            self.unpack_request()
            if self.server.status_isprocessing(self.raddr, self.req_ident):
                raise Info("{0}.{1} Discarding request. Duplicate request.".format(*self.raddr))
            else:
                self.server.status_starting(self.raddr, self.req_ident)
                try:
                    if self.req_code == ACCESS_REQUEST:
                        if self.process_access_request():
                            return self.process_response(ACCESS_ACCEPT)
                    raise Error("{1}.{2} Discarded request.  Unhandled/Unknown request code {0}".format(self.req_code, *self.raddr))
                finally:
                    self.server.status_finished(self.raddr, self.req_ident)
        except Info as e:
            auditlog.info(e.message)
        except Error as e:
            auditlog.error(e.message)
        except AttributeError as e:
            serverlog.error(e)
        except Exception as e:
            serverlog.exception(e)
        # default reject
        return self.process_response(ACCESS_REJECT)

    def process_access_request(self):
        # Message Authenticator
        if 'Message-Authenticator' in self.req_attrs:
            pass
        # Username
        if 'User-Name' in self.req_attrs:
            self.username = self.req_attrs['User-Name'][0]
        # EAP
        if 'EAP-Message' in self.req_attrs:
            if 'Message-Authenticator' not in self.req_attrs:
                raise Error("{0}.{1} Discarding request. EAP-Message received without Message-Authenticator".format(*self.raddr))
            self.unpack_eap_message()
            if not 1 <= self.eap_code <= 4:
                raise Error("{0}.{1} Discarding request. Unknown EAP-Message code '{0}'".format(self.eap_code, *self.raddr))
            if not (1 <= self.eap_type <= 6 or self.eap_type == 254 or self.eap_type == 255):
                raise Error("{0}.{1} Discarding request. Unknown EAP-Message type '{0}'".format(self.eap_type, *self.raddr))
            if self.eap_type == 1:  # Identity
                self.eap_identity = self.eap_data
                auditlog.debug("{1}.{2} EAP-Identity: {0}".format(repr(self.eap_identity), *self.raddr))
        # CHAP
        elif 'CHAP-Password' in self.req_attrs:
            return self.verify_chap_password()
        # PAP
        elif 'User-Password' in self.req_attrs:
            return self.verify_pap_password()
        return False

    #
    # RESPONSE
    #

    def process_response(self, code):
        if code == ACCESS_ACCEPT:
            self.response_accept()
        elif code == ACCESS_REJECT:
            self.response_reject()
        elif code == ACCESS_CHALLENGE:
            self.response_challenge()

    def response_accept(self):
        auditlog.info("{1}.{2} ACCESS_ACCEPT for '{0}'".format(self.username, *self.raddr))
        attrs = OrderedDict({})
        self.send_response(ACCESS_ACCEPT, attrs)

    def response_reject(self):
        auditlog.info("{1}.{2} ACCESS_REJECT for '{0}'".format(self.username, *self.raddr))
        attrs = OrderedDict({})
        self.send_response(ACCESS_REJECT, attrs)

    def response_challenge(self):
        """
        :param attrs: [RFC 2865]: 'Reply-Message', 'State', 'Vendor-Specific', 'Idle-Timeout', 'Session-Timeout', 'Proxy-State'
        """
        auditlog.info("{1}.{2} ACCESS_CHALLENGE for '{0}'".format(self.username, *self.raddr))
        attrs = OrderedDict({})
        attrs['State'] = self.server.create_session(self.raddr, self.req_ident, self.req_attrs)
        attrs['Session-Timeout'] = self.server.session_timeout
        attrs['Reply-Message'] = 'Challenge to your auth request.'
        self.send_response(ACCESS_CHALLENGE, attrs)

    def send_response(self, code, attrs):
        auditlog.debug("{1}.{2} Sending: {0}".format(', '.join(['{}: {}'.format(k, attrs[k]) for k in attrs]), *self.raddr))
        attrs = self.pack_attributes(attrs)
        resp_auth = self.response_authenticator(code, attrs)
        data = [self.pack_header(code, len(attrs), resp_auth), attrs]
        self.sock.sendto(b''.join(data), self.raddr)
