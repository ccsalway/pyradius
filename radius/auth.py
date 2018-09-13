from hashlib import md5

import six

from attributes import *
from error import Error
from logger import auditlog


class AuthRequest(object):
    username = None
    eap_identity = None

    def __init__(self, server, raddr, attrs, authenticator, secret):
        self.server = server
        self.attrs = attrs
        self.raddr = raddr
        self.authenticator = authenticator
        self.secret = secret

    def __call__(self):
        return self.authenticate()

    def authenticate(self):
        try:
            # Message Authenticator
            if 'Message-Authenticator' in self.attrs:
                pass
            # Username
            if 'User-Name' in self.attrs:
                self.username = self.attrs['User-Name'][0]
            # Challenge Response
            if 'State' in self.attrs:
                if self.verify_challenge():
                    self.auditlog('Access-Accept')
                    return AUTH_ACCEPT
            # EAP
            elif 'EAP-Message' in self.attrs:
                if 'Message-Authenticator' not in self.attrs:
                    raise Error("Discarding request. EAP-Message received without Message-Authenticator.")
                eap_code, eap_id, eap_type, eap_data = self.unpack_eap_message()
                if not 1 <= eap_code <= 4:
                    raise Error("Discarding request. Unknown EAP-Message code '{0}'".format(eap_code))
                if eap_type not in (1, 2, 3, 4, 5, 6, 254, 255):
                    raise Error("Discarding request. Unknown EAP-Message type '{0}'".format(eap_type))
                if eap_type == 1:  # Identity
                    self.eap_identity = eap_data
                    auditlog.debug("{1}.{2} EAP-Identity: {0}".format(repr(self.eap_identity), *self.raddr))
            # CHAP
            elif 'CHAP-Password' in self.attrs:
                if self.verify_chap_password(self.get_user_password()):
                    self.auditlog('Access-Accept')
                    return AUTH_ACCEPT
            # PAP
            elif 'User-Password' in self.attrs:
                if self.verify_pap_password(self.get_user_password()):
                    self.auditlog('Access-Accept')
                    return AUTH_ACCEPT
        except Error as e:
            auditlog.error("{1}.{2} {0}".format(e, *self.raddr))
        self.auditlog('Access-Reject')
        return AUTH_REJECT

    def auditlog(self, code):
        auditlog.info("{2}.{3} {0} for '{1}'.".format(code, self.username, *self.raddr))

    def unpack_eap_message(self):
        eap_msg = ''.join(self.attrs['EAP-Message'])  # EAP-Message attribute (concat)
        eap_code, eap_id, length, eap_type = unpack('!BBHB', eap_msg[:5])
        eap_data = unpack('!{}s'.format(length - 5), eap_msg[5:length])[0]
        return eap_code, eap_id, eap_type, eap_data

    def verify_chap_password(self, plain_password):
        """With CHAP, the Secret is not used!"""
        # id, password
        chap_password = self.attrs['CHAP-Password'][0]
        if len(chap_password) != 19:  # RFC2865
            # raise Error("{1}.{2} Invalid CHAP-Password length ({0}).".format(len(chap_password), *self.raddr))
            auditlog.warning("{1}.{2} Invalid CHAP-Password length {0}, should be 19.".format(len(chap_password), *self.raddr))
        chapid, chappswd = chap_password[0], chap_password[1:]
        # challenge
        chap_challenge = self.authenticator
        if 'CHAP-Challenge' in self.attrs:
            chap_challenge = self.attrs['CHAP-Challenge'][0]
        # comparison
        return chappswd == md5("{}{}{}".format(chapid, plain_password, chap_challenge)).digest()

    def verify_pap_password(self, plain_password):
        buf = self.attrs['User-Password'][0]
        # RFC says maximum length == 128 characters, but ignoring rule
        if len(buf) % 16 != 0:
            raise Error("Invalid User-Password length.")
        pw = six.b('')
        last = self.authenticator
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
            return plain_password == pw.decode('utf-8')
        except UnicodeDecodeError:
            raise Error("Invalid secret or User-Password.")

    def verify_challenge(self):
        return False

    def get_user_password(self):
        # Default password. Override method in production.
        return 'fakepassword'
