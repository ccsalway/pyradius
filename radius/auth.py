from hashlib import md5

import six

from attributes import *
from error import Error
from logger import auditlog


class AuthRequest(object):
    username = None
    eap_identity = None

    def __init__(self, raddr, attrs, authenticator, secret):
        self.attrs = attrs
        self.raddr = raddr
        self.authenticator = authenticator
        self.secret = secret

    def __call__(self):
        self.result = result = self.check_access()
        if result == 2:
            auditlog.info("{1}.{2} ACCESS_ACCEPT for '{0}'".format(self.username, *self.raddr))
        elif result == 11:
            auditlog.info("{1}.{2} ACCESS_CHALLENGE for '{0}'".format(self.username, *self.raddr))
        else:
            auditlog.info("{1}.{2} ACCESS_REJECT for '{0}'".format(self.username, *self.raddr))
        return self

    def check_access(self):
        try:
            # Message Authenticator
            if 'Message-Authenticator' in self.attrs:
                pass
            # Username
            if 'User-Name' in self.attrs:
                self.username = self.attrs['User-Name'][0]
            # EAP
            if 'EAP-Message' in self.attrs:
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
                if self.verify_chap_password():
                    return 2  # Access-Accept
            # PAP
            elif 'User-Password' in self.attrs:
                if 'State' in self.attrs:  # Challenge Response
                    pass
                elif self.verify_pap_password():
                    return 2  # Access-Accept
        except Error as e:
            auditlog.error("{1}.{2} {0}".format(e, *self.raddr))
        return 3  # Access-Reject

    def unpack_eap_message(self):
        eap_msg = ''.join(self.attrs['EAP-Message'])  # EAP-Message attribute (concat)
        eap_code, eap_id, length, eap_type = unpack('!BBHB', eap_msg[:5])
        eap_data = unpack('!{}s'.format(length - 5), eap_msg[5:length])[0]
        return eap_code, eap_id, eap_type, eap_data

    def verify_chap_password(self):
        """With CHAP, the Secret is not used!"""
        plain_pswd = self.get_user_password()
        # id, password
        chap_password = self.attrs['CHAP-Password'][0]
        if len(chap_password) != 19:  # RFC2865
            # raise Error("{1}.{2} Invalid CHAP-Password length ({0}).".format(len(chap_password), *self.raddr))
            auditlog.warning("{1}.{2} Invalid CHAP-Password length {0}, should be 19.".format(len(chap_password), *self.raddr))
        chapid, password = chap_password[0], chap_password[1:]
        # challenge
        chap_challenge = self.authenticator
        if 'CHAP-Challenge' in self.attrs:
            chap_challenge = self.attrs['CHAP-Challenge'][0]
        # comparison
        return password == md5("{}{}{}".format(chapid, plain_pswd, chap_challenge)).digest()

    def verify_pap_password(self):
        plain_pswd = self.get_user_password()
        buf = self.attrs['User-Password'][0]
        # RFC says length max length == 128 characters but ignoring restriction
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
            return plain_pswd == pw.decode('utf-8')
        except UnicodeDecodeError:
            raise Error("Invalid secret or User-Password.")

    def get_user_password(self):
        # Default password. Override method in production.
        return 'fakepassword'
