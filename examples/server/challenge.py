import pyotp

from radius.attributes import *
from radius.auth import AuthRequest
from radius.logger import auditlog
from radius.server import Server


class CustomAuthRequest(AuthRequest):
    def __call__(self):
        """
        If initial login successful, we want to challenge the user's MFA.
        'State' is not in the initial Access-Request. It MUST be passed back
         in with the response to the Auth-Challenge for the response to be verified.
        """
        result = self.authenticate()
        if result == AUTH_ACCEPT and 'State' not in self.attrs:
            result = AUTH_CHALLENGE
        return result

    def get_username(self):
        if 'eap_identity' in self.__dict__:
            return self.eap_identity
        return self.username

    def get_user_password(self):
        username = self.get_username()  # can be used to do a pswd lookup
        return 'fakepassword'

    def get_user_totp(self):
        username = self.get_username()  # can be used to do a TOTP code lookup
        totp = pyotp.TOTP('base32secret3232')
        return totp.now()

    def verify_challenge(self):
        state = self.server.get_session(self.attrs['State'][0], self.raddr)
        if not state:
            auditlog.debug("{0}.{1} State not found or expired.".format(*self.raddr))
            return False
        # current TOTP code
        totp = self.get_user_totp()
        # compare current TOTP with passed-in
        if 'CHAP-Password' in self.attrs:
            if self.verify_chap_password(totp):
                return True
        elif 'User-Password' in self.attrs:
            if self.verify_pap_password(totp):
                return True
        return False


class CustomServer(Server):
    def access_challenge(self, req_attrs, raddr):
        attrs = OrderedDict({})
        attrs['State'] = self.create_session('TOTP', raddr)
        attrs['Session-Timeout'] = self.session_timeout
        attrs['Reply-Message'] = 'Secret: '
        return attrs


if __name__ == "__main__":
    clients = {
        # Can be a single IP or CIDR
        '127.0.0.1': 'aXY8mAc4Bqi4G4tyyRgb0cwn8F1ee3oqyQWi8GE81#cANOuxAtCCL6LxxoVHwDrB',
    }
    server = CustomServer(clients, auth_request=CustomAuthRequest)
    server.start()
