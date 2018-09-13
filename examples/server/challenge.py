from radius.attributes import *
from radius.auth import AuthRequest
from radius.server import Server
from radius.logger import auditlog
import pyotp

class CustomAuthRequest(AuthRequest):
    def __call__(self):
        result = self.authenticate()
        if 'State' not in self.attrs and result == AUTH_ACCEPT:
            """After initial successful login, we want to challenge the user with MFA."""
            result = AUTH_CHALLENGE
        return result

    def get_user_password(self):
        username = self.eap_identity if 'eap_identity' in self.__dict__ else self.username
        return 'fakepassword'

    def get_mfa_code(self):
        totp = pyotp.TOTP('base32secret3232')
        return totp.now()

    def verify_challenge(self):
        # session contains the previous access-request attributes
        state = self.server.get_session(self.attrs['State'][0], self.raddr)
        if not state:
            auditlog.info("State not found or expired.")
            return False
        # check response
        if 'User-Password' in self.attrs:
            self.verify_pap_password(self.get)
        return False


class CustomServer(Server):
    def access_challenge(self, req_attrs, session_id):
        """Build the attributes to send in an Access-Challenge.
        :param attrs: [RFC 2865]: 'Reply-Message', 'State', 'Vendor-Specific', 'Idle-Timeout', 'Session-Timeout', 'Proxy-State'
        """
        attrs = OrderedDict({})
        attrs['State'] = session_id
        attrs['Session-Timeout'] = self.session_timeout
        attrs['Reply-Message'] = 'Please enter your current MFA secret'
        attrs['Prompt'] = 'Secret:'
        return attrs


if __name__ == "__main__":
    clients = {
        # Can be a single IP or CIDR
        '127.0.0.1': 'aXY8mAc4Bqi4G4tyyRgb0cwn8F1ee3oqyQWi8GE81#cANOuxAtCCL6LxxoVHwDrB',
    }
    server = CustomServer(clients, auth_request=CustomAuthRequest)
    server.start()
