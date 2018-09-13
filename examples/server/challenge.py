from radius.attributes import *
from radius.auth import AuthRequest
from radius.server import Server


class CustomAuthRequest(AuthRequest):
    def __call__(self):
        result = self.authenticate()
        # if Access-Accept, change to Access-Challenge
        if result == AUTH_ACCEPT:
            result = AUTH_CHALLENGE
        return result

    def get_user_password(self):
        username = self.eap_identity if 'eap_identity' in self.__dict__ else self.username
        return 'fakepassword'


class CustomServer(Server):
    def get_mfa_code(self):
        return 12345

    def access_challenge(self, session_id, req_attrs):
        """Build the attributes to send in an Access-Challenge.
        :param attrs: [RFC 2865]: 'Reply-Message', 'State', 'Vendor-Specific', 'Idle-Timeout', 'Session-Timeout', 'Proxy-State'
        """
        attrs = OrderedDict({})
        attrs['State'] = session_id
        attrs['Session-Timeout'] = self.session_timeout
        attrs['Reply-Message'] = 'Challenge {0}. Please send your response.'.format(self.get_mfa_code())
        return attrs


if __name__ == "__main__":
    clients = {
        # Can be a single IP or CIDR
        '127.0.0.1': 'aXY8mAc4Bqi4G4tyyRgb0cwn8F1ee3oqyQWi8GE81#cANOuxAtCCL6LxxoVHwDrB',
    }
    server = CustomServer(clients, auth_request=CustomAuthRequest)
    server.start()
