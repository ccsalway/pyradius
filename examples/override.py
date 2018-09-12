from collections import OrderedDict

from radius.auth import AuthRequest
from radius.server import Server


class CustomAuthRequest(AuthRequest):
    def get_user_password(self):
        username = self.eap_identity if 'eap_identity' in self.__dict__ else self.username
        return 'fakepassword'


class CustomServer(Server):
    def access_accept(self, req_attrs):
        attrs = OrderedDict({})
        attrs['Reply-Message'] = "Welcome to RADIUS"
        # echo test
        attrs['NAS-Identifier'] = req_attrs['NAS-Identifier']
        attrs['User-Name'] = req_attrs['User-Name']
        return attrs


clients = {
    # Can be a single IP or CIDR
    '127.0.0.1': 'aXY8mAc4Bqi4G4tyyRgb0cwn8F1ee3oqyQWi8GE81#cANOuxAtCCL6LxxoVHwDrB',
}

server = CustomServer(clients)
server.auth_request = CustomAuthRequest
server.start()
