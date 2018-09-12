from collections import OrderedDict

from radius.attributes import ACCESS_ACCEPT
from radius.auth import AuthRequest
from radius.server import Server

clients = {
    # Can be a single IP or CIDR
    '127.0.0.1': 'aXY8mAc4Bqi4G4tyyRgb0cwn8F1ee3oqyQWi8GE81#cANOuxAtCCL6LxxoVHwDrB',
}


class CustomAuthRequest(AuthRequest):
    def response_accept(self):
        attrs = OrderedDict({})
        attrs['NAS-Identifier'] = self.req_attrs['NAS-Identifier']  # echo test
        attrs['Reply-Message'] = ""
        self.send_response(ACCESS_ACCEPT, attrs)


server = Server(clients)
server.auth_request = CustomAuthRequest
server.start()
