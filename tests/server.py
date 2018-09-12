from radius.server import Server
from radius.auth import AuthRequest
from radius.attributes import ACCESS_ACCEPT

clients = {
    # Can be a single IP or CIDR
    '127.0.0.1': 'aXY8mAc4Bqi4G4tyyRgb0cwn8F1ee3oqyQWi8GE81#cANOuxAtCCL6LxxoVHwDrB',
}


class CustomAuthRequest(AuthRequest):
    def response_accept(self, attrs):
        attrs['NAS-Identifier'] = self.req_attrs['NAS-Identifier']  # echo test
        attrs = self.pack_attributes(attrs)
        resp_auth = self.response_authenticator(ACCESS_ACCEPT, attrs)
        data = [self.pack_header(ACCESS_ACCEPT, len(attrs), resp_auth), attrs]
        self.sock.sendto(b''.join(data), self.raddr)


server = Server(clients)
server.auth_request = CustomAuthRequest
server.start()
