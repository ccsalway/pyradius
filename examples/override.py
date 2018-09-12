from collections import OrderedDict

from radius.attributes import ACCESS_ACCEPT
from radius.auth import AuthRequest
from radius.logger import auditlog
from radius.server import Server

clients = {
    # Can be a single IP or CIDR
    '127.0.0.1': 'aXY8mAc4Bqi4G4tyyRgb0cwn8F1ee3oqyQWi8GE81#cANOuxAtCCL6LxxoVHwDrB',
}


class CustomAuthRequest(AuthRequest):
    def get_user_password(self):
        username = self.eap_identity if 'eap_identity' in self.__dict__ else self.username
        return 'fakepassword'

    def response_accept(self):
        auditlog.info("{1}.{2} ACCESS_ACCEPT for '{0}'".format(self.username, *self.raddr))
        attrs = OrderedDict({})
        attrs['NAS-Identifier'] = self.req_attrs['NAS-Identifier']  # echo test
        attrs['Reply-Message'] = "Welcome to RADIUS"
        self.send_response(ACCESS_ACCEPT, attrs)


server = Server(clients)
server.auth_request = CustomAuthRequest
server.start()
