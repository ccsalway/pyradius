import binascii
import os
import socket
import threading
import time
from hashlib import md5
import hmac, hashlib

from attributes import *
from auth import AuthRequest
from error import Error, Info
from logger import *

attributes = Attributes()


class Server(object):
    sock_clients = set()
    radius_clients = {}
    connections = {}
    sessions = {}

    connections_interval = 5
    connection_timeout = 10
    sessions_interval = 5
    session_timeout = 300

    auth_request = None

    def __init__(self, clients, auth_request=AuthRequest, bind_addr='', auth_port=1812, buff_size=4096):
        self.radius_clients = clients
        self.auth_request = auth_request
        self.bind_addr = bind_addr
        self.auth_port = auth_port
        self.buff_size = buff_size

    #
    # Connections
    #

    def cleanup_connections(self):
        """Prevents duplicate requests in a short time frame."""
        stopped = threading.Event()

        def loop():
            serverlog.debug("Checking for stale connections every {} seconds".format(self.connections_interval))
            while not stopped.wait(self.connections_interval):
                for k, v in self.connections.copy().items():
                    if not k.startswith('conn.'): continue
                    if time.time() - v[0] > self.connection_timeout:
                        serverlog.debug("Removing stale connection {}".format(k))
                        self.connections.pop(k, None)

        threading.Thread(target=loop).start()
        return stopped.set

    def _get_connection_id(self, raddr, ident):
        return 'conn.{}.{}.{}'.format(raddr[0], raddr[1], ident)

    def status_isprocessing(self, raddr, ident):
        auditlog.debug("{0}.{1} Checking for running processing request.".format(*raddr))
        return self._get_connection_id(raddr, ident) in self.connections

    def status_starting(self, raddr, ident):
        auditlog.debug("{0}.{1} Starting processing request.".format(*raddr))
        self.connections[self._get_connection_id(raddr, ident)] = (time.time(), 1)

    def status_finished(self, raddr, ident):
        auditlog.debug("{0}.{1} Finished processing request.".format(*raddr))
        self.connections.pop(self._get_connection_id(raddr, ident), None)

    #
    # Sessions
    #

    def cleanup_sessions(self):
        """The amount of time allowed to respond to a challenge."""
        stopped = threading.Event()

        def loop():
            serverlog.debug("Checking for aged sessions every {} seconds".format(self.sessions_interval))
            while not stopped.wait(self.sessions_interval):
                for k, v in self.sessions.copy().items():
                    if time.time() - v[0] > self.session_timeout:
                        serverlog.debug("Removing aged session {}".format(k))
                        self.sessions.pop(k, None)

        threading.Thread(target=loop).start()
        return stopped.set

    def create_session(self, attr, raddr):
        session_id = binascii.hexlify(os.urandom(32))
        auditlog.debug("{1}.{2} Saving session '{0}'.".format(session_id, *raddr))
        self.sessions[session_id] = (time.time(), attr)
        return session_id

    def get_session(self, session_id, raddr):
        auditlog.debug("{1}.{2} Getting session '{0}'.".format(session_id, *raddr))
        state = self.sessions.pop(session_id, None)
        return state[1] if state else None

    #
    # Start
    #

    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            serverlog.info("Starting Auth Server on {0}:{1}".format(self.bind_addr, self.auth_port))
            sock.bind((self.bind_addr, self.auth_port))
            local_addr = sock.getsockname()
            serverlog.info("Listening on {0}.{1}".format(*local_addr))
            cleanup_connections = self.cleanup_connections()
            cleanup_sessions = self.cleanup_sessions()
            try:
                while True:
                    data, remote_addr = sock.recvfrom(self.buff_size)
                    threading.Thread(target=self.request_handler(sock, remote_addr, data)).start()
            finally:
                cleanup_connections()
                cleanup_sessions()
        except socket.error as e:
            exit(e)
        except KeyboardInterrupt:
            serverlog.info("Received Keyboard Interrupt. Shutting down.")
        finally:
            for client in self.sock_clients:
                client.shutdown(socket.SHUT_RDWR)
                client.close()

    #
    # REQUEST
    #

    def lookup_host(self, raddr):
        ip_addr = IPAddress(raddr[0])
        for cidr, secret in self.radius_clients.items():
            if ip_addr in IPNetwork(cidr):
                return secret

    def request_handler(self, sock, raddr, data):
        self.sock_clients.add(raddr)
        try:
            # check data length
            data_length = len(data)
            auditlog.debug("{1}.{2} Received {0} bytes".format(data_length, *raddr))
            if data_length < 20:
                raise Error("Discarding request. Data length less than minimum length of 20.")
            # check host known
            secret = self.lookup_host(raddr)
            if not secret or len(secret) == 0:
                raise Error("Discarding request. Secret is empty (length 0).")
            # unpack request
            code, ident, length = unpack('!BBH', data[:4])
            auditlog.debug("{3}.{4} Received Code {0} Ident {1} Length {2}".format(code, ident, length, *raddr))
            if code not in (1, 2, 3, 4, 5, 11, 12, 13, 255):
                raise Error("Discarding request. Unknown RADIUS code {0}.".format(code))
            # check length
            if data_length < length:
                raise Error("Discarding request. Actual length of data is less than specified.")
            # duplicate test
            if self.status_isprocessing(raddr, ident):
                raise Info("Discarding request. Duplicate request.")
            # request authenticator
            authenticator = unpack('!16s', data[4:20])[0]  # 16 random numbers [0..255]
            # attributes
            attrs = attributes.unpack_attributes(data[20:length])  # ignore out-of-bounds data which could be padding
            auditlog.debug("{1}.{2} Received: {0}".format(', '.join(['{}: {}'.format(k, attrs[k]) for k in attrs]), *raddr))
            # Check Message-Authenticator
            if 'Message-Authenticator' in attrs:
                # Message-Authenticator = HMAC-MD5(Secret, Type + Identifier + Length + RequestAuthenticator + Attributes)
                message_authenticator = self.message_authenticator(secret, code, ident, attrs.copy(), authenticator)
                if attrs['Message-Authenticator'][0] != message_authenticator:
                    raise Error("Discarding request. Invalid Message-Authenticator.")
            # process
            self.status_starting(raddr, ident)
            try:
                if code == AUTH_REQUEST:
                    result = self.auth_request(self, raddr, attrs, authenticator, secret)()
                    if result == AUTH_ACCEPT:
                        resp_attrs = self.access_accept(attrs)
                    elif result == AUTH_CHALLENGE:
                        resp_attrs = self.access_challenge(attrs, raddr)
                    else:  # AUTH_REJECT
                        resp_attrs = self.access_reject(attrs)
                    # Add Message-Authenticator
                    resp_attrs['Message-Authenticator'] = self.message_authenticator(secret, result, ident, resp_attrs, authenticator)
                    # Send Response
                    self.send_response(sock, raddr, ident, result, authenticator, resp_attrs, secret)
                else:
                    serverlog.error("Unhandled RADIUS code received {} from {}.{}".format(code, *raddr))
            finally:
                self.status_finished(raddr, ident)
        except Info as e:
            auditlog.info("{1}.{2} {0}".format(e, *raddr))
        except Error as e:
            auditlog.error("{1}.{2} {0}".format(e, *raddr))
        except Exception as e:
            serverlog.exception(e)
        finally:
            self.sock_clients.remove(raddr)

    #
    # RESPONSE
    #

    def access_accept(self, req_attrs):
        """Build the attributes to send in an Access-Accept."""
        return OrderedDict({})

    def access_reject(self, req_attrs):
        """Build the attributes to send in an Access-Reject."""
        return OrderedDict({})

    def access_challenge(self, req_attrs, raddr):
        """Build the attributes to send in an Access-Challenge."""
        attrs = OrderedDict({})
        # attrs['State'] = self.create_session('Session-Data', raddr)
        # attrs['Session-Timeout'] = self.session_timeout
        # attrs['Reply-Message'] = 'Challenge xyz. Please send your response.'
        return attrs

    def pack_header(self, code, ident, length_attrs, authenticator):
        # Code + ID + Length + ResponseAuth
        return pack('!BBH16s', code, ident, 20 + length_attrs, authenticator)

    def authenticator(self, code, ident, req_authenticator, attrs, secret):
        # MD5(Code + ID + Length + RequestAuth + Attributes + Secret)
        len_attrs, len_secret = len(attrs), len(secret)
        p = pack('!BBH16s{}s{}s'.format(len_attrs, len_secret), code, ident, 20 + len_attrs, req_authenticator, attrs, secret)
        return md5(p).digest()

    def message_authenticator(self, secret, code, ident, attrs, authenticator):
        # HMAC_MD5(Secret, Code + ID + Length + RequestAuth + Attributes)
        attrs['Message-Authenticator'] = 16 * b'\x00'
        pa = attributes.pack_attributes(attrs)
        p = pack("!BBH16s{}s".format(len(pa)), code, ident, 20 + len(pa), authenticator, pa)
        return hmac.new(secret, p).digest()

    def send_response(self, sock, raddr, ident, code, req_authenticator, attrs, secret):
        auditlog.debug("{1}.{2} Sending: {0}".format(', '.join(['{}: {}'.format(k, attrs[k]) for k in attrs]), *raddr))
        pattrs = attributes.pack_attributes(attrs)
        authenticator = self.authenticator(code, ident, req_authenticator, pattrs, secret)
        data = [self.pack_header(code, ident, len(pattrs), authenticator), pattrs]
        sock.sendto(b''.join(data), raddr)


if __name__ == "__main__":
    radius_clients = {
        # Can be a single IP or CIDR
        '127.0.0.1': 'aXY8mAc4Bqi4G4tyyRgb0cwn8F1ee3oqyQWi8GE81#cANOuxAtCCL6LxxoVHwDrB',
    }

    server = Server(radius_clients)
    server.start()
