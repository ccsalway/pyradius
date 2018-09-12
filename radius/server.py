import socket
import threading
import time
from hashlib import md5

from attributes import *
from auth import AuthRequest
from error import Error, Info
from logger import *

attributes = Attributes()


class Server(object):
    clients = {}
    connections = {}
    sessions = {}

    connections_interval = 5
    connection_timeout = 10
    sessions_interval = 5
    session_timeout = 600

    auth_request = AuthRequest

    def __init__(self, clients, bind_addr='', auth_port=1812, buff_size=4096):
        self.clients = clients
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
                    if not k.startswith('sess.'): continue
                    if time.time() - v[0] > self.session_timeout:
                        serverlog.debug("Removing aged session {}".format(k))
                        self.sessions.pop(k, None)

        threading.Thread(target=loop).start()
        return stopped.set

    def _get_session_id(self, raddr, ident):
        return 'sess.{}.{}.{}'.format(raddr[0], raddr[1], ident)

    def get_session(self, raddr, ident):
        session_id = self._get_session_id(raddr, ident)
        auditlog.debug("{1}.{2} Getting session '{0}'.".format(session_id, *raddr))
        return self.sessions.get(session_id, None)

    def create_session(self, raddr, ident, attr):
        session_id = self._get_session_id(raddr, ident)
        auditlog.debug("{1}.{2} Saving session '{0}'.".format(session_id, *raddr))
        self.sessions[session_id] = (time.time(), attr)
        return session_id

    def delete_session(self, raddr, ident):
        session_id = self._get_session_id(raddr, ident)
        auditlog.debug("{1}.{2} Deleting session '{0}'.".format(session_id, *raddr))
        self.sessions.pop(session_id, None)

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
            sock.close()

    #
    # REQUEST
    #

    def request_handler(self, sock, raddr, data):
        try:
            # check data length
            data_length = len(data)
            auditlog.debug("{1}.{2} Received {0} bytes".format(data_length, *raddr))
            if data_length < 20:
                raise Error("Discarding request. Data length less than minimum length of 20.")
            # check host known
            secret = self.lookup_host(raddr)
            if not secret:
                raise Error("Discarding request. Unknown Host.")
            # unpack request
            code, ident, length = unpack('!BBH', data[:4])  # header
            if code not in (1, 2, 3, 4, 5, 11, 12, 13, 255):
                raise Error("Discarding request. Unknown RADIUS code {0}.".format(code))
            if data_length < length:
                raise Error("Discarding request. Actual length of data is less than specified.")
            # duplicate test
            if self.status_isprocessing(raddr, ident):
                raise Info("Discarding request. Duplicate request.")
            # request authenticator
            authenticator = unpack('!16s', data[4:20])[0]  # random 16 numbers 0..255
            # attributes
            attrs = attributes.unpack_attributes(data[20:length])  # ignore out-of-bounds data which could be padding
            auditlog.debug("{1}.{2} Received: {0}".format(', '.join(['{}: {}'.format(k, attrs[k]) for k in attrs]), *raddr))
            # process
            self.status_starting(raddr, ident)
            try:
                # Access-Request
                if code == 1:
                    auth = self.auth_request(raddr, attrs, authenticator, secret)()
                    # Access-Accept
                    if auth.result == 2:
                        resp_attrs = self.access_accept(attrs)
                    # Access-Challenge
                    elif auth.result == 11:
                        session_id = self.create_session(raddr, ident, attrs)
                        resp_attrs = self.access_challenge(session_id, attrs)
                    # Access-Reject
                    else:
                        resp_attrs = self.access_reject(attrs)
                    # Send Response
                    self.send_response(sock, raddr, ident, code, authenticator, resp_attrs, secret)
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

    def lookup_host(self, raddr):
        ip_addr = IPAddress(raddr[0])
        for cidr, secret in self.clients.items():
            if ip_addr in IPNetwork(cidr):
                if len(secret) == 0:
                    raise Error("Discarding request. Secret is empty (length 0).")
                return secret

    #
    # RESPONSE
    #

    def access_accept(self, req_attrs):
        """Build the attributes to send in an Access-Accept."""
        return OrderedDict({})

    def access_reject(self, req_attrs):
        """Build the attributes to send in an Access-Reject."""
        return OrderedDict({})

    def access_challenge(self, session_id, req_attrs):
        """Build the attributes to send in an Access-Challenge.
        :param attrs: [RFC 2865]: 'Reply-Message', 'State', 'Vendor-Specific', 'Idle-Timeout', 'Session-Timeout', 'Proxy-State'
        """
        attrs = OrderedDict({})
        attrs['State'] = session_id
        attrs['Session-Timeout'] = self.session_timeout
        attrs['Reply-Message'] = 'Challenge to your auth request.'
        return attrs

    def pack_header(self, code, ident, length_attrs, authenticator):
        # Code + ID + Length + ResponseAuth
        return pack('!BBH16s', code, ident, 20 + length_attrs, authenticator)

    def authenticator(self, code, ident, req_authenticator, attrs, secret):
        # MD5(Code + ID + Length + RequestAuth + Attributes + Secret) [RFC2865]
        len_attrs, len_secret = len(attrs), len(secret)
        p = pack('!BBH16s{}s{}s'.format(len_attrs, len_secret),
                 code, ident, 20 + len_attrs, req_authenticator, attrs, secret)
        return md5(p).digest()

    def send_response(self, sock, raddr, ident, code, reqauth, attrs, secret):
        auditlog.debug("{1}.{2} Sending: {0}".format(', '.join(['{}: {}'.format(k, attrs[k]) for k in attrs]), *raddr))
        attrs = attributes.pack_attributes(attrs)
        authenticator = self.authenticator(code, ident, reqauth, attrs, secret)
        data = [self.pack_header(code, ident, len(attrs), authenticator), attrs]
        sock.sendto(b''.join(data), raddr)


if __name__ == "__main__":
    radius_clients = {
        # Can be a single IP or CIDR
        '127.0.0.1': 'aXY8mAc4Bqi4G4tyyRgb0cwn8F1ee3oqyQWi8GE81#cANOuxAtCCL6LxxoVHwDrB',
    }

    server = Server(radius_clients)
    server.start()
