import socket
import threading
import time

from auth import AuthRequest
from logger import *


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
                    threading.Thread(target=self.auth_request(self, sock, remote_addr, data)).start()
            finally:
                cleanup_connections()
                cleanup_sessions()
        except socket.error as e:
            exit(e)
        except KeyboardInterrupt:
            serverlog.info("Received Keyboard Interrupt. Shutting down.")
        finally:
            sock.close()


if __name__ == "__main__":
    radius_clients = {
        # Can be a single IP or CIDR
        '127.0.0.1': 'aXY8mAc4Bqi4G4tyyRgb0cwn8F1ee3oqyQWi8GE81#cANOuxAtCCL6LxxoVHwDrB',
    }

    server = Server(radius_clients)
    server.start()
