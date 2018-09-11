import logging
import time
from threading import Event, Thread

logger = logging.getLogger(__name__)

connection_timer = 30  # the delay in seconds to check for stale connections
connection_stale = 310  # the delay in seconds to assume a connection is stale. (>= session_timeout)


class Connections(Thread):
    """Stores active requests to prevent duplicate requests."""

    def __init__(self, event):
        Thread.__init__(self)
        self.event = event

    def run(self):
        """Remove stale connections."""
        logger.debug("0.0.0.0.0 Started checking for stale connections every {} seconds".format(connection_timer))
        while not self.event.wait(connection_timer):
            logger.debug("0.0.0.0.0 Checking for stale connections")
            for k, v in self.__dict__.copy().items():
                if not k.startswith('conn.'): continue
                if time.time() - v[0] > connection_stale:
                    logger.debug("0.0.0.0.0 Removing stale connection {}".format(k))
                    self.__delattr__(k)

    def cancel(self):
        self.event.set()


connections = Connections(Event())


def set_connection_timeout(timeout):
    global connection_stale
    connection_stale = timeout


def _get_connection_id(raddr, ident):
    return 'conn.{}.{}.{}'.format(raddr[0], raddr[1], ident)


def status_isprocessing(raddr, ident):
    logger.debug("{0}.{1} Checking for running processing request.".format(*raddr))
    return getattr(connections, _get_connection_id(raddr, ident), None)


def status_starting(raddr, ident):
    logger.debug("{0}.{1} Starting processing request.".format(*raddr))
    setattr(connections, _get_connection_id(raddr, ident), (time.time(), 1))


def status_finished(raddr, ident):
    logger.debug("{0}.{1} Finished processing request.".format(*raddr))
    delattr(connections, _get_connection_id(raddr, ident))
