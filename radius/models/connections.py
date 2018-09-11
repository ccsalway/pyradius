import os
import time
from threading import Event, Thread, current_thread

from ..config import logger, connection_stale

connectionsFlag = Event()


class Connections(Thread):
    """Stores active requests to prevent duplicate requests."""

    def __init__(self, event):
        Thread.__init__(self)
        self.stopped = event

    def run(self):
        """Remove stale connections."""
        while not self.stopped.wait(30):
            logger.debug("Checking for stale connections")
            for k, v in self.__dict__.copy().items():
                if not k.startswith('conn.'): continue
                if time.time() - v[0] > connection_stale:
                    logger.debug("Removing stale connection {}".format(k))
                    self.__delattr__(k)

    def cancel(self):
        connectionsFlag.set()


connections = Connections(connectionsFlag)
connections.start()


def status_isprocessing(raddr, ident):
    logger.debug("Checking if request still running for {}.{}:{} [{}:{}]".format(raddr[0], raddr[1], ident, os.getpid(), current_thread().name))
    return getattr(connections, 'conn.{}.{}.{}'.format(raddr[0], raddr[1], ident), None)


def status_starting(raddr, ident):
    logger.debug("Starting processing request for {}.{}:{} [{}:{}]".format(raddr[0], raddr[1], ident, os.getpid(), current_thread().name))
    setattr(connections, 'conn.{}.{}.{}'.format(raddr[0], raddr[1], ident), (time.time(), 1))


def status_finished(raddr, ident):
    logger.debug("Finished processing request for {}.{}:{} [{}:{}]".format(raddr[0], raddr[1], ident, os.getpid(), current_thread().name))
    delattr(connections, 'conn.{}.{}.{}'.format(raddr[0], raddr[1], ident))
