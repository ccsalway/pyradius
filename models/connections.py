import os
import threading
import time

from config import logger


class Connections(object):
    """Stores active requests to prevent duplicate requests."""

    def __init__(self):
        """Self cleaning."""
        pass


connections = Connections()


def status_isprocessing(raddr, ident):
    logger.debug("Checking if request still running for {}.{}:{} [{}:{}]".format(raddr[0], raddr[1], ident, os.getpid(), threading.current_thread().name))
    return getattr(connections, '{}.{}.{}'.format(raddr[0], raddr[1], ident), None)


def status_starting(raddr, ident):
    logger.debug("Starting processing request for {}.{}:{} [{}:{}]".format(raddr[0], raddr[1], ident, os.getpid(), threading.current_thread().name))
    setattr(connections, '{}.{}.{}'.format(raddr[0], raddr[1], ident), (time.time(), 1))


def status_finished(raddr, ident):
    logger.debug("Finished processing request for {}.{}:{} [{}:{}]".format(raddr[0], raddr[1], ident, os.getpid(), threading.current_thread().name))
    delattr(connections, '{}.{}.{}'.format(raddr[0], raddr[1], ident))
