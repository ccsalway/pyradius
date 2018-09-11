import os
import threading
import time

from config import logger


class States(object):
    """Stores State between challenges."""

    def __init__(self):
        """Self cleaning."""
        pass


states = States()


def get_state(raddr, ident):
    logger.debug("Getting state for {}.{}:{} [{}:{}]".format(raddr[0], raddr[1], ident, os.getpid(), threading.current_thread().name))
    return getattr(states, '{}.{}.{}'.format(raddr[0], raddr[1], ident), None)


def create_state(raddr, ident, attr):
    logger.debug("Saving state for {}.{}:{} [{}:{}]".format(raddr[0], raddr[1], ident, os.getpid(), threading.current_thread().name))
    setattr(states, '{}.{}.{}'.format(raddr[0], raddr[1], ident), (time.time(), attr))  # timestamps the state for garbage collection


def delete_state(raddr, ident):
    logger.debug("Deleting state for {}.{}:{} [{}:{}]".format(raddr[0], raddr[1], ident, os.getpid(), threading.current_thread().name))
    delattr(states, '{}.{}.{}'.format(raddr[0], raddr[1], ident))
