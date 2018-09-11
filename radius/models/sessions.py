import os
import time
from threading import Event, Thread, current_thread

from ..config import logger, session_timeout

sessionsFlag = Event()


class Sessions(Thread):
    """Stores State between challenges."""

    def __init__(self, event):
        Thread.__init__(self)
        self.stopped = event

    def run(self):
        """Removes any aged sessions."""
        while not self.stopped.wait(30):
            logger.debug("Checking for aged sessions")
            for k, v in self.__dict__.copy().items():
                if not k.startswith('state.'): continue
                if time.time() - v[0] > session_timeout:
                    logger.debug("Removing aged session {}".format(k))
                    self.__delattr__(k)

    def cancel(self):
        sessionsFlag.set()


sessions = Sessions(sessionsFlag)
sessions.start()


def get_session(raddr, ident):
    logger.debug("Getting state for {}.{}:{} [{}:{}]".format(raddr[0], raddr[1], ident, os.getpid(), current_thread().name))
    return getattr(sessions, 'state.{}.{}.{}'.format(raddr[0], raddr[1], ident), None)


def create_session(raddr, ident, attr):
    logger.debug("Saving state for {}.{}:{} [{}:{}]".format(raddr[0], raddr[1], ident, os.getpid(), current_thread().name))
    setattr(sessions, 'state.{}.{}.{}'.format(raddr[0], raddr[1], ident), (time.time(), attr))


def delete_session(raddr, ident):
    logger.debug("Deleting state for {}.{}:{} [{}:{}]".format(raddr[0], raddr[1], ident, os.getpid(), current_thread().name))
    delattr(sessions, 'state.{}.{}.{}'.format(raddr[0], raddr[1], ident))
