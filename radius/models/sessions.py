import logging
import time
from threading import Event, Thread

logger = logging.getLogger(__name__)

session_timer = 30  # the delay in seconds to check for stale sessions
session_timeout = 300  # the amount of time in seconds a client has to respond to a challenge


class Sessions(Thread):
    """Stores State between challenges."""

    def __init__(self, event):
        Thread.__init__(self)
        self.event = event

    def run(self):
        """Removes aged sessions."""
        logger.debug("0.0.0.0.0 Started checking for aged sessions every {} seconds".format(session_timer))
        while not self.event.wait(session_timer):
            logger.debug("0.0.0.0.0 Checking for aged sessions")
            for k, v in self.__dict__.copy().items():
                if not k.startswith('state.'): continue
                if time.time() - v[0] > session_timeout:
                    logger.debug("0.0.0.0.0 Removing aged session {}".format(k))
                    self.__delattr__(k)

    def cancel(self):
        self.event.set()


sessions = Sessions(Event())


def set_session_timeout(timeout):
    global session_timeout
    session_timeout = timeout


def _get_session_id(raddr, ident):
    return 'session.{}.{}.{}'.format(raddr[0], raddr[1], ident)


def get_session(raddr, ident):
    session_id = _get_session_id(raddr, ident)
    logger.debug("{1}.{2} Getting session '{0}'.".format(session_id, *raddr))
    return getattr(sessions, session_id, None)


def create_session(raddr, ident, attr):
    session_id = _get_session_id(raddr, ident)
    logger.debug("{1}.{2} Saving session '{0}'.".format(session_id, *raddr))
    setattr(sessions, session_id, (time.time(), attr))
    return session_id


def delete_session(raddr, ident):
    session_id = _get_session_id(raddr, ident)
    logger.debug("{1}.{2} Deleting session '{0}'.".format(session_id, *raddr))
    delattr(sessions, session_id)
