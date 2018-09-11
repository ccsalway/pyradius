import os
import time
from threading import Event, Thread, current_thread

from config import logger, states_ttl

statesFlag = Event()


class States(Thread):
    """
    Stores State between challenges.
    Removes old states after states_ttl seconds
    """

    def __init__(self, event):
        Thread.__init__(self)
        self.stopped = event

    def run(self):
        while not self.stopped.wait(30):
            logger.debug("Checking for stale states")
            for k, v in self.__dict__.copy().items():
                if not k.startswith('state.'): continue
                if time.time() - v[0] > states_ttl:
                    logger.debug("Removing stale state {}".format(k))
                    self.__delattr__(k)

    def cancel(self):
        statesFlag.set()


states = States(statesFlag)
states.start()


def get_state(raddr, ident):
    logger.debug("Getting state for {}.{}:{} [{}:{}]".format(raddr[0], raddr[1], ident, os.getpid(), current_thread().name))
    return getattr(states, 'state.{}.{}.{}'.format(raddr[0], raddr[1], ident), None)


def create_state(raddr, ident, attr):
    logger.debug("Saving state for {}.{}:{} [{}:{}]".format(raddr[0], raddr[1], ident, os.getpid(), current_thread().name))
    setattr(states, 'state.{}.{}.{}'.format(raddr[0], raddr[1], ident), (time.time(), attr))  # timestamps the state for garbage collection


def delete_state(raddr, ident):
    logger.debug("Deleting state for {}.{}:{} [{}:{}]".format(raddr[0], raddr[1], ident, os.getpid(), current_thread().name))
    delattr(states, 'state.{}.{}.{}'.format(raddr[0], raddr[1], ident))
