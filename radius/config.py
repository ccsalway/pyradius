import logging

BIND_ADDR = ''
AUTH_PORT = 1812
BUFF_SIZE = 8192

logging.basicConfig(level="DEBUG", format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

session_timeout = 300  # the amount of time a client has to respond to a challenge
connection_stale = 300  # should be >= session_timeout

CLIENTS = {
    # Can be a single IP or CIDR
    '127.0.0.1': 'Kah3choteereethiejeimaeziecumi',
    '10.0.0.0/16': 'XuMsFsQmfygQJvCg'
}
