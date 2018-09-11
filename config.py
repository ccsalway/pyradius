import logging

BIND_ADDR = ''
AUTH_PORT = 1812
BUFF_SIZE = 8192

logging.basicConfig(level="DEBUG", format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

connections_ttl = 30
states_ttl = 600

CLIENTS = {
    # Can be a single IP or CIDR
    '127.0.0.1': 'Kah3choteereethiejeimaeziecumi',
    '10.0.0.0/16': 'XuMsFsQmfygQJvCg'
}
