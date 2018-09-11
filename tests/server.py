from radius.server import Server

clients = {
    # Can be a single IP or CIDR
    '127.0.0.1': 'Kah3choteereethiejeimaeziecumi',
    '10.0.0.0/16': 'XuMsFsQmfygQJvCg'
}

server = Server(clients)
server.start()
