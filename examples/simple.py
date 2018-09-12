from radius.server import Server

clients = {
    # Can be a single IP or CIDR
    '127.0.0.1': 'aXY8mAc4Bqi4G4tyyRgb0cwn8F1ee3oqyQWi8GE81#cANOuxAtCCL6LxxoVHwDrB',
}

server = Server(clients)
server.start()
