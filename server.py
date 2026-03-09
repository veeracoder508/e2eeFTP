"""
This script runs the secure file transfer server.

It instantiates and starts the Server from the pyproto package, which listens
for incoming client connections.
"""
from e2eeFTP import Server


server = Server()


if __name__ == "__main__":
    server.run()