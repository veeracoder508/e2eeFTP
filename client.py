"""
This script is an example client for the secure file transfer server.

It demonstrates how to use the Client class from the pyproto package to
send one file ("README.md") and request another ("main.py").
"""
from e2eeFTP import Client


client = Client()


if __name__ == "__main__":
    client.send("README.md")
    client.get('main.py')
