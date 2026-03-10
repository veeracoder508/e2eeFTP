"""
This script is an example client for the secure file transfer server.

It demonstrates how to use the Client class from the pyproto package to
send one file ("README.md") and request another ("main.py").
"""
from e2eeFTP import e2eeftpClient


client = e2eeftpClient()

def main() -> None:
    # # Testing send request
    client.send("test_mini-veera.jpg")

    # # Testing get request
    # client.get('mini-veera.jpg')

    # Testing list request
    client.list()


if __name__ == "__main__":
    main()
