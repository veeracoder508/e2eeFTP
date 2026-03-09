from pyproto import Client


client = Client()


if __name__ == "__main__":
    client.send("README.md")