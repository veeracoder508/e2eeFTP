import argparse
from .server import e2eeftp


def main():
    parse = argparse.ArgumentParser()
    parse.add_argument("--host", help="The gost for the server", default="127.0.0.1", type=str)
    parse.add_argument("--port", help="The port for the server", default=5001, type=int)
    args = parse.parse_args()

    server = e2eeftp(args.host, args.port)
    server.run()


if __name__ == "__main__":
    main()