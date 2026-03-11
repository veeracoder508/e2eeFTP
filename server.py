from e2eeFTP import e2eeftp
from e2eeFTP.auth.key import generate_keys


if __name__ == "__main__":
    server = e2eeftp()
    generate_keys()
    server.run()