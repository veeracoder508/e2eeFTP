import socket
import os
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet
import logging
from logging import Formatter
from rich.logging import RichHandler


rh = RichHandler()
# Configure logging with Rich
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s", # Rich handles the timestamp and level formatting
    datefmt="[%X]",
    handlers=[rh] # Shows cool traceback visuals on errors
)

log = logging.getLogger("rich")

class Client:
    """
    A client for secure, end-to-end encrypted file transfers.

    This client uses Elliptic Curve Diffie-Hellman (ECDH) to establish a
    shared secret with the server for every session, ensuring forward secrecy.
    It can be used to send (upload) and get (download) files from a compatible
    server.
    """
    def __init__(self, host='127.0.0.1', port=5001):
        """
        Initializes the client with server connection details.

        Args:
            host (str): The IP address or hostname of the server. Defaults to '127.0.0.1'.
            port (int): The port number the server is listening on. Defaults to 5001.
        """
        self.host = host
        self.port = port
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def _connect(self):
        """Creates and connects a new TCP socket to the server.

        Raises:
            ConnectionRefusedError: If the server is not reachable.
        """
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((self.host, self.port))

    def _perform_handshake(self):
        """Executes an ECDH Key Exchange to derive a session-specific symmetric key.

        This method performs the client-side handshake:
        1. Generates an ephemeral SECP256R1 private/public key pair.
        2. Sends its public key to the server.
        3. Receives the server's public key.
        4. Computes a shared secret and derives a 32-byte key using HKDF.

        Returns:
            Fernet: A symmetric cipher object for encrypting/decrypting data
                for the current session.
        """
        logging.info("Starting secure handshake...")
        
        client_private_key = ec.generate_private_key(ec.SECP256R1())
        client_public_bytes = client_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # 2. Send Client's public key to Server
        self.client_socket.sendall(client_public_bytes)

        # 3. Receive Server's public key
        server_public_bytes = self.client_socket.recv(1024)
        server_public_key = serialization.load_pem_public_key(server_public_bytes)

        shared_secret = client_private_key.exchange(ec.ECDH(), server_public_key)

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'file-transfer-e2ee',
        ).derive(shared_secret)
        fernet_key = base64.urlsafe_b64encode(derived_key)
        return Fernet(fernet_key)

    def send(self, filepath):
        """Encrypts and sends a file to the connected server.

        A new connection and handshake are performed for each file transfer.
        The protocol for sending is: "SEND|<filename>|<filesize>".

        Args:
            filepath (str): The local path to the file to be sent.
        """
        if not os.path.exists(filepath):
            print(f"[-] File {filepath} not found.")
            return

        filename = os.path.basename(filepath)
        try:
            self._connect() 
            cipher = self._perform_handshake()
            
            with open(filepath, "rb") as f:
                encrypted_data = cipher.encrypt(f.read())
            
            # Protocol: ACTION|FILENAME|SIZE
            header = f"SEND|{filename}|{len(encrypted_data)}"
            self.client_socket.send(header.encode())
            
            import time; time.sleep(0.1) 
            self.client_socket.sendall(encrypted_data)
            logging.info(f"Encrypted file '{filename}' sent.")
        except Exception as e:
            logging.error(f"Send error: {e}")
        finally:
            self.client_socket.close()

    def get(self, filename):
        """Requests, receives, and decrypts a file from the server.

        A new connection and handshake are performed for each file transfer.
        The file is saved locally with a "downloaded_" prefix.

        Args:
            filename (str): The name of the file to request from the server.
        """
        try:
            self._connect()
            cipher = self._perform_handshake()
            
            # 1. Send GET request
            self.client_socket.send(f"GET|{filename}".encode())

            # 2. Receive Header (status|filesize)
            header = self.client_socket.recv(1024).decode()
            if header.startswith("ERROR"):
                logging.error(f"Fetching {filename}...")
                return

            _, filesize = header.split("|")
            filesize = int(filesize)

            # 3. Receive Encrypted Data
            encrypted_buffer = b""
            while len(encrypted_buffer) < filesize:
                chunk = self.client_socket.recv(4096)
                if not chunk: break
                encrypted_buffer += chunk

            # 4. Decrypt and Save
            decrypted_data = cipher.decrypt(encrypted_buffer)
            with open(f"downloaded_{filename}", "wb") as f:
                f.write(decrypted_data)
            
            logging.info(f"Success: {filename} downloaded.")

        except Exception as e:
            logging.error(f"{e}")
        finally:
            self.client_socket.close()

if __name__ == "__main__":
    # Example usage
    # First, create a dummy file if it doesn't exist
    if not os.path.exists("test.txt"):
        with open("test.txt", "w") as f:
            f.write("This is a highly confidential message.")

    client = Client()
    client.send("test.txt")