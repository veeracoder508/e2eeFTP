import socket
import logging
from logging import Formatter
from rich.logging import RichHandler
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet


rh = RichHandler()
# Configure logging with Rich
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s", # Rich handles the timestamp and level formatting
    datefmt="[%X]",
    handlers=[rh] # Shows cool traceback visuals on errors
)
log = logging.getLogger("rich")

class Server:
    """
    A multi-functional socket server supporting secure file transfers.

    This server uses an Elliptic Curve Diffie-Hellman (ECDH) key exchange to
    establish a unique, session-specific encryption key for every incoming
    connection. This ensures that even if traffic is intercepted, it cannot be
    decrypted without the ephemeral keys from that specific session (forward
    secrecy).
    """
    
    def __init__(self, host='127.0.0.1', port=5001):
        """
        Initializes the server configuration.

        Args:
            host (str): The interface IP to bind the server to. Defaults to '127.0.0.1'.
            port (int): The port number to listen on. Defaults to 5001.
        """
        
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def _establish_shared_key(self, sock):
        """Performs the server-side ECDH handshake to establish a shared secret.

        This method follows these steps:
        1. Receives the client's public key.
        2. Generates the server's own ephemeral private/public key pair.
        3. Sends the server's public key to the client.
        4. Computes a shared secret using the client's public key and server's
           private key.
        5. Derives a 32-byte symmetric key from the shared secret using HKDF,
           which is then used to initialize a Fernet cipher.

        Args:
            sock (socket.socket): The connected client socket for the handshake.

        Returns:
            Fernet: The derived symmetric cipher object for this session.
        """
        logging.info("Performing secure handshake...")
        
        client_public_bytes = sock.recv(1024)
        client_public_key = serialization.load_pem_public_key(client_public_bytes)

        server_private_key = ec.generate_private_key(ec.SECP256R1())
        server_public_bytes = server_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # 3. Send Server's public key to Client
        sock.sendall(server_public_bytes)

        shared_secret = server_private_key.exchange(ec.ECDH(), client_public_key)

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'file-transfer-e2ee',
        ).derive(shared_secret)

        fernet_key = base64.urlsafe_b64encode(derived_key)
        return Fernet(fernet_key)

    def run(self):
        """Starts the main server loop to accept and handle client connections.

        Listens for incoming TCP connections on the configured host and port.
        For each connection, it performs a secure handshake and then passes
        control to the request handler. It handles `KeyboardInterrupt` for
        graceful shutdown.
        """
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.server_socket.settimeout(1.0)
            logging.info(f"Secure Server listening on {self.host}:{self.port}")

            while True:
                try:
                    client_socket, address = self.server_socket.accept()
                except socket.timeout:
                    continue
                
                logging.info(f"Connection from {address}")
                try:
                    cipher = self._establish_shared_key(client_socket)
                    self._handle_request(client_socket, address, cipher)
                except Exception as e:
                    logging.error(f"Transfer failed: {e}")
                finally:
                    client_socket.close()
        
        except KeyboardInterrupt:
            logging.warning("Shutting down...")
        finally:
            self.server_socket.close()

    def _handle_request(self, sock, address, cipher):
        """Parses the client's initial command and routes to SEND or GET logic.

        The client is expected to send a command as its first message after the
        handshake. The command format is "ACTION|ARG1|ARG2...".

        - SEND: "SEND|<filename>|<filesize>"
        - GET: "GET|<filename>"

        Args:
            sock (socket.socket): The client socket.
            address (tuple): The client's (IP, port) address.
            cipher (Fernet): The session's encryption object.
        """
        data = sock.recv(1024).decode()
        if not data: return
            
        parts = data.split("|")
        command = parts[0]

        if command == "SEND":
            # Expecting SEND|filename|filesize
            filename, filesize = parts[1], int(parts[2])
            self._receive_file(sock, filename, filesize, cipher)
        elif command == "GET":
            # Expecting GET|filename
            filename = parts[1]
            self._send_file(sock, filename, cipher)

    def _receive_file(self, sock, filename, filesize, cipher):
        """Receives an encrypted byte stream, decrypts it, and saves it to disk.

        The file is saved with a "received_" prefix to avoid overwriting local
        files.

        Args:
            sock (socket.socket): The client socket.
            filename (str): The name to save the file as, sent by the client.
            filesize (int): The expected size of the incoming encrypted payload.
            cipher (Fernet): The session's encryption object used for decryption.
        """
        logging.info(f"Receiving encrypted file: {filename} ({filesize} bytes)")
        
        encrypted_buffer = b""
        while len(encrypted_buffer) < filesize:
            chunk = sock.recv(4096)
            if not chunk: break
            encrypted_buffer += chunk

        try:
            decrypted_data = cipher.decrypt(encrypted_buffer)
            write_path = f"received_{filename}"
            with open(write_path, "wb") as f:
                f.write(decrypted_data)
            logging.info(f"File saved and decrypted: {write_path}")
        except Exception as e:
            logging.error(f"Decryption failed! The keys likely didn't match: {e}")

    def _send_file(self, sock, filename, cipher):
        """Reads a local file, encrypts it, and sends it to the client.

        If the requested file does not exist, it sends an "ERROR|File not found"
        message. Otherwise, it sends a header "OK|<filesize>" followed by the
        encrypted file data.

        Args:
            sock (socket.socket): The client socket.
            filename (str): The name of the local file to read and send.
            cipher (Fernet): The session's encryption object.
        """
        try:
            import os
            if not os.path.exists(filename):
                sock.send("ERROR|File not found".encode())
                return

            with open(filename, "rb") as f:
                raw_data = f.read()
            
            encrypted_data = cipher.encrypt(raw_data)
            filesize = len(encrypted_data)

            # Send Header
            sock.send(f"OK|{filesize}".encode())
            import time; time.sleep(0.1)
            
            # Send Payload
            sock.sendall(encrypted_data)
            logging.info(f"Sent encrypted file: {filename}")
        except Exception as e:
            logging.error(f"Failed to send file: {e}")


if __name__ == "__main__":
    server = Server()
    server.run()