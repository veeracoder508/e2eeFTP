import socket
import logging
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler()]
)

class Server:
    def __init__(self, host='127.0.0.1', port=5001):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def _establish_shared_key(self, sock):
        """
        Executes the Server-side of the ECDH handshake.
        Matches the logic in SecureClient.
        """
        logging.info("Performing secure handshake...")
        
        # 1. Receive Client's public key
        client_public_bytes = sock.recv(1024)
        client_public_key = serialization.load_pem_public_key(client_public_bytes)

        # 2. Generate Server's ephemeral private/public key pair
        server_private_key = ec.generate_private_key(ec.SECP256R1())
        server_public_bytes = server_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # 3. Send Server's public key to Client
        sock.sendall(server_public_bytes)

        # 4. Derive Shared Secret
        shared_secret = server_private_key.exchange(ec.ECDH(), client_public_key)

        # 5. Derive the same Fernet key as the client
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'file-transfer-e2ee',
        ).derive(shared_secret)

        fernet_key = base64.urlsafe_b64encode(derived_key)
        return Fernet(fernet_key)

    def run(self):
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
                    # Establish encryption before receiving data
                    cipher = self._establish_shared_key(client_socket)
                    self._receive_file(client_socket, address, cipher)
                except Exception as e:
                    logging.error(f"Transfer failed: {e}")
                finally:
                    client_socket.close()
        
        except KeyboardInterrupt:
            logging.warning("Shutting down...")
        finally:
            self.server_socket.close()

    def _receive_file(self, sock, address, cipher):
        # 1. Receive Header (filename|size)
        data = sock.recv(1024).decode()
        if not data: return
            
        filename, filesize = data.split("|")
        filesize = int(filesize)
        
        logging.info(f"Receiving encrypted file: {filename} ({filesize} bytes)")
        
        # 2. Receive the encrypted blob
        encrypted_buffer = b""
        while len(encrypted_buffer) < filesize:
            chunk = sock.recv(4096)
            if not chunk: break
            encrypted_buffer += chunk

        # 3. Decrypt and Save
        try:
            decrypted_data = cipher.decrypt(encrypted_buffer)
            write_path = f"received_{filename}"
            with open(write_path, "wb") as f:
                f.write(decrypted_data)
            logging.info(f"File saved and decrypted: {write_path}")
        except Exception as e:
            logging.error(f"Decryption failed! The keys likely didn't match: {e}")


if __name__ == "__main__":
    server = Server()
    server.run()