import socket
import os
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet

class Client:
    def __init__(self, host='127.0.0.1', port=5001):
        self.host = host
        self.port = port
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def _perform_handshake(self):
        """
        Executes ECDH Key Exchange to agree on a secret without 
        sending the secret over the wire.
        """
        print("[*] Starting secure handshake...")
        
        # 1. Generate Client's temporary private/public key pair
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

        # 4. Generate the Shared Secret
        shared_secret = client_private_key.exchange(ec.ECDH(), server_public_key)

        # 5. Use HKDF to derive a symmetric key from the shared secret
        # This makes the key suitable for Fernet (AES)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'file-transfer-e2ee',
        ).derive(shared_secret)

        # Return a Fernet cipher object using the derived key
        fernet_key = base64.urlsafe_b64encode(derived_key)
        return Fernet(fernet_key)

    def send(self, filepath):
        if not os.path.exists(filepath):
            print(f"[-] File {filepath} not found.")
            return

        # Prepare metadata
        filename = os.path.basename(filepath)
        
        try:
            self.client_socket.connect((self.host, self.port))
            
            # Perform Handshake
            cipher = self._perform_handshake()
            print("[+] Secure channel established.")

            # Encrypt the entire file content
            with open(filepath, "rb") as f:
                raw_data = f.read()
            
            encrypted_data = cipher.encrypt(raw_data)
            filesize = len(encrypted_data)

            # Send Header: filename|size
            header = f"{filename}|{filesize}"
            self.client_socket.send(header.encode())
            
            # Small pause to allow server to process header
            import time; time.sleep(0.1)

            # Send the encrypted payload
            self.client_socket.sendall(encrypted_data)
            print(f"[+] Encrypted file '{filename}' sent successfully.")

        except Exception as e:
            print(f"[-] An error occurred: {e}")
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