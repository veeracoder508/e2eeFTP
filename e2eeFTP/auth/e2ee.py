import socket
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet


def _recv_all(sock: socket.socket, n: int) -> bytes:
    """Helper to receive n bytes or raise ConnectionError if the connection is closed."""
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            raise ConnectionError("Socket connection broken during handshake")
        data.extend(packet)
    return bytes(data)


class E2EE:
    """
    Manages the End-to-End Encryption handshake using Elliptic Curve
    Diffie-Hellman (ECDH) to establish a secure, ephemeral session key.
    """
    def __init__(self):
        """
        Initializes the E2EE object by generating an ephemeral private/public
        key pair for this session.
        """
        # Generate an ephemeral private key for this session
        self._private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key_bytes = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def _derive_fernet_key(self, peer_public_key_bytes: bytes) -> Fernet:
        """
        Derives a shared secret and creates a Fernet cipher object.

        Using the peer's public key and our own private key, this method
        computes a shared secret via ECDH. It then uses HKDF to derive a
        32-byte key suitable for Fernet (AES128-CBC).

        Args:
            peer_public_key_bytes (bytes): The PEM-encoded public key from the
                                           other party.

        Returns:
            Fernet: The symmetric cipher object for this session.
        """
        peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes)
        shared_secret = self._private_key.exchange(ec.ECDH(), peer_public_key)
        
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'file-transfer-e2ee',
        ).derive(shared_secret)

        return Fernet(base64.urlsafe_b64encode(derived_key))

    def client_handshake(self, sock: socket.socket) -> Fernet:
        """
        Performs the client-side ECDH handshake.

        1. Sends the client's public key to the server.
        2. Receives the server's public key.
        3. Derives the shared symmetric key and returns the Fernet cipher.

        Args:
            sock (socket.socket): The connected client socket.

        Returns:
            Fernet: The derived symmetric cipher for this session.
        """
        # Send public key with its length prepended
        sock.sendall(len(self.public_key_bytes).to_bytes(4, 'big'))
        sock.sendall(self.public_key_bytes)

        # Receive server's public key
        size_bytes = _recv_all(sock, 4)
        server_key_size = int.from_bytes(size_bytes, 'big')
        server_public_bytes = _recv_all(sock, server_key_size)

        return self._derive_fernet_key(server_public_bytes)

    def server_handshake(self, sock: socket.socket) -> Fernet:
        """
        Performs the server-side ECDH handshake.

        1. Receives the client's public key.
        2. Sends the server's public key to the client.
        3. Derives the shared symmetric key and returns the Fernet cipher.

        Args:
            sock (socket.socket): The connected client socket.

        Returns:
            Fernet: The derived symmetric cipher for this session.
        """
        # Receive client's public key
        size_bytes = _recv_all(sock, 4)
        client_key_size = int.from_bytes(size_bytes, 'big')
        client_public_bytes = _recv_all(sock, client_key_size)

        # Send server's public key with its length prepended
        sock.sendall(len(self.public_key_bytes).to_bytes(4, 'big'))
        sock.sendall(self.public_key_bytes)
        return self._derive_fernet_key(client_public_bytes)
