import socket
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hmac
from cryptography.exceptions import InvalidSignature


def _recv_all(sock: socket.socket, n: int) -> bytes:
    """
    Helper to receive n bytes or raise ConnectionError if the connection is closed.
    """
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            raise ConnectionError("Socket connection broken during handshake")
        data.extend(packet)
    return bytes(data)

class AESCipher:
    """
    A custom cipher class that implements AES-256-CBC encryption with
    HMAC-SHA256 authentication, mimicking the primitives used in Signal/WhatsApp.

    The encrypted payload is structured as: IV || Ciphertext || HMAC Tag
    """
    def __init__(self, encryption_key: bytes, authentication_key: bytes) -> None:
        """
        Initializes the cipher with encryption and authentication keys.
        
        Args:
            encryption_key (bytes): The key used for AES-256-CBC encryption.
            authentication_key (bytes): The key used for HMAC-SHA256 authentication.
        """
        self.encryption_key = encryption_key
        self.authentication_key = authentication_key
        self.iv_size = 16  # AES-CBC uses a 128-bit (16-byte) IV
        self.tag_size = 32 # HMAC-SHA256 produces a 256-bit (32-byte) tag

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypts data with AES-256-CBC and signs it with HMAC-SHA256.
        
        Args:
            plaintext (bytes): The data to encrypt.

        Returns:
            bytes: The encrypted payload.
        """
        iv = os.urandom(self.iv_size)
        
        # Pad plaintext to AES block size
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        # Encrypt
        cipher = Cipher(algorithms.AES(self.encryption_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        # Sign the IV and ciphertext
        mac = hmac.HMAC(self.authentication_key, hashes.SHA256())
        mac.update(iv + ciphertext)
        tag = mac.finalize()

        return iv + ciphertext + tag

    def decrypt(self, payload: bytes) -> bytes:
        """
        Verifies HMAC and decrypts AES-256-CBC ciphertext.
        
        Args:
            payload (bytes): The encrypted payload.

        Returns:
            bytes: The decrypted data.
        """
        # Extract components from payload
        iv = payload[:self.iv_size]
        tag = payload[-self.tag_size:]
        ciphertext = payload[self.iv_size:-self.tag_size]

        # Verify the HMAC tag first
        mac = hmac.HMAC(self.authentication_key, hashes.SHA256())
        mac.update(iv + ciphertext)
        mac.verify(tag) # Raises InvalidSignature on failure

        # Decrypt
        cipher = Cipher(algorithms.AES(self.encryption_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Unpad
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        return plaintext


class E2EE:
    """
    Manages the End-to-End Encryption handshake using Elliptic Curve
    Diffie-Hellman (ECDH) to establish a secure, ephemeral session key.
    """
    def __init__(self) -> None:
        """
        Initializes the E2EE object by generating an ephemeral private/public
        key pair for this session.
        """
        # Generate an ephemeral private key for this session
        # Use X25519, the curve used by Signal/WhatsApp
        self._private_key = x25519.X25519PrivateKey.generate()
        self.public_key_bytes = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def _derive_cipher(self, peer_public_key_bytes: bytes) -> AESCipher:
        """
        Derives a shared secret and creates a custom AESCipher object.

        Using the peer's public key and our own private key, this method
        computes a shared secret via X25519. It then uses HKDF to derive
        keys for AES-256 encryption and HMAC-SHA256 authentication.

        Args:
            peer_public_key_bytes (bytes): The raw public key from the
                                           other party.

        Returns:
            AESCipher: The symmetric cipher object for this session.
        """
        peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_key_bytes)
        shared_secret = self._private_key.exchange(peer_public_key)
        
        # Derive 64 bytes: 32 for AES-256 key, 32 for HMAC-SHA256 key
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=b'file-transfer-e2ee',
        ).derive(shared_secret)

        encryption_key = derived_key[:32]
        authentication_key = derived_key[32:]
        return AESCipher(encryption_key, authentication_key)

    def client_handshake(self, sock: socket.socket, client_id_priv_key: ed25519.Ed25519PrivateKey, known_server_pub_key: ed25519.Ed25519PublicKey) -> AESCipher:
        """
        Performs the authenticated client-side handshake.

        This extends the ECDH handshake with a signature-based authentication
        step to verify both the client's and the server's identity, preventing
        Man-in-the-Middle (MitM) attacks.

        Args:
            sock (socket.socket): The connected client socket.
            client_id_priv_key (ed25519.Ed25519PrivateKey): The client's long-term private identity key.
            known_server_pub_key (ed25519.Ed25519PublicKey): The server's expected long-term public identity key.

        Returns:
            AESCipher: The derived symmetric cipher for this session.
        
        Raises:
            ConnectionError: If the server's identity cannot be verified.
        """
        # 1. Sign our ephemeral public key with our long-term identity key.
        client_signature = client_id_priv_key.sign(self.public_key_bytes)
        client_id_pub_key_bytes = client_id_priv_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )

        # 2. Send our ephemeral key, identity key, and signature.
        payload = self.public_key_bytes + client_id_pub_key_bytes + client_signature
        sock.sendall(len(payload).to_bytes(4, 'big'))
        sock.sendall(payload)

        # 3. Receive the server's response.
        size_bytes = _recv_all(sock, 4)
        server_payload_size = int.from_bytes(size_bytes, 'big')
        server_payload = _recv_all(sock, server_payload_size)

        # 4. Unpack and verify the server's identity and signature.
        server_eph_pub_bytes = server_payload[:32]
        server_id_pub_bytes = server_payload[32:64]
        server_signature = server_payload[64:]

        # Verify server identity against our known key
        known_server_pub_key_bytes = known_server_pub_key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        if server_id_pub_bytes != known_server_pub_key_bytes:
            raise ConnectionError("Server identity verification failed! Mismatched public key.")

        # Verify server's signature
        try:
            known_server_pub_key.verify(server_signature, server_eph_pub_bytes)
        except InvalidSignature:
            raise ConnectionError("Server identity verification failed! Invalid signature.")

        # 5. If all checks pass, derive the shared secret.
        return self._derive_cipher(server_eph_pub_bytes)

    def server_handshake(self, sock: socket.socket, server_id_priv_key: ed25519.Ed25519PrivateKey, authorized_client_keys: list[ed25519.Ed25519PublicKey]) -> AESCipher:
        """
        Performs the authenticated server-side handshake.

        This authenticates the client against a list of authorized public keys
        and proves the server's identity to the client.

        Args:
            sock (socket.socket): The connected client socket.
            server_id_priv_key (ed25519.Ed25519PrivateKey): The server's long-term private identity key.
            authorized_client_keys (list[ed25519.Ed25519PublicKey]): A list of authorized client public keys.

        Returns:
            AESCipher: The derived symmetric cipher for this session.
        
        Raises:
            ConnectionError: If the client is not authorized or sends an invalid signature.
        """
        # 1. Receive the client's payload.
        size_bytes = _recv_all(sock, 4)
        client_payload_size = int.from_bytes(size_bytes, 'big')
        client_payload = _recv_all(sock, client_payload_size)

        # 2. Unpack and verify the client's identity and signature.
        client_eph_pub_bytes = client_payload[:32]
        client_id_pub_bytes = client_payload[32:64]
        client_signature = client_payload[64:]

        # Check if client is authorized
        authorized_raw_keys = [key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw) for key in authorized_client_keys]
        if client_id_pub_bytes not in authorized_raw_keys:
            raise ConnectionError(f"Client authentication failed. Unknown public key.")

        # Verify client's signature
        try:
            client_id_pub_key = ed25519.Ed25519PublicKey.from_public_bytes(client_id_pub_bytes)
            client_id_pub_key.verify(client_signature, client_eph_pub_bytes)
        except InvalidSignature:
            raise ConnectionError("Client authentication failed. Invalid signature.")

        # 3. Client is authenticated. Now, prove our identity to the client.
        server_signature = server_id_priv_key.sign(self.public_key_bytes)
        server_id_pub_key_bytes = server_id_priv_key.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        payload = self.public_key_bytes + server_id_pub_key_bytes + server_signature
        sock.sendall(len(payload).to_bytes(4, 'big'))
        sock.sendall(payload)

        # 4. If all checks pass, derive the shared secret.
        return self._derive_cipher(client_eph_pub_bytes)
