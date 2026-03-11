import socket
import os
import logging
from contextlib import contextmanager
from rich.logging import RichHandler
from ..auth import E2EE, AESCipher
from cryptography.hazmat.primitives import serialization

rh = RichHandler()
# Configure logging with Rich
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s", # Rich handles the timestamp and level formatting
    datefmt="[%X]",
    handlers=[rh] # Shows cool traceback visuals on errors
)

log = logging.getLogger("rich")

class e2eeftpClient:
    """
    A client for secure, end-to-end encrypted file transfers.

    This client uses Elliptic Curve Diffie-Hellman (ECDH) to establish a
    shared secret with the server for every session, ensuring forward secrecy.
    It can be used to send (upload) and get (download) files from a compatible
    server.
    """ 
    def __init__(self, host='127.0.0.1', port=5001, logging: bool = True, identity_key_path: str = "client_id.key", server_key_path: str = "known_server.pub") -> None:
        """
        Initializes the client with server connection details.

        Args:
            host (str): The IP address or hostname of the server. Defaults to '127.0.0.1'.
            port (int): The port number the server is listening on. Defaults to 5001.
            logging (bool): Whether to enable logging. Defaults to True.
            identity_key_path (str): Path to the client's private identity key.
            server_key_path (str): Path to the server's known public key.
        """
        self.host = host
        self.port = port
        self.identity_key_path = identity_key_path
        self.server_key_path = server_key_path
        self.logging = logging

        log.disabled = not self.logging

    def _recv_until(self, sock: socket.socket, delimiter: bytes) -> bytes:
        """
        Receives data from the socket until a delimiter is found.

        Args:
            socket (socket.socket): The socket to receive data from.
            delimiter (bytes): The sequence of bytes to look for.

        Returns:
            bytes: The received data until the delimiter is found.
        """
        data = b''
        while not data.endswith(delimiter):
            chunk = sock.recv(1)
            if not chunk: break
            data += chunk
        return data

    @contextmanager
    def _secure_channel(self) -> tuple[socket.socket | None, AESCipher | None]: # type: ignore
        """
        A context manager that establishes and tears down a secure channel.
        
        It handles key loading, connection, handshake, and socket closure. It loads
        keys *before* connecting to provide clearer errors and avoid broken pipes.
        
        Yields:
            A tuple of (socket, cipher) on success, or (None, None) on failure.
        """
        # 1. Load keys before attempting any network connection.
        try:
            log.info("Loading identity keys...")
            with open(self.identity_key_path, "rb") as f:
                client_id_priv_key = serialization.load_pem_private_key(f.read(), password=None)
            with open(self.server_key_path, "rb") as f:
                known_server_pub_key = serialization.load_pem_public_key(f.read())
        except FileNotFoundError as e:
            log.error(f"Identity key file not found: {e}.")
            log.warning("Run 'generate_keys.py' and ensure 'known_server.pub' from the server is present.")
            yield None, None
            return

        # 2. If keys are loaded, proceed with connection and handshake.
        sock = None
        try:
            sock = socket.create_connection((self.host, self.port))
            cipher = E2EE().client_handshake(sock, client_id_priv_key, known_server_pub_key)
            log.info("Secure handshake complete.")
            yield sock, cipher
        except ConnectionRefusedError:
            log.error(f"Connection to {self.host}:{self.port} refused. Is the server running?")
            yield None, None
        except ConnectionError as e:
            log.error(f"Handshake failed: {e}")
            log.warning("This can happen if the server does not authorize your client key or if server identity is wrong.")
            yield None, None
        finally:
            if sock: sock.close()

    def send(self, filepath: str) -> int:
        """
        Encrypts and sends a file to the connected server.

        A new connection and handshake are performed for each file transfer.
        The protocol for sending is: "SEND|<filename>|<filesize>".

        Args:
            filepath (str): The local path to the file to be sent.

        Returns:
            The status code of the response from the server.
        """
        if not os.path.exists(filepath): 
            log.error(f"File not found: {filepath}")
            return 404
        
        log.info(f"Attempting to send {os.path.basename(filepath)}...")
        code = 500
        try:
            with self._secure_channel() as (sock, cipher):
                if not sock or not cipher:
                    return 500

                with open(filepath, "rb") as f:
                    data = f.read()
                encrypted_data = cipher.encrypt(data)
                header = f"SEND|{os.path.basename(filepath)}|{len(encrypted_data)}\n"
                sock.sendall(header.encode())
                sock.sendall(encrypted_data)

                response = self._recv_until(sock, b'\n').decode().strip()
                log.info(f"Server response: {response}")
                res_code, _ = response.split("|", 1)
                code = int(res_code)
        except Exception as e:
            log.error(f"An error occurred during send operation: {e}")
        return code

    def get(self, filename: str) -> int:
        """Requests, receives, and decrypts a file from the server.

        A new connection and handshake are performed for each file transfer.
        The file is saved locally with a "downloaded_" prefix.

        Args:
            filename (str): The name of the file to request from the server.

        Returns:
            the status code of the response from the server.
        """
        log.info(f"Attempting to get {filename}...")
        code = 500
        try:
            with self._secure_channel() as (sock, cipher):
                if not sock or not cipher:
                    return 500

                sock.sendall(f"GET|{filename}\n".encode())
                header = self._recv_until(sock, b'\n').decode().strip()
                if not header:
                    log.error("Connection closed by server without a response.")
                    return 500

                try:
                    code, val = header.split("|", 1)
                except ValueError:
                    log.error(f"Received malformed header: {header}")
                    return 400
                
                code = int(code)
                if code == "200":
                    filesize = int(val)
                    log.info(f"Receiving {filename} ({filesize} bytes)...")
                    buf = b""
                    while len(buf) < filesize:
                        chunk = sock.recv(min(filesize - len(buf), 4096))
                        if not chunk: 
                            log.error("Connection lost during file download.")
                            break
                        buf += chunk
                    
                    if len(buf) == filesize:
                        try:
                            decrypted_data = cipher.decrypt(buf)
                            with open(f"downloaded_{filename}", "wb") as f:
                                f.write(decrypted_data)
                            log.info(f"Successfully downloaded and saved to downloaded_{filename}")
                        except Exception as e:
                            log.error(f"Failed to decrypt file: {e}")
                    else:
                        log.error("File download was incomplete.")
                else:
                    log.error(f"Server error: {val}")
        except Exception as e:
            log.error(f"An error occurred during get operation: {e}")
        return code

    def list(self) -> int:
        """
        Requests and prints a list of available files from the server.

        Returns:
            The status code of the response from the server.
        """
        log.info("Requesting file list from server...")
        code = 500
        try:
            with self._secure_channel() as (sock, cipher):
                if not sock or not cipher:
                    return 500
                
                sock.sendall(b"LIST\n")
                
                header = self._recv_until(sock, b'\n').decode().strip()
                if not header:
                    log.error("Connection closed by server without a response.")
                    return 500

                try:
                    code, val = header.split("|", 1)
                except ValueError:
                    log.error(f"Received malformed header: {header}")
                    return 400

                code = int(code)
                if code == "200":
                    list_size = int(val)
                    if list_size == 0:
                        log.info("Server has no files available.")
                        return 200

                    log.info(f"Receiving file list ({list_size} bytes)...")
                    buf = b""
                    while len(buf) < list_size:
                        chunk = sock.recv(min(list_size - len(buf), 4096))
                        if not chunk:
                            log.error("Connection lost while receiving file list.")
                            break
                        buf += chunk

                    if len(buf) == list_size:
                        file_list_str = buf.decode()
                        with open('list.txt', 'w') as f: 
                            f.write("")
                        for filename in file_list_str.split('\n'):
                            with open('list.txt', 'a') as f:
                                f.write(f"{filename}\n")
                    else:
                        log.error("File list reception was incomplete.")
                else:
                    log.error(f"Server error: {val}")
        except Exception as e:
            log.error(f"An error occurred during list operation: {e}")
        return code

    def delete(self, filename: str) -> int:
        """
        Requests the server to delete a file.

        Args:
            filename (str): The name of the file to delete.

        Returns:
            The status code of the response from the server.
        """
        log.info(f"Attempting to delete {filename}...")
        code = 500
        try:
            with self._secure_channel() as (sock, cipher):
                if not sock or not cipher:
                    return 500
                
                sock.sendall(f"DELETE|{filename}\n".encode())
                response = self._recv_until(sock, b'\n').decode().strip()
                
                if not response:
                    log.error("Connection closed by server without a response.")
                    return 500

                try:
                    code, val = response.split("|", 1)
                    if code == "200":
                        log.info(f"Server: {val}")
                    else:
                        log.error(f"Server error: {val}")
                    code = int(code)
                except ValueError:
                    log.error(f"Received malformed response: {response}")
        except Exception as e:
            log.error(f"An error occurred during delete operation: {e}")
        return code
