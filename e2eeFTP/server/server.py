import socket
import logging
import os
from rich.logging import RichHandler
from cryptography.fernet import Fernet
from ..auth import E2EE


# Configure logging to output to both console and file
log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

# Avoid duplicate logs if root logger is also configured
log.propagate = False

# Create handlers if they don't exist to avoid duplication
if not log.handlers:
    # Console handler with Rich for pretty output
    console_handler = RichHandler(rich_tracebacks=True, show_path=False)
    console_handler.setFormatter(logging.Formatter("%(message)s", datefmt="[%X]"))
    log.addHandler(console_handler)

    # File handler to store logs in server.log
    file_handler = logging.FileHandler("server.log")
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    log.addHandler(file_handler)

class e2eeftp:
    """
    A multi-functional socket server supporting secure file transfers.

    This server uses an Elliptic Curve Diffie-Hellman (ECDH) key exchange to
    establish a unique, session-specific encryption key for every incoming
    connection. This ensures that even if traffic is intercepted, it cannot be
    decrypted without the ephemeral keys from that specific session (forward
    secrecy).

    all status codes:
        - 200: Success
        - 226: Transfer Complete
        - 400: Bad Request
        - 404: File Not Found
        - 500: Internal Server Error
    """
    
    def __init__(self, host='127.0.0.1', port=5001) -> None:
        """
        Initializes the server configuration.

        Args:
            host (str): The interface IP to bind the server to. Defaults to '127.0.0.1'.
            port (int): The port number to listen on. Defaults to 5001.
        """
        
        self.host, self.port = host, port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def run(self) -> None:
        """Starts the main server loop to accept and handle client connections.

        Listens for incoming TCP connections on the configured host and port.
        For each connection, it performs a secure handshake and then passes
        control to the request handler. It handles `KeyboardInterrupt` for
        graceful shutdown.
        """
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.server_socket.settimeout(1.0)  # Set a timeout for the accept() call
            log.info(f"host: {self.host}, port: {self.port}")
            log.info("press ctrl+c to exit")
            log.info(f"Server listening on {self.host}:{self.port}")

            while True:
                try:
                    client_socket, address = self.server_socket.accept()
                except socket.timeout:
                    continue  # Allow the loop to be interrupted

                log.info(f"Accepted connection from {address}")
                try:
                    e2ee = E2EE()
                    log.info(f"Performing secure handshake with {address}...")
                    cipher = e2ee.server_handshake(client_socket)
                    log.info(f"Secure handshake with {address} complete.")
                    self._handle_request(client_socket, address, cipher)
                except Exception as e:
                    log.error(f"Error during session with {address}: {e}", extra={"markup": True})
                finally:
                    client_socket.close()
                    log.info(f"Connection with {address} closed.")
        
        except KeyboardInterrupt:
            log.warning("Shutting down...")
        finally:
            self.server_socket.close()

    def _recv_until(self, sock: socket.socket, delimiter: bytes) -> bytes:
        """
        Receives data from the socket until a delimiter is found.
        
        Args:
            sock (socket.socket): The socket to receive data from.
            delimiter (bytes): The sequence of bytes to look for.

        Returns:
            bytes: The received data until the delimiter is found.
        """
        data = b''
        while not data.endswith(delimiter):
            # Reading 1 byte at a time is inefficient but fine for small headers
            chunk = sock.recv(1) 
            if not chunk: break
            data += chunk
        return data

    def _handle_request(self, sock: socket.socket, address: tuple, cipher: Fernet) -> None:
        """
        Handles the request from the client.

        The protocol expects commands in the format:
        COMMAND|ARG1|ARG2...\\n

        Supported commands:
        - SEND|<filename>|<filesize>
        - GET|<filename>
        - DELETE|<filename>
        - LIST

        Args:
            sock (socket.socket): The client socket.
            address (tuple): The client's IP and port.
            cipher (Fernet): The session's encryption object.
        """
        
        header_data = self._recv_until(sock, b'\n')
        if not header_data: return
        
        try:
            parts = header_data.decode().strip().split("|")
            command = parts[0]

            if command == "SEND":
                filename, filesize = parts[1], int(parts[2])
                self._receive_file(sock, filename, filesize, cipher)
            elif command == "GET":
                filename = parts[1]
                self._send_file(sock, filename, cipher)
            elif command == "LIST":
                self._send_list(sock)
            elif command == "DELETE":
                filename = parts[1]
                self._delete_file(sock, filename)
            else:
                sock.sendall(b"400|Invalid Command\n")
                log.warning(f"Invalid command from {address}: {command}")
        except (IndexError, ValueError) as e:
            log.error(f"Malformed request from {address}: {header_data.strip()!r} - {e}")
            sock.sendall(b"400|Malformed request\n")

    def _send_list(self, sock: socket.socket) -> None:
        log.info("Sending file list...")
        files = os.listdir("received")
        file_list = "\n".join(files)
        sock.sendall(f"200|{len(file_list)}\n".encode())
        sock.sendall(file_list.encode())

    def _delete_file(self, sock: socket.socket, filename: str) -> None:
        filepath = os.path.join("received", filename)
        if os.path.exists(filepath):
            log.info(f"Deleting file: {filename}")
            os.remove(filepath)
            sock.sendall(b"200|File deleted\n")
        else:
            sock.sendall(b"404|File not found\n")


    def _receive_file(self, sock: socket.socket, filename: str, filesize: int, cipher: Fernet) -> None:
        """Receives an encrypted byte stream, decrypts it, and saves it to disk.

        The file is saved in the "received" folder to avoid overwriting local
        files.

        Args:
            sock (socket.socket): The client socket.
            filename (str): The name to save the file as, sent by the client.
            filesize (int): The expected size of the incoming encrypted payload.
            cipher (Fernet): The session's encryption object used for decryption.
        """
        log.info(f"Receiving encrypted file: {filename} ({filesize} bytes)")

        received_dir = "received"
        os.makedirs(received_dir, exist_ok=True)
        write_path = os.path.join(received_dir, filename)
        encrypted_buffer = b""
        while len(encrypted_buffer) < filesize:
            chunk = sock.recv(min(filesize - len(encrypted_buffer), 4096))
            if not chunk: break
            encrypted_buffer += chunk
        
        if len(encrypted_buffer) < filesize:
            log.error(f"File transfer incomplete for {filename}. Expected {filesize}, got {len(encrypted_buffer)}")
            return

        try:
            decrypted_data = cipher.decrypt(encrypted_buffer)
            with open(write_path, "wb") as f:
                f.write(decrypted_data)
            sock.sendall(b"226|Transfer Complete\n") 
            log.info(f"Stored: {write_path}")
        except Exception as e:
            log.error(f"Decryption failed for {filename}: {e}")
            sock.sendall(b"500|Decryption Failed\n")

    def _send_file(self, sock: socket.socket, filename: str, cipher: Fernet) -> None:
        """ 
        send the file back to the client.

        Args:
            sock (socket.socket): The client socket.
            filename (str): The name of the file to send.
            cipher (Fernet): The session's encryption object used for encryption.
        """
        filepath = os.path.join("received", filename)
        if not os.path.exists(filepath):
            log.warning(f"Client requested non-existent file: {filename}")
            sock.sendall(f"404|File not found: {filename}\n".encode())
            return

        try:
            with open(filepath, "rb") as f:
                raw_data = f.read()
            
            encrypted_data = cipher.encrypt(raw_data)
            sock.sendall(f"200|{len(encrypted_data)}\n".encode())
            
            sock.sendall(encrypted_data)
            log.info(f"Sent: {filename}")
        except Exception as e:
            log.error(f"Error reading or sending file {filename}: {e}")
            sock.sendall(b"500|Server Read Error\n")
