import socketserver
import logging
import os
from cryptography.fernet import Fernet
from ..auth import E2EE


# Configure logging to output to both console and file
log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

# Avoid duplicate logs if root logger is also configured
log.propagate = False

# Create handlers if they don't exist to avoid duplication
if not log.handlers:
    from rich.logging import RichHandler
    # Console handler with Rich for pretty output
    console_handler = RichHandler(rich_tracebacks=True, show_path=False)
    console_handler.setFormatter(logging.Formatter("%(message)s", datefmt="[%X]"))
    log.addHandler(console_handler)

    # File handler to store logs in server.log
    file_handler = logging.FileHandler("server.log")
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    log.addHandler(file_handler)

class E2EEFTPRequestHandler(socketserver.BaseRequestHandler):
    """
    Request handler for each client connection, instantiated by the socketserver.

    This class manages the entire lifecycle of a client connection. It is
    responsible for performing the secure handshake, parsing client commands,
    and dispatching to the appropriate handler methods (e.g., for sending or
    receiving files).

    Each instance of this class runs in a separate thread, allowing the server
    to handle multiple clients concurrently. The client's socket object is
    accessible via `self.request`.

    The header format is:
        - SEND: SEND|filename|encrypted_data
        - GET: GET|filename
        - LIST: LIST
        - DELETE: DELETE|filename
    """
    def handle(self):
        """
        The main entry point for handling a new client connection.

        This method orchestrates the session:
        1.  Performs the E2EE handshake to establish a secure channel.
        2.  Waits for and parses a command from the client.
        3.  Calls the internal method corresponding to the command.
        4.  Handles any exceptions during the session.
        5.  Ensures the connection is logged and closed cleanly.
        """
        address = self.client_address
        log.info(f"Accepted connection from {address}")
        try:
            e2ee = E2EE()
            log.info(f"Performing secure handshake with {address}...")
            cipher = e2ee.server_handshake(self.request) # self.request is the client socket
            log.info(f"Secure handshake with {address} complete.")
            self._handle_request(cipher)
        except Exception as e:
            log.error(f"Error during session with {address}: {e}", extra={"markup": True})
        finally:
            log.info(f"Connection with {address} closed.")

    def _recv_until(self, delimiter: bytes) -> bytes:
        """
        Receives data from the socket until a specific delimiter is found.

        This is a helper method to read data from the stream-based TCP socket
        in a message-oriented way. It reads one byte at a time until the
        `delimiter` is encountered.

        Args:
            delimiter (bytes): The byte sequence that marks the end of a message.

        Returns:
            bytes: The data received from the socket, including the delimiter.
                   Returns an empty bytestring if the client disconnects before
                   sending any data.
        """
        data = b''
        while not data.endswith(delimiter):
            chunk = self.request.recv(1)
            if not chunk: break
            data += chunk
        return data

    def _handle_request(self, cipher: Fernet) -> None:
        """
        Parses the client's command and dispatches to the correct handler.

        This method reads the initial command header from the client, which is
        expected to be a newline-terminated string. The header format is:
        - SEND: SEND|filename|encrypted_data
        - GET: GET|filename
        - LIST: LIST
        - DELETE: DELETE|filename

        Args:
            cipher (Fernet): The active Fernet cipher instance for this session,
                     used for encrypting/decrypting file data.
        """
        header_data = self._recv_until(b'\n')
        if not header_data: return
        
        try:
            parts = header_data.decode().strip().split("|")
            command = parts[0]

            if command == "SEND":
                filename, filesize = parts[1], int(parts[2])
                self._receive_file(filename, filesize, cipher)
            elif command == "GET":
                filename = parts[1]
                self._send_file(filename, cipher)
            elif command == "LIST":
                self._send_list()
            elif command == "DELETE":
                filename = parts[1]
                self._delete_file(filename)
            else:
                self.request.sendall(b"400|Invalid Command\n")
                log.warning(f"Invalid command from {self.client_address}: {command}")
        except (IndexError, ValueError) as e:
            log.error(f"Malformed request from {self.client_address}: {header_data.strip()!r} - {e}")
            self.request.sendall(b"400|Malformed request\n")

    def _send_list(self) -> None:
        """
        Sends a list of available files in the 'received' directory to the client.

        The server responds with a header `200|<content_length>` followed by a
        newline-separated string of filenames.

        **Protocol**:
        1.  Sends header: `b"200|<size>"`
        2.  Sends body: A string of filenames.
        """
        log.info("Sending file list...")
        files = os.listdir("received")
        file_list = "\n".join(files)
        self.request.sendall(f"200|{len(file_list)}\n".encode())
        self.request.sendall(file_list.encode())

    def _delete_file(self, filename: str) -> None:
        """
        Deletes a specified file from the server's 'received' directory.

        Args:
            filename (str): The name of the file to delete.

        **Responses**:
        - On success: `b"200|File deleted\\n"`
        - If file not found: `b"404|File not found\\n"`
        """
        filepath = os.path.join("received", filename)
        if os.path.exists(filepath):
            log.info(f"Deleting file: {filename}")
            os.remove(filepath)
            self.request.sendall(b"200|File deleted\n")
        else:
            self.request.sendall(b"404|File not found\n")

    def _receive_file(self, filename: str, filesize: int, cipher: Fernet) -> None:
        """
        Receives, decrypts, and saves a file sent by the client.

        This method reads a specified number of bytes (`filesize`) from the socket,
        which contains the encrypted file data. It then attempts to decrypt this
        data using the session's cipher and saves it to the `received` directory.

        Args:
            filename (str): The name to save the file as.
            filesize (int): The exact size of the incoming encrypted data buffer.
            cipher (Fernet): The Fernet cipher instance for this session.

        **Responses**:
        - On success: `b"226|Transfer Complete\\n"`
        - On decryption failure: `b"500|Decryption Failed\\n"`
        """
        log.info(f"Receiving encrypted file: {filename} ({filesize} bytes)")

        received_dir = "received"
        os.makedirs(received_dir, exist_ok=True)
        write_path = os.path.join(received_dir, filename)
        encrypted_buffer = b""
        while len(encrypted_buffer) < filesize:
            chunk = self.request.recv(min(filesize - len(encrypted_buffer), 4096))
            if not chunk: break
            encrypted_buffer += chunk
        
        if len(encrypted_buffer) < filesize:
            log.error(f"File transfer incomplete for {filename}. Expected {filesize}, got {len(encrypted_buffer)}")
            return

        try:
            decrypted_data = cipher.decrypt(encrypted_buffer)
            with open(write_path, "wb") as f:
                f.write(decrypted_data)
            self.request.sendall(b"226|Transfer Complete\n") 
            log.info(f"Stored: {write_path}")
        except Exception as e:
            log.error(f"Decryption failed for {filename}: {e}")
            self.request.sendall(b"500|Decryption Failed\n")

    def _send_file(self, filename: str, cipher: Fernet) -> None:
        """
        Encrypts and sends a requested file to the client.

        If the file exists in the 'received' directory, it is read, encrypted
        with the session cipher, and sent over the socket.

        Args:
            filename (str): The name of the file to send.
            cipher (Fernet): The Fernet cipher instance for this session.

        **Protocol & Responses**:
        - If file found:
            1. Sends header: `b"200|<encrypted_size>\\n"`
            2. Sends body: The encrypted file data.
        - If file not found: `b"404|File not found: {filename}\\n"`
        - On server-side error: `b"500|Server Read Error\\n"`
        """
        filepath = os.path.join("received", filename)
        if not os.path.exists(filepath):
            log.warning(f"Client requested non-existent file: {filename}")
            self.request.sendall(f"404|File not found: {filename}\n".encode())
            return

        try:
            with open(filepath, "rb") as f:
                raw_data = f.read()
            
            encrypted_data = cipher.encrypt(raw_data)
            self.request.sendall(f"200|{len(encrypted_data)}\n".encode())
            
            self.request.sendall(encrypted_data)
            log.info(f"Sent: {filename}")
        except Exception as e:
            log.error(f"Error reading or sending file {filename}: {e}")
            self.request.sendall(b"500|Server Read Error\n")


class e2eeftp(socketserver.ThreadingTCPServer):
    """
    A multi-threaded TCP server for secure file transfers.

    This server uses `socketserver.ThreadingTCPServer` to handle each incoming
    client connection in a separate thread. This allows for concurrent file
    transfer operations.

    Security is established on a per-connection basis using an Elliptic Curve
    Diffie-Hellman (ECDH) key exchange. This generates a unique, ephemeral
    session key for each client, providing forward secrecy. All file data
    transferred after the handshake is encrypted with this key.

    The server listens for commands like SEND, GET, LIST, and DELETE.

    Attributes:
        allow_reuse_address (bool): Allows the server to restart and bind to the
                                    same address quickly.
        host (str): The IP address the server is bound to.
        port (int): The port the server is listening on.

    Supported Status Codes:
        - 200: Success
        - 226: Transfer Complete
        - 400: Bad Request / Invalid Command
        - 404: File Not Found
        - 500: Internal Server Error (e.g., Decryption Failed)

    The header format is:
        - SEND: SEND|filename|encrypted_data
        - GET: GET|filename
        - LIST: LIST
        - DELETE: DELETE|filename
    """
    allow_reuse_address = True

    def __init__(self, host: str='127.0.0.1', port: int=5001) -> None:
        """
        Initializes the server and binds it to a host and port.

        Args:
            host (str): The network interface IP to bind to. Defaults to '127.0.0.1'
                        (localhost). Use '0.0.0.0' to listen on all interfaces.
            port (int): The port number to listen on. Defaults to 5001.
        """
        super().__init__((host, port), E2EEFTPRequestHandler)
        self.host, self.port = host, port

    def run(self) -> None:
        """
        Starts the server's main loop to listen for and handle connections.

        This method calls `serve_forever()`, which blocks and waits for incoming
        connections. Each connection is then passed to an instance of
        `E2EEFTPRequestHandler` for processing in a new thread.
        """
        log.info(f"host: {self.host}, port: {self.port}")
        log.info("press ctrl+c to exit")
        log.info(f"Server listening on {self.host}:{self.port}")
        try:
            self.serve_forever()
        except KeyboardInterrupt:
            log.warning("Shutting down...")
        finally:
            self.server_close()
