"""
This script runs the secure file transfer server.

It instantiates and starts the Server from the pyproto package, which listens
for incoming client connections.
"""
from e2eeFTP.server.server import E2EEFTPRequestHandler, e2eeftp
from cryptography.fernet import Fernet
import os
import logging
import socketserver

# It's good practice to use the same logger as the base class
log = logging.getLogger(__name__)

class CustomE2EERequestHandler(E2EEFTPRequestHandler):
    """
    An extended request handler that adds support for RENAME and STAT commands.
    """

    def _rename_file(self, old_filename: str, new_filename: str) -> None:
        """
        Renames a file in the 'received' directory.

        Args:
            old_filename (str): The current name of the file.
            new_filename (str): The new name for the file.

        **Responses**:
        - On success: `b"200|File renamed successfully\\n"`
        - If old file not found: `b"404|Source file not found\\n"`
        - If new file name already exists: `b"409|Destination file already exists\\n"` (409 Conflict)
        - On other errors: `b"500|Rename failed\\n"`
        """
        old_filepath = os.path.join("received", old_filename)
        new_filepath = os.path.join("received", new_filename)

        if not os.path.exists(old_filepath):
            log.warning(f"Rename failed: source file '{old_filename}' not found.")
            self.request.sendall(b"404|Source file not found\n")
            return
        
        if os.path.exists(new_filepath):
            log.warning(f"Rename failed: destination file '{new_filename}' already exists.")
            self.request.sendall(b"409|Destination file already exists\n")
            return

        try:
            log.info(f"Renaming '{old_filename}' to '{new_filename}'")
            os.rename(old_filepath, new_filepath)
            self.request.sendall(b"200|File renamed successfully\n")
        except OSError as e:
            log.error(f"Error renaming file: {e}")
            self.request.sendall(b"500|Rename failed\n")

    def _get_file_stats(self, filename: str) -> None:
        """
        Sends statistics (size, modification time) for a specified file.

        Args:
            filename (str): The name of the file to get stats for.

        **Protocol & Responses**:
        - If file found: `b"200|<filesize>|<mod_time>\\n"`
        - If file not found: `b"404|File not found\\n"`
        """
        filepath = os.path.join("received", filename)
        if not os.path.exists(filepath):
            log.warning(f"Stat request for non-existent file: {filename}")
            self.request.sendall(b"404|File not found\n")
            return
        
        try:
            stats = os.stat(filepath)
            response = f"200|{stats.st_size}|{int(stats.st_mtime)}\n"
            log.info(f"Sending stats for {filename}: {stats.st_size} bytes, modified at {int(stats.st_mtime)}")
            self.request.sendall(response.encode())
        except OSError as e:
            log.error(f"Error getting stats for file {filename}: {e}")
            self.request.sendall(b"500|Could not retrieve file stats\n")

    def _handle_request(self, cipher: Fernet) -> None:
        """
        Overrides the base request handler to include RENAME and STAT commands.
        """
        header_data = self._recv_until(b'\n')
        if not header_data: return
        
        try:
            parts = header_data.decode().strip().split("|")
            command = parts[0].upper()

            if command == "SEND": self._receive_file(parts[1], int(parts[2]), cipher)
            elif command == "GET": self._send_file(parts[1], cipher)
            elif command == "LIST": self._send_list()
            elif command == "DELETE": self._delete_file(parts[1])
            elif command == "RENAME": self._rename_file(parts[1], parts[2])
            elif command == "STAT": self._get_file_stats(parts[1])
            else:
                self.request.sendall(b"400|Invalid Command\n")
                log.warning(f"Invalid command from {self.client_address}: {command}")
        except (IndexError, ValueError) as e:
            log.error(f"Malformed request from {self.client_address}: {header_data.strip()!r} - {e}")
            self.request.sendall(b"400|Malformed request\n")

class CustomE2EEFTPServer(e2eeftp):
    def __init__(self, host='127.0.0.1', port=5001):
        socketserver.ThreadingTCPServer.__init__(self, (host, port), CustomE2EERequestHandler)
        self.host, self.port = host, port

if __name__ == "__main__":
    server = CustomE2EEFTPServer()
    server.run()