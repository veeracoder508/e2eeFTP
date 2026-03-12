"""
e2eeftp: A prototype for end-to-end encrypted file transfers.

This package contains the core client and server logic for a secure file
transfer application using a Diffie-Hellman key exchange.
"""
from .client import e2eeftpClient
from .client.cli import e2eeftpClientCli
from .server import e2eeftp
from .server.server import E2EEFTPRequestHandler
from .auth.e2ee import E2EE, AESCipher
from .auth.key import generate_keys



__version__ = "0.0.0b3"
__all__ = ["e2eeftp", "E2EEFTPRequstionHandler", "E2EE", "AESCipher", "generate_keys"]
