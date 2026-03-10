"""
e2eeftp: A prototype for end-to-end encrypted file transfers.

This package contains the core client and server logic for a secure file
transfer application using a Diffie-Hellman key exchange.
"""
from .client import e2eeftpClient
from .server import e2eeftp


__version__ = "0.0.0b2"
__all__ = ["e2eeftpClient", "e2eeftp"]
