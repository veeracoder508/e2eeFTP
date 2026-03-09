# e2eeFTP: End-to-End Encrypted File Transfer

A simple command-line prototype for secure file transfers over TCP using Python. It ensures that files are encrypted from the client to the server, with no one in the middle being able to decipher the content.

## Key Features

-   **End-to-End Encryption**: Files are encrypted on the client side before transmission and decrypted only upon arrival at the server.
-   **Forward Secrecy**: Uses an ephemeral Elliptic Curve Diffie-Hellman (ECDH) key exchange for every connection. A new shared secret is generated for each session, meaning a compromised key from one session cannot be used to decrypt past or future sessions.
-   **Modern Cryptography**: Employs the `cryptography` library, using ECDH for the key exchange and Fernet (AES128-CBC with HMAC-SHA256) for symmetric encryption.
-   **Simple Protocol**: A straightforward text-based protocol to either `SEND` or `GET` files.

## How It Works

The security of the connection is established through a handshake process before any data is transferred:

1.  The client initiates a TCP connection to the server.
2.  An ECDH handshake immediately occurs:
    -   The client generates a temporary public/private key pair and sends its public key to the server.
    -   The server receives the client's public key, generates its own temporary key pair, and sends its public key back to the client.
    -   Both the client and server use their own private key and the other's public key to independently compute the exact same shared secret. This is the core of the Diffie-Hellman exchange.
3.  A 256-bit symmetric encryption key is derived from this shared secret using a Key Derivation Function (HKDF).
4.  With a secure channel established, the client sends its desired command (`SEND` or `GET`).
5.  All file data and subsequent communication for that session are encrypted and decrypted using the unique, session-specific symmetric key.
6.  Once the transfer is complete, the connection is closed, and the ephemeral keys are discarded forever.

## Project Structure

```
e2eeFTP/
├── client.py               
├── server.py               
├── README.md   
├── LICENSE           
└── e2eeFTP/                
    ├── __init__.py
    ├── client/            
    │   ├── client.py
    │   └── __init__.py
    ├── server/             
    │   ├── server.py
    │   └── __init__.py
    └── auth/
        ├── __init__.py
        └── e2ee.py

```

## Setup and Installation

### 1. Prerequisites

-   Python 3.7+
-   uv (file manager)

### 2. Clone the Repository

```sh
uh install e2eeftp
```

### 3. Install Dependencies

The project requires the `cryptography` and `rich` libraries. You can install them using pip. It's recommended to create a `requirements.txt` file:

**requirements.txt**
```
cryptography
rich
```

Then install them with:
```sh
pip install -r requirements.txt
```

## Usage

1.  **Start the Server**
    Open a terminal and run the server script. It will bind to `127.0.0.1:5001` and wait for incoming connections.
    ```sh
    python server.py
    ```

2.  **Run the Client**
    Open a second terminal and run the client script.
    ```sh
    python client.py
    ```
    The example client will automatically connect to the server, send `README.md`, and then attempt to download a file named `main.py`. Since `main.py` does not exist in the root directory, the server will correctly respond with a "File not found" error, which will be displayed on the client side.these transferred files are for example.