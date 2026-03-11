from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import base64
import os

def generate_keys():
    """Generates and saves key pairs for server and client."""
    
    # --- Generate Server Keys ---
    print("--- Generating Server Keys ---")
    server_priv_key = ed25519.Ed25519PrivateKey.generate()
    server_pub_key = server_priv_key.public_key()

    # Save server private key in PEM format
    with open("server_id.key", "wb") as f:
        f.write(server_priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print("Saved 'server_id.key' (private). Place this in your server's root directory.")

    # Save server public key in PEM format (for client's known_server.pub)
    with open("known_server.pub", "wb") as f:
        f.write(server_pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print("Saved 'known_server.pub' (public). Copy this to your client's directory.")

    # --- Generate Client Keys ---
    print("\n--- Generating Client Keys ---")
    client_priv_key = ed25519.Ed25519PrivateKey.generate()
    client_pub_key = client_priv_key.public_key()

    # Save client private key in PEM format
    with open("client_id.key", "wb") as f:
        f.write(client_priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print("Saved 'client_id.key' (private). Place this in your client's directory.")

    # Get client public key in raw format, then base64 encode it for authorized_clients.pub
    client_pub_key_raw_b64 = base64.b64encode(client_pub_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ))

    # Create or append to the authorized_clients.pub file
    with open("authorized_clients.pub", "a") as f:
        f.write(client_pub_key_raw_b64.decode() + '\n')
    
    print("\n--- Authorization ---")
    print("The client's public key has been added to 'authorized_clients.pub'.")
    print("Place this file in your server's root directory.")
    print(f"Key added: {client_pub_key_raw_b64.decode()}")

if __name__ == "__main__":
    generate_keys()