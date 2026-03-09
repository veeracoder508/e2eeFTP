from cryptography.fernet import Fernet

def generate_key():
    """Run this once and save the output to a file named 'secret.key'"""
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    """Loads the key from the current directory named 'secret.key'"""
    return open("secret.key", "rb").read()

# If you don't have a key yet, uncomment the line below and run this file once:
# generate_key()