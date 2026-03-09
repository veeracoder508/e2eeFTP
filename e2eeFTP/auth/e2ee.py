from cryptography.fernet import Fernet

def generate_key():
    """Generates a Fernet encryption key and saves it to 'secret.key'.

    This function should be run once to create the key file.
    """
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    """Loads the Fernet encryption key from 'secret.key'.

    Returns:
        bytes: The encryption key.
    """
    return open("secret.key", "rb").read()

# If you don't have a key yet, uncomment the line below and run this file once:
# generate_key()