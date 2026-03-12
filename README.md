# Table Of Content
1. [introduction (*e2eeftp*)](#e2eeftp-end-to-end-file-transfer-protocol)
2. [concepts used](#concepts-used)
    - [What is e2ee encryption?](#what-is-e2ee-encryption)
    - [What is FTP protocol?](#what-is-ftp-protocol)
3. [requirements](#requirements)
4. [how to start the server?](#how-to-start-the-server)

[github](https://github.com/veeracoder508/e22eftp)
[issues](https://github.com/veeracoder508/e22eftp/issues)


# e2eeftp(0.0.0b2) (end-to-end encryptioned file transfer protocol)
This is a custom file transfer protocol to transfer file in a secure tunnel with e2ee encryption from client to server.

# concepts used
## What is e2ee encryption?
End-to-end encryption (E2EE) is a type of messaging that keeps messages private from everyone, including the messaging service. When E2EE is used, a message only appears in decrypted form for the person sending the message and the person receiving the message. The sender is one "end" of the conversation and the recipient is the other "end"; hence the name "end-to-end."

Think of end-to-end encryption as being like a letter that goes through the mail in a sealed envelope. The person sending the letter is able to read it, and the person who receives it can open it and read it. Postal service employees cannot read the letter because it remains sealed in the envelope. <!-- source https://www.cloudflare.com/en-in/learning/privacy/what-is-end-to-end-encryption/ -->

## What is FTP protocol?
File transfer protocol (FTP) is an Internet tool provided by TCP/IP. It helps to transfer files from one computer to another by providing access to directories or folders on remote computers and allows software, data and text files to be transferred between different kinds of computers. <!-- source https://www.geeksforgeeks.org/computer-science-fundamentals/file-transfer-protocol-ftp/ -->

# requirements
Brfore we start we need to install these
- python 3.14+
- uv *(my choice for the package manager)*
- rich, cryptography 

# How to start the server?
To start the server type create a python file and past in this command for a simple server.
```python
# server.py
from e2eeFTP import e2eeftp

server = e2eeftp()

if __name__ == "__main__":
    server.run()
```

For the client this is the simple setup.
```python
# client.py
from e2eeFTP import e2eeftpClient

if __name__ == "__main__":
    client = e2eeftpClient()
    client.send("mini-veera.jpg")  # Testing send request
    client.get('mini-veera.jpg')   # Testing get request
    client.list()                  # Testing list request
    client.delete('mini-veera.jpg')# Testing delete request
)
```
You can send any file - image(png, jpeg), text(py, txt, c), executable, commpressed file(zip, rar, tar, gz) and more.

you can also cutomize the server to add or upgrage any methods. check `custom_server.py` for an example.


sources:
- [cloudflare](https://www.cloudflare.com/en-in/learning/privacy/what-is-end-to-end-encryption/)
- [geeksforgeeks](https://www.geeksforgeeks.org/computer-science-fundamentals/file-transfer-protocol-ftp/)