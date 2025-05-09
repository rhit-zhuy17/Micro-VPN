import socket
from crypto_utils import encrypt, decrypt
from shared_config import HOST, PORT

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    print("[+] Connected to VPN server")
    try:
        while True:
            msg = input(">> ")
            if msg.lower() == "exit":
                break
            s.send(encrypt(msg.encode()))
            response = decrypt(s.recv(4096))
            print("[Server]", response.decode())
    finally:
        s.close()

if __name__ == "__main__":
    main()
