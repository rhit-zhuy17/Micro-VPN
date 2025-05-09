import socket
import threading
from crypto_utils import decrypt, encrypt
from shared_config import HOST, PORT

def handle_client(conn, addr):
    print(f"[+] Connected: {addr}")
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            plain = decrypt(data).decode()
            print(f"[{addr}] {plain}")
            response = f"Received: {plain}".encode()
            conn.send(encrypt(response))
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        conn.close()

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(5)
    print(f"[+] VPN Server running on {HOST}:{PORT}")
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_client, args=(conn, addr)).start()

if __name__ == "__main__":
    main()
