import socket
import json
import sys
import logging
from crypto_utils import encrypt, decrypt
from shared_config import HOST, PORT
from tunnel import ClientTunnel

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class VPNClient:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.authenticated = False
        self.username = None
        self.tunnel = None

    def connect(self):
        try:
            self.socket.connect((HOST, PORT))
            logging.info("[+] Connected to server")
            return True
        except Exception as e:
            logging.error(f"[-] Connection failed: {e}")
            return False

    def authenticate(self, username, password):
        auth_request = {
            "type": "auth",
            "username": username,
            "password": password
        }
        self.socket.send(encrypt(json.dumps(auth_request).encode()))
        response = json.loads(decrypt(self.socket.recv(4096)).decode())
        
        if response["status"] == "success":
            self.authenticated = True
            self.username = username
            logging.info("[+] Authentication successful")
            
            self.tunnel = ClientTunnel(1080, HOST, PORT) 
            self.tunnel.connect_vpn(self.socket)
            logging.info("[+] VPN tunnel established on port 1080")
            return True
        else:
            logging.error(f"[-] Authentication failed: {response['message']}")
            return False

    def send_message(self, message):
        if not self.authenticated:
            logging.error("[-] Not authenticated")
            return False

        request = {
            "type": "message",
            "content": message
        }
        self.socket.send(encrypt(json.dumps(request).encode()))
        response = json.loads(decrypt(self.socket.recv(4096)).decode())
        logging.info(f"[Server] {response['message']}")
        return True

    def get_status(self):
        if not self.authenticated:
            logging.error("[-] Not authenticated")
            return False

        request = {"type": "status"}
        self.socket.send(encrypt(json.dumps(request).encode()))
        response = json.loads(decrypt(self.socket.recv(4096)).decode())
        
        if response["status"] == "success":
            logging.info(f"\n[*] Connected users: {response['connected_users']}")
            logging.info("[*] User list:")
            for user in response['user_list']:
                logging.info(f"    - {user['username']} (connected since {user['start_time']})")
        return True

    def close(self):
        if self.tunnel:
            self.tunnel.stop()
        self.socket.close()

def print_help():
    print("\nAvailable commands:")
    print("  connect <username> <password> - Connect to the VPN server")
    print("  status                       - Check server status")
    print("  message <text>              - Send a message to the server")
    print("  help                         - Show this help message")
    print("  quit                         - Exit the program")
    print()

def main():
    print("🔒 VPN Client")
    print("Type 'help' for available commands")
    
    client = VPNClient()
    if not client.connect():
        return

    # Authentication
    username = input("Username: ")
    password = input("Password: ")
    
    if not client.authenticate(username, password):
        client.close()
        return

    print("\n[*] Available commands:")
    print("    - message <text>: Send a message")
    print("    - status: Show connected users")
    print("    - quit: Exit the program")
    print("\n[*] VPN tunnel is running on port 1080")
    print("    Configure your applications to use SOCKS proxy at 127.0.0.1:1080")

    while True:
        try:
            command = input("\n> ").strip()
            
            if command == "quit":
                break
            elif command == "status":
                client.get_status()
            elif command.startswith("message "):
                message = command[8:]
                client.send_message(message)
            else:
                print("Unknown command. Type 'help' for available commands.")

        except KeyboardInterrupt:
            break
        except Exception as e:
            logging.error(f"[-] Error: {e}")
            break

    client.close()
    print("[*] Disconnected from server")

if __name__ == "__main__":
    main()
