import socket
import threading
import json
import time
from datetime import datetime
import logging
from crypto_utils import decrypt, encrypt
from shared_config import HOST, PORT
from tunnel import ServerTunnel

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class UserManager:
    def __init__(self):
        self.users = {}  # {username: {"password": hash, "connected": False, "last_seen": None}}
        self.connections = {}  # {addr: {"username": username, "start_time": timestamp, "tunnel": ServerTunnel}}
        self.lock = threading.Lock()

    def add_user(self, username, password):
        with self.lock:
            if username in self.users:
                return False
            self.users[username] = {
                "password": password,  # In production, use proper password hashing
                "connected": False,
                "last_seen": None
            }
            return True

    def authenticate(self, username, password):
        with self.lock:
            if username in self.users and self.users[username]["password"] == password:
                return True
            return False

    def user_connect(self, addr, username):
        with self.lock:
            tunnel = ServerTunnel(0)  # Let OS choose port
            self.connections[addr] = {
                "username": username,
                "start_time": datetime.now(),
                "tunnel": tunnel
            }
            self.users[username]["connected"] = True
            self.users[username]["last_seen"] = datetime.now()
            return tunnel

    def user_disconnect(self, addr):
        with self.lock:
            if addr in self.connections:
                username = self.connections[addr]["username"]
                if username in self.users:
                    self.users[username]["connected"] = False
                if "tunnel" in self.connections[addr]:
                    self.connections[addr]["tunnel"].stop()
                del self.connections[addr]

    def get_connected_users(self):
        with self.lock:
            return {addr: info for addr, info in self.connections.items()}

    def get_user_status(self, username):
        with self.lock:
            if username in self.users:
                return self.users[username]
            return None

    def get_all_users(self):
        with self.lock:
            return self.users

def handle_client(conn, addr, user_manager):
    logging.info(f"[+] New connection from {addr}")
    authenticated = False
    username = None
    tunnel = None

    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break

            try:
                decrypted_data = decrypt(data).decode()
                request = json.loads(decrypted_data)
                
                if not authenticated:
                    if request["type"] == "auth":
                        username = request["username"]
                        password = request["password"]
                        
                        if user_manager.authenticate(username, password):
                            authenticated = True
                            tunnel = user_manager.user_connect(addr, username)
                            response = {"status": "success", "message": "Authentication successful"}
                        else:
                            response = {"status": "error", "message": "Invalid credentials"}
                    else:
                        response = {"status": "error", "message": "Authentication required"}
                else:
                    if request["type"] == "status":
                        connected_users = user_manager.get_connected_users()
                        response = {
                            "status": "success",
                            "connected_users": len(connected_users),
                            "user_list": list(connected_users.values())
                        }
                    elif request["type"] == "message":
                        response = {"status": "success", "message": f"Received: {request['content']}"}
                    elif request["type"] == "tunnel":
                        if tunnel:
                            response = tunnel.handle_tunnel_request(conn, request)
                        else:
                            response = {"status": "error", "message": "Tunnel not initialized"}
                    else:
                        response = {"status": "error", "message": "Unknown command"}

                conn.send(encrypt(json.dumps(response).encode()))
                
            except json.JSONDecodeError:
                response = {"status": "error", "message": "Invalid JSON format"}
                conn.send(encrypt(json.dumps(response).encode()))
            except Exception as e:
                response = {"status": "error", "message": str(e)}
                conn.send(encrypt(json.dumps(response).encode()))

    except Exception as e:
        logging.error(f"[-] Error with client {addr}: {e}")
    finally:
        if authenticated and username:
            user_manager.user_disconnect(addr)
        conn.close()
        logging.info(f"[-] Disconnected: {addr}")

def main():
    user_manager = UserManager()
    
    # Add some test users
    user_manager.add_user("test_user", "test_pass")
    user_manager.add_user("admin", "admin123")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(5)
    logging.info(f"[+] VPN Server running on {HOST}:{PORT}")
    logging.info("[*] Test users created:")
    logging.info("    - Username: test_user, Password: test_pass")
    logging.info("    - Username: admin, Password: admin123")

    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_client, args=(conn, addr, user_manager)).start()

if __name__ == "__main__":
    main()
