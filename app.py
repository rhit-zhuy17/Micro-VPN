import streamlit as st
import socket
import threading
import json
import time
from datetime import datetime
import pandas as pd
import logging
from crypto_utils import decrypt, encrypt
from shared_config import HOST, PORT, ENCRYPTION_KEY
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
        self.server_stats = {
            "total_connections": 0,
            "active_connections": 0,
            "total_data_sent": 0,
            "total_data_received": 0,
            "start_time": datetime.now()
        }

    def add_user(self, username, password):
        with self.lock:
            if username in self.users:
                return False
            self.users[username] = {
                "password": password,
                "connected": False,
                "last_seen": None,
                "created_at": datetime.now()
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
                "tunnel": tunnel,
                "data_sent": 0,
                "data_received": 0
            }
            self.users[username]["connected"] = True
            self.users[username]["last_seen"] = datetime.now()
            self.server_stats["total_connections"] += 1
            self.server_stats["active_connections"] += 1
            return tunnel

    def user_disconnect(self, addr):
        with self.lock:
            if addr in self.connections:
                username = self.connections[addr]["username"]
                if username in self.users:
                    self.users[username]["connected"] = False
                if "tunnel" in self.connections[addr]:
                    self.connections[addr]["tunnel"].stop()
                self.server_stats["active_connections"] -= 1
                del self.connections[addr]

    def update_stats(self, addr, sent_bytes=0, received_bytes=0):
        with self.lock:
            if addr in self.connections:
                self.connections[addr]["data_sent"] += sent_bytes
                self.connections[addr]["data_received"] += received_bytes
                self.server_stats["total_data_sent"] += sent_bytes
                self.server_stats["total_data_received"] += received_bytes

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

    def get_server_stats(self):
        with self.lock:
            return self.server_stats.copy()

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
                            # Update stats
                            user_manager.update_stats(addr, sent_bytes=len(str(response).encode()))
                        else:
                            response = {"status": "error", "message": "Tunnel not initialized"}
                    else:
                        response = {"status": "error", "message": "Unknown command"}

                conn.send(encrypt(json.dumps(response).encode()))
                user_manager.update_stats(addr, received_bytes=len(data))
                
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

def start_server(user_manager):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(5)
    logging.info(f"[+] VPN Server running on {HOST}:{PORT}")
    
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_client, args=(conn, addr, user_manager)).start()

def main():
    st.set_page_config(
        page_title="VPN Server Manager",
        page_icon="🔒",
        layout="wide"
    )

    st.title("🔒 VPN Server Manager")

    # Initialize session state
    if 'user_manager' not in st.session_state:
        st.session_state.user_manager = UserManager()
        # Add some test users
        st.session_state.user_manager.add_user("test_user", "test_pass")
        st.session_state.user_manager.add_user("admin", "admin123")
        
        # Start server in a separate thread
        server_thread = threading.Thread(
            target=start_server,
            args=(st.session_state.user_manager,),
            daemon=True
        )
        server_thread.start()

    # Sidebar for user management
    with st.sidebar:
        st.header("User Management")
        
        # Add new user
        st.subheader("Add New User")
        new_username = st.text_input("Username")
        new_password = st.text_input("Password", type="password")
        if st.button("Add User"):
            if new_username and new_password:
                if st.session_state.user_manager.add_user(new_username, new_password):
                    st.success(f"User {new_username} added successfully!")
                else:
                    st.error("Username already exists!")
            else:
                st.warning("Please enter both username and password")

        # Server Statistics
        st.header("Server Statistics")
        stats = st.session_state.user_manager.get_server_stats()
        st.metric("Active Connections", stats["active_connections"])
        st.metric("Total Connections", stats["total_connections"])
        st.metric("Data Sent", f"{stats['total_data_sent'] / 1024 / 1024:.2f} MB")
        st.metric("Data Received", f"{stats['total_data_received'] / 1024 / 1024:.2f} MB")
        uptime = datetime.now() - stats["start_time"]
        st.metric("Uptime", f"{uptime.days}d {uptime.seconds//3600}h {(uptime.seconds//60)%60}m")

    # Main content area
    col1, col2 = st.columns(2)

    with col1:
        st.header("Connected Users")
        connected_users = st.session_state.user_manager.get_connected_users()
        
        if connected_users:
            data = []
            for addr, info in connected_users.items():
                data.append({
                    "Username": info["username"],
                    "Connected Since": info["start_time"].strftime("%Y-%m-%d %H:%M:%S"),
                    "IP Address": addr[0],
                    "Data Sent": f"{info['data_sent'] / 1024 / 1024:.2f} MB",
                    "Data Received": f"{info['data_received'] / 1024 / 1024:.2f} MB"
                })
            df = pd.DataFrame(data)
            st.dataframe(df, use_container_width=True)
        else:
            st.info("No users currently connected")

    with col2:
        st.header("All Users")
        all_users = st.session_state.user_manager.get_all_users()
        
        if all_users:
            data = []
            for username, info in all_users.items():
                data.append({
                    "Username": username,
                    "Status": "🟢 Connected" if info["connected"] else "⚪ Disconnected",
                    "Last Seen": info["last_seen"].strftime("%Y-%m-%d %H:%M:%S") if info["last_seen"] else "Never",
                    "Created At": info["created_at"].strftime("%Y-%m-%d %H:%M:%S")
                })
            df = pd.DataFrame(data)
            st.dataframe(df, use_container_width=True)
        else:
            st.info("No users registered")

    # Server status
    st.header("Server Status")
    st.info(f"Server running on {HOST}:{PORT}")
    
    # Auto-refresh
    time.sleep(1)
    st.rerun()

if __name__ == "__main__":
    main() 