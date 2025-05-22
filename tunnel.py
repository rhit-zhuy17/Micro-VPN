import socket
import struct
import threading
import select
import logging
from typing import Optional, Tuple
import json
import os
import sys
import subprocess

class Tunnel:
    def __init__(self, local_port: int, remote_host: str, remote_port: int):
        self.local_port = local_port
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.running = False
        self.tunnels = {}  # {client_socket: server_socket}
        self.lock = threading.Lock()

    def start(self):
        """Start the tunnel server"""
        self.running = True
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(('0.0.0.0', self.local_port))  # Listen on all interfaces
        self.server.listen(5)
        logging.info(f"Tunnel listening on 0.0.0.0:{self.local_port}")

        while self.running:
            try:
                client_socket, addr = self.server.accept()
                logging.info(f"New connection from {addr}")
                threading.Thread(target=self.handle_client, args=(client_socket,)).start()
            except Exception as e:
                if self.running:
                    logging.error(f"Error accepting connection: {e}")

    def handle_client(self, client_socket: socket.socket):
        """Handle a new client connection"""
        try:
            # Create connection to remote server
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((self.remote_host, self.remote_port))
            
            with self.lock:
                self.tunnels[client_socket] = server_socket
                self.tunnels[server_socket] = client_socket

            # Start bidirectional forwarding
            threading.Thread(target=self.forward, args=(client_socket, server_socket)).start()
            threading.Thread(target=self.forward, args=(server_socket, client_socket)).start()

        except Exception as e:
            logging.error(f"Error handling client: {e}")
            self.cleanup_socket(client_socket)

    def forward(self, source: socket.socket, destination: socket.socket):
        """Forward data between source and destination sockets"""
        try:
            while self.running:
                try:
                    data = source.recv(4096)
                    if not data:
                        break
                    destination.send(data)
                except Exception as e:
                    if self.running:
                        logging.error(f"Error forwarding data: {e}")
                    break
        finally:
            self.cleanup_socket(source)

    def cleanup_socket(self, sock: socket.socket):
        """Clean up a socket and its pair"""
        with self.lock:
            if sock in self.tunnels:
                pair = self.tunnels[sock]
                del self.tunnels[sock]
                if pair in self.tunnels:
                    del self.tunnels[pair]
                try:
                    pair.close()
                except:
                    pass
            try:
                sock.close()
            except:
                pass

    def stop(self):
        """Stop the tunnel server"""
        self.running = False
        try:
            self.server.close()
        except:
            pass
        with self.lock:
            for sock in list(self.tunnels.keys()):
                self.cleanup_socket(sock)

class ClientTunnel(Tunnel):
    def __init__(self, local_port: int, vpn_server_host: str, vpn_server_port: int):
        super().__init__(local_port, vpn_server_host, vpn_server_port)
        self.vpn_socket: Optional[socket.socket] = None

    def connect_vpn(self, vpn_socket: socket.socket):
        """Connect to VPN server"""
        self.vpn_socket = vpn_socket
        self.start()
        
        # Set up system routing
        if sys.platform == 'win32':
            self.setup_windows_routing()
        else:
            self.setup_unix_routing()

    def setup_windows_routing(self):
        """Set up routing on Windows"""
        try:
            # Get current default gateway
            result = subprocess.run(['ipconfig'], capture_output=True, text=True)
            output = result.stdout
            
            # Save current default gateway
            self.original_gateway = "137.112.208.1"  # From your ipconfig output
            
            # Add route for VPN server through original gateway
            os.system(f'route add {self.remote_host} mask 255.255.255.255 {self.original_gateway}')
            
            # Add route for local network through original gateway
            os.system('route add 137.112.208.0 mask 255.255.252.0 137.112.208.1')
            
            # Add default route through VPN
            os.system('route delete 0.0.0.0')
            os.system('route add 0.0.0.0 mask 0.0.0.0 127.0.0.1 metric 1')
            
            logging.info("Windows routing configured")
        except Exception as e:
            logging.error(f"Error setting up Windows routing: {e}")

    def setup_unix_routing(self):
        """Set up routing on Unix-like systems"""
        try:
            # Add route for VPN server
            os.system(f'sudo route add {self.remote_host} 127.0.0.1')
            # Add default route through VPN
            os.system('sudo route add default 127.0.0.1')
            logging.info("Unix routing configured")
        except Exception as e:
            logging.error(f"Error setting up Unix routing: {e}")

    def handle_client(self, client_socket: socket.socket):
        """Handle a new client connection by forwarding through VPN"""
        try:
            # Send connection request to VPN server
            if not self.vpn_socket:
                raise Exception("Not connected to VPN server")

            # Send tunnel request
            request = {
                "type": "tunnel",
                "action": "connect",
                "local_port": self.local_port
            }
            self.vpn_socket.send(json.dumps(request).encode())
            
            # Wait for VPN server to establish connection
            response = json.loads(self.vpn_socket.recv(4096).decode())
            if response["status"] != "success":
                raise Exception(f"Tunnel connection failed: {response['message']}")

            # Start forwarding through VPN
            with self.lock:
                self.tunnels[client_socket] = self.vpn_socket
                self.tunnels[self.vpn_socket] = client_socket

            # Start bidirectional forwarding
            threading.Thread(target=self.forward, args=(client_socket, self.vpn_socket)).start()
            threading.Thread(target=self.forward, args=(self.vpn_socket, client_socket)).start()

        except Exception as e:
            logging.error(f"Error handling client: {e}")
            self.cleanup_socket(client_socket)

    def stop(self):
        """Stop the tunnel and restore routing"""
        super().stop()
        if sys.platform == 'win32':
            self.restore_windows_routing()
        else:
            self.restore_unix_routing()

    def restore_windows_routing(self):
        """Restore Windows routing"""
        try:
            # Remove VPN routes
            os.system('route delete 0.0.0.0')
            os.system(f'route delete {self.remote_host}')
            os.system('route delete 137.112.208.0')
            
            # Restore default route
            os.system(f'route add 0.0.0.0 mask 0.0.0.0 {self.original_gateway}')
            
            logging.info("Windows routing restored")
        except Exception as e:
            logging.error(f"Error restoring Windows routing: {e}")

    def restore_unix_routing(self):
        """Restore Unix routing"""
        try:
            os.system('sudo route del default')
            os.system(f'sudo route del {self.remote_host}')
            logging.info("Unix routing restored")
        except Exception as e:
            logging.error(f"Error restoring Unix routing: {e}")

class ServerTunnel(Tunnel):
    def __init__(self, local_port: int):
        super().__init__(local_port, "0.0.0.0", 0)  # Server listens on all interfaces

    def handle_tunnel_request(self, vpn_socket: socket.socket, request: dict):
        """Handle tunnel request from VPN client"""
        try:
            action = request.get("action")
            if action == "connect":
                # Create new tunnel for the client
                client_tunnel = Tunnel(
                    local_port=0,  # Let OS choose port
                    remote_host=request.get("remote_host", "127.0.0.1"),
                    remote_port=request.get("remote_port", 80)
                )
                client_tunnel.start()
                return {"status": "success", "message": "Tunnel established"}
            else:
                return {"status": "error", "message": "Unknown tunnel action"}
        except Exception as e:
            return {"status": "error", "message": str(e)}