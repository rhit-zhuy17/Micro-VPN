import socket
import struct
import threading
import select
import logging
from typing import Optional, Tuple
import json

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
        self.server.bind(('127.0.0.1', self.local_port))
        self.server.listen(5)
        logging.info(f"Tunnel listening on 127.0.0.1:{self.local_port}")

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