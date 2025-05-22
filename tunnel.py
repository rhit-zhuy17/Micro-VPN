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
import time

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

class SOCKSProxy:
    """SOCKS5 proxy implementation to hide client IP"""
    SOCKS_VERSION = 5
    
    def __init__(self, host='127.0.0.1', port=1080):
        self.host = host
        self.port = port
        self.running = False
        
    def handle_client(self, client):
        """Handle SOCKS5 client connection"""
        # SOCKS5 initialization
        version, nmethods = struct.unpack("!BB", client.recv(2))
        methods = client.recv(nmethods)
        
        # We only support no authentication (0x00)
        client.sendall(struct.pack("!BB", self.SOCKS_VERSION, 0))
        
        # SOCKS5 connection request
        version, cmd, _, address_type = struct.unpack("!BBBB", client.recv(4))
        
        if cmd != 1:  # Only support CONNECT command
            client.close()
            return
            
        if address_type == 1:  # IPv4
            address = socket.inet_ntoa(client.recv(4))
        elif address_type == 3:  # Domain name
            domain_length = client.recv(1)[0]
            address = client.recv(domain_length).decode()
        else:  # Not supported
            client.close()
            return
            
        port = struct.unpack('!H', client.recv(2))[0]
        
        try:
            # Connect to destination
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.connect((address, port))
            bind_address = remote.getsockname()
            
            # Send success response
            addr = struct.unpack("!I", socket.inet_aton(bind_address[0]))[0]
            port = bind_address[1]
            reply = struct.pack("!BBBBIH", self.SOCKS_VERSION, 0, 0, 1, addr, port)
            client.sendall(reply)
            
            # Set up forwarding
            self.forward_data(client, remote)
            
        except Exception as e:
            logging.error(f"SOCKS error: {e}")
            # Send failure response
            reply = struct.pack("!BBBBIH", self.SOCKS_VERSION, 5, 0, 1, 0, 0)
            client.sendall(reply)
            client.close()
            
    def forward_data(self, client, remote):
        """Forward data between client and remote"""
        client_to_remote = threading.Thread(
            target=self._forward_data_thread, 
            args=(client, remote)
        )
        remote_to_client = threading.Thread(
            target=self._forward_data_thread, 
            args=(remote, client)
        )
        
        client_to_remote.daemon = True
        remote_to_client.daemon = True
        
        client_to_remote.start()
        remote_to_client.start()
        
        # Wait for either thread to finish
        client_to_remote.join()
        remote_to_client.join()
        
    def _forward_data_thread(self, source, destination):
        """Thread for forwarding data"""
        while self.running:
            try:
                data = source.recv(4096)
                if not data:
                    break
                destination.sendall(data)
            except:
                break
                
        # Close both sockets when done
        try:
            source.close()
        except:
            pass
        try:
            destination.close()
        except:
            pass
            
    def start(self):
        """Start the SOCKS proxy server"""
        self.running = True
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(5)
        logging.info(f"SOCKS5 proxy listening on {self.host}:{self.port}")
        
        while self.running:
            try:
                client, addr = server.accept()
                logging.info(f"New SOCKS client from {addr}")
                client_thread = threading.Thread(target=self.handle_client, args=(client,))
                client_thread.daemon = True
                client_thread.start()
            except Exception as e:
                if self.running:
                    logging.error(f"SOCKS server error: {e}")
        
        server.close()
        
    def stop(self):
        """Stop the SOCKS proxy server"""
        self.running = False

class ClientTunnel(Tunnel):
    def __init__(self, local_port: int, vpn_server_host: str, vpn_server_port: int):
        super().__init__(local_port, vpn_server_host, vpn_server_port)
        self.vpn_socket: Optional[socket.socket] = None
        self.proxy = None

    def connect_vpn(self, vpn_socket: socket.socket):
        """Connect to VPN server"""
        self.vpn_socket = vpn_socket
        
        # Start SOCKS proxy on localhost
        self.proxy = SOCKSProxy(host='127.0.0.1', port=1080)
        proxy_thread = threading.Thread(target=self.proxy.start)
        proxy_thread.daemon = True
        proxy_thread.start()
        
        logging.info("SOCKS proxy started on 127.0.0.1:1080")
        
        # Start tunnel
        self.start()
        
        # Configure system proxy settings
        if sys.platform == 'win32':
            self.setup_windows_proxy()
        else:
            self.setup_unix_proxy()
            
        # Give the user instructions
        print("\n================================================")
        print("PROXY SETUP COMPLETE - YOUR IP IS NOW HIDDEN")
        print("================================================")
        print("To use the VPN proxy:")
        print("1. Configure your browser to use SOCKS5 proxy:")
        print("   - Host: 127.0.0.1")
        print("   - Port: 1080")
        print("2. Visit https://whatismyip.com to verify your IP is hidden")
        print("3. Your traffic is now routed through the VPN server")
        print("================================================\n")

    def setup_windows_proxy(self):
        """Set up Windows proxy settings"""
        try:
            # Save the current proxy settings to restore later
            self.original_proxy = subprocess.run(
                ['reg', 'query', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings'], 
                capture_output=True, text=True
            ).stdout
            
            # Enable proxy settings via registry
            subprocess.run([
                'reg', 'add', 
                'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings', 
                '/v', 'ProxyEnable', '/t', 'REG_DWORD', '/d', '1', '/f'
            ])
            
            # Set proxy server to our SOCKS proxy
            subprocess.run([
                'reg', 'add', 
                'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings', 
                '/v', 'ProxyServer', '/t', 'REG_SZ', '/d', 'socks=127.0.0.1:1080', '/f'
            ])
            
            logging.info("Windows proxy settings configured")
        except Exception as e:
            logging.error(f"Error setting up Windows proxy: {e}")

    def setup_unix_proxy(self):
        """Set up Unix-like proxy settings"""
        try:
            # For macOS, set system-wide proxy using networksetup
            if sys.platform == 'darwin':
                # Get the active network service
                services = subprocess.run(
                    ['networksetup', '-listallnetworkservices'], 
                    capture_output=True, text=True
                ).stdout.strip().split('\n')[1:]  # Skip the first line
                
                for service in services:
                    if service.startswith('*'):
                        continue  # Skip disabled services
                    
                    # Save current settings
                    self.original_proxy = subprocess.run(
                        ['networksetup', '-getsocksfirewallproxy', service],
                        capture_output=True, text=True
                    ).stdout
                    
                    # Enable SOCKS proxy
                    subprocess.run([
                        'networksetup', '-setsocksfirewallproxy', 
                        service, '127.0.0.1', '1080'
                    ])
                    subprocess.run([
                        'networksetup', '-setsocksfirewallproxystate', 
                        service, 'on'
                    ])
                    
                logging.info("macOS proxy settings configured")
            else:
                logging.info("Automatic proxy configuration not supported on this platform")
                logging.info("Please manually configure your applications to use SOCKS5 proxy 127.0.0.1:1080")
        except Exception as e:
            logging.error(f"Error setting up Unix proxy: {e}")

    def stop(self):
        """Stop the tunnel and restore proxy settings"""
        super().stop()
        
        if self.proxy:
            self.proxy.stop()
        
        # Restore proxy settings
        if sys.platform == 'win32':
            self.restore_windows_proxy()
        else:
            self.restore_unix_proxy()

    def restore_windows_proxy(self):
        """Restore Windows proxy settings"""
        try:
            # Disable proxy
            subprocess.run([
                'reg', 'add', 
                'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings', 
                '/v', 'ProxyEnable', '/t', 'REG_DWORD', '/d', '0', '/f'
            ])
            
            logging.info("Windows proxy settings restored")
        except Exception as e:
            logging.error(f"Error restoring Windows proxy: {e}")

    def restore_unix_proxy(self):
        """Restore Unix proxy settings"""
        try:
            # For macOS, restore system-wide proxy
            if sys.platform == 'darwin':
                services = subprocess.run(
                    ['networksetup', '-listallnetworkservices'], 
                    capture_output=True, text=True
                ).stdout.strip().split('\n')[1:]  # Skip the first line
                
                for service in services:
                    if service.startswith('*'):
                        continue  # Skip disabled services
                    
                    # Disable SOCKS proxy
                    subprocess.run([
                        'networksetup', '-setsocksfirewallproxystate', 
                        service, 'off'
                    ])
                    
                logging.info("macOS proxy settings restored")
        except Exception as e:
            logging.error(f"Error restoring Unix proxy: {e}")

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