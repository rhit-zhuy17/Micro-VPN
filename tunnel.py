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
            # First, receive the destination info from the SOCKS proxy
            # Read first byte to determine address type
            address_type = struct.unpack('!B', client_socket.recv(1))[0]
            
            if address_type == 1:  # IPv4
                # IPv4: <type><ignored><ipv4>
                _, ipv4_int = struct.unpack('!BI', client_socket.recv(5))
                address = socket.inet_ntoa(struct.pack('!I', ipv4_int))
            elif address_type == 3:  # Domain name
                # Domain: <type><length><domain>
                length = struct.unpack('!B', client_socket.recv(1))[0]
                address = client_socket.recv(length + 1)[1:].decode()  # +1 for ignored byte, then skip it
            else:
                logging.error(f"Unsupported address type: {address_type}")
                client_socket.close()
                return
                
            # Read port
            port = struct.unpack('!H', client_socket.recv(2))[0]
            
            logging.info(f"Tunnel request to {address}:{port}")
            
            # Create connection to remote server via the VPN server
            # For this micro-VPN, we're connecting directly rather than forwarding through
            # the VPN socket since this is a simplified implementation
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((self.remote_host, self.remote_port))
            
            # Send a request to the VPN server with destination info
            request = {
                "action": "connect",
                "remote_host": address,
                "remote_port": port
            }
            server_socket.sendall((json.dumps(request) + "\n").encode())
            
            with self.lock:
                self.tunnels[client_socket] = server_socket
                self.tunnels[server_socket] = client_socket

            # Start bidirectional forwarding
            threading.Thread(target=self.forward, args=(client_socket, server_socket)).start()
            threading.Thread(target=self.forward, args=(server_socket, client_socket)).start()

        except Exception as e:
            logging.error(f"Error handling client in tunnel: {e}")
            self.cleanup_socket(client_socket)

    def forward(self, source: socket.socket, destination: socket.socket):
        """Forward data between source and destination sockets"""
        try:
            while self.running:
                try:
                    # Use select to check if socket is readable
                    readable, _, _ = select.select([source], [], [], 1.0)
                    if not readable:
                        continue
                        
                    data = source.recv(4096)
                    if not data:
                        break
                        
                    # Check if destination is still valid
                    try:
                        destination.send(data)
                    except (socket.error, OSError) as e:
                        if self.running:
                            logging.error(f"Error sending data: {e}")
                        break
                        
                except (socket.error, OSError) as e:
                    if self.running:
                        logging.error(f"Error receiving data: {e}")
                    break
                except Exception as e:
                    if self.running:
                        logging.error(f"Unexpected error in forward: {e}")
                    break
        finally:
            self.cleanup_socket(source)
            self.cleanup_socket(destination)

    def cleanup_socket(self, sock: socket.socket):
        """Clean up a socket and its pair"""
        if sock is None:
            return
            
        with self.lock:
            try:
                if sock in self.tunnels:
                    pair = self.tunnels[sock]
                    del self.tunnels[sock]
                    if pair in self.tunnels:
                        del self.tunnels[pair]
                    try:
                        pair.shutdown(socket.SHUT_RDWR)
                    except:
                        pass
                    try:
                        pair.close()
                    except:
                        pass
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except:
                    pass
                try:
                    sock.close()
                except:
                    pass
            except Exception as e:
                logging.error(f"Error during socket cleanup: {e}")

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
    
    def __init__(self, host='127.0.0.1', port=1080, tunnel=None):
        self.host = host
        self.port = port
        self.running = False
        self.tunnel = tunnel  # Reference to the tunnel for forwarding
        
    def handle_client(self, client):
        """Handle SOCKS5 client connection"""
        try:
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
                if self.tunnel:
                    # Connect through the tunnel instead of directly
                    remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    remote.connect(('127.0.0.1', self.tunnel.local_port))
                    
                    # Send destination info to the tunnel
                    # Format: <address_type><address_len><address><port>
                    if address_type == 1:  # IPv4
                        header = struct.pack('!BBI', 1, 0, struct.unpack('!I', socket.inet_aton(address))[0])
                    else:  # Domain name
                        header = struct.pack('!BBB', 3, len(address), 0) + address.encode()
                    
                    header += struct.pack('!H', port)
                    remote.sendall(header)
                else:
                    # Direct connection if no tunnel (for testing)
                    remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    remote.connect((address, port))
                    
                bind_address = remote.getsockname()
                
                # Send success response
                addr = struct.unpack("!I", socket.inet_aton(bind_address[0]))[0]
                port = bind_address[1]
                reply = struct.pack("!BBBBIH", self.SOCKS_VERSION, 0, 0, 1, addr, port)
                client.sendall(reply)
                
                # Set up forwarding with proper buffering
                self.forward_data(client, remote)
                
            except Exception as e:
                logging.error(f"SOCKS error: {e}")
                # Send failure response
                reply = struct.pack("!BBBBIH", self.SOCKS_VERSION, 5, 0, 1, 0, 0)
                client.sendall(reply)
                client.close()
                
        except Exception as e:
            logging.error(f"Error in SOCKS client handler: {e}")
            try:
                client.close()
            except:
                pass
            
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
        buffer = b''
        while self.running:
            try:
                # Use select to check if socket is readable
                readable, _, _ = select.select([source], [], [], 1.0)
                if not readable:
                    continue
                    
                data = source.recv(4096)
                if not data:
                    break
                    
                # Add data to buffer
                buffer += data
                
                # Try to send as much as possible
                while buffer:
                    try:
                        sent = destination.send(buffer)
                        buffer = buffer[sent:]
                    except socket.error as e:
                        if e.errno in (socket.EAGAIN, socket.EWOULDBLOCK):
                            # Socket is full, wait a bit
                            time.sleep(0.1)
                            continue
                        raise
                        
            except Exception as e:
                if self.running:
                    logging.error(f"Error in forward thread: {e}")
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
                client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
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
        self.proxy = SOCKSProxy(host='127.0.0.1', port=1080, tunnel=self)
        proxy_thread = threading.Thread(target=self.proxy.start)
        proxy_thread.daemon = True
        proxy_thread.start()
        
        logging.info("SOCKS proxy started on 127.0.0.1:1080")
        
        # Use a different port for the tunnel
        self.local_port = 1081  # Use a different port than the SOCKS proxy
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
        self.client_tunnels = {}  # Keep track of client tunnels

    def handle_client(self, client_socket: socket.socket):
        """Handle incoming connection from VPN client"""
        try:
            # Read VPN client commands as JSON
            buffer = ""
            while True:
                data = client_socket.recv(1024).decode()
                if not data:
                    break
                buffer += data
                if '\n' in buffer:
                    line, buffer = buffer.split('\n', 1)
                    request = json.loads(line)
                    response = self.handle_tunnel_request(client_socket, request)
                    client_socket.sendall((json.dumps(response) + "\n").encode())
        except Exception as e:
            logging.error(f"Error handling VPN client: {e}")
            client_socket.close()

    def handle_tunnel_request(self, vpn_socket: socket.socket, request: dict):
        """Handle tunnel request from VPN client"""
        try:
            action = request.get("action")
            if action == "connect":
                # Extract destination info
                remote_host = request.get("remote_host", "127.0.0.1")
                remote_port = request.get("remote_port", 80)
                
                logging.info(f"Creating tunnel to {remote_host}:{remote_port}")
                
                try:
                    # Connect to the requested destination
                    dest_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    dest_socket.connect((remote_host, remote_port))
                    
                    # Set up forwarding between VPN client and destination
                    with self.lock:
                        self.tunnels[vpn_socket] = dest_socket
                        self.tunnels[dest_socket] = vpn_socket
                        
                    # Start bidirectional forwarding
                    threading.Thread(target=self.forward, args=(vpn_socket, dest_socket)).start()
                    threading.Thread(target=self.forward, args=(dest_socket, vpn_socket)).start()
                    
                    return {"status": "success", "message": f"Connected to {remote_host}:{remote_port}"}
                except Exception as e:
                    logging.error(f"Failed to connect to {remote_host}:{remote_port}: {e}")
                    return {"status": "error", "message": f"Connection failed: {str(e)}"}
            else:
                return {"status": "error", "message": "Unknown tunnel action"}
        except Exception as e:
            return {"status": "error", "message": str(e)}