import socket
import json
import sys
from crypto_utils import encrypt, decrypt
from shared_config import HOST, PORT

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
    
    client_socket = None
    authenticated = False
    username = None

    while True:
        try:
            command = input("\n> ").strip()
            
            if command == "quit":
                if client_socket:
                    client_socket.close()
                print("Goodbye!")
                break
                
            elif command == "help":
                print_help()
                
            elif command.startswith("connect "):
                if client_socket:
                    print("Already connected. Please disconnect first.")
                    continue
                    
                try:
                    _, username, password = command.split()
                except ValueError:
                    print("Usage: connect <username> <password>")
                    continue
                
                try:
                    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    client_socket.connect((HOST, PORT))
                    print("[+] Connected to server")
                    
                    # Send authentication request
                    auth_request = {
                        "type": "auth",
                        "username": username,
                        "password": password
                    }
                    client_socket.send(encrypt(json.dumps(auth_request).encode()))
                    
                    # Get response
                    response = json.loads(decrypt(client_socket.recv(4096)).decode())
                    if response["status"] == "success":
                        authenticated = True
                        print("[+] Authentication successful")
                    else:
                        print(f"[-] Authentication failed: {response['message']}")
                        client_socket.close()
                        client_socket = None
                        
                except Exception as e:
                    print(f"[-] Connection failed: {e}")
                    if client_socket:
                        client_socket.close()
                        client_socket = None
                
            elif command == "status":
                if not client_socket or not authenticated:
                    print("[-] Not connected. Use 'connect' first.")
                    continue
                    
                request = {"type": "status"}
                client_socket.send(encrypt(json.dumps(request).encode()))
                response = json.loads(decrypt(client_socket.recv(4096)).decode())
                
                if response["status"] == "success":
                    print(f"\n[*] Connected users: {response['connected_users']}")
                    print("[*] User list:")
                    for user in response['user_list']:
                        print(f"    - {user['username']} (connected since {user['start_time']})")
                else:
                    print(f"[-] Error: {response['message']}")
                    
            elif command.startswith("message "):
                if not client_socket or not authenticated:
                    print("[-] Not connected. Use 'connect' first.")
                    continue
                    
                message = command[8:]
                request = {
                    "type": "message",
                    "content": message
                }
                client_socket.send(encrypt(json.dumps(request).encode()))
                response = json.loads(decrypt(client_socket.recv(4096)).decode())
                print(f"[Server] {response['message']}")
                
            else:
                print("Unknown command. Type 'help' for available commands.")
                
        except KeyboardInterrupt:
            print("\nGoodbye!")
            if client_socket:
                client_socket.close()
            break
        except Exception as e:
            print(f"[-] Error: {e}")
            if client_socket:
                client_socket.close()
                client_socket = None
                authenticated = False

if __name__ == "__main__":
    main()
