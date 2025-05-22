import requests
import socket
import time
import sys

def get_public_ip():
    """Get public IP address from external service"""
    try:
        response = requests.get('https://api.ipify.org', timeout=5)
        return response.text
    except Exception as e:
        return f"Error getting public IP: {e}"

def get_local_ip():
    """Get local IP address"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Doesn't need to be reachable, just to determine interface
        s.connect(('10.255.255.255', 1))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        return f"Error getting local IP: {e}"

def check_continuously():
    """Check IP addresses continuously"""
    try:
        print("\n===== IP ADDRESS CHECKER =====")
        print("Press Ctrl+C to exit")
        print("==============================")
        
        while True:
            public_ip = get_public_ip()
            local_ip = get_local_ip()
            
            print(f"\n[{time.strftime('%H:%M:%S')}]")
            print(f"Public IP: {public_ip}")
            print(f"Local IP:  {local_ip}")
            print("------------------------------")
            time.sleep(5)
            
    except KeyboardInterrupt:
        print("\nExiting IP checker...")
        sys.exit(0)

if __name__ == "__main__":
    check_continuously() 