# Micro-VPN

A lightweight VPN server with a user-friendly web interface for managing connections and users.

## Features

- 🔒 Secure encrypted communication
- 👥 User management system
- 📊 Real-time connection statistics
- 🌐 Web-based management interface
- 📈 Connection monitoring and analytics
- 🔐 Authentication system
- 🚀 Multi-threaded server architecture
- 🌐 IP Privacy: Your traffic appears to come from the server's IP address

## Prerequisites

- Python 3.7+
- Required Python packages (install via `pip install -r requirements.txt`):
  - streamlit
  - pandas
  - cryptography
  - pycryptodome

## Installation

1. Clone the repository:
```bash
git clone https://github.com/rhit-zhuy17/Micro-VPN.git
```

2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Configuration

The application uses a `shared_config.py` file for configuration. Make sure to set the following variables:
- `HOST`: Server host address
- `PORT`: Server port number
- `ENCRYPTION_KEY`: Encryption key for secure communication

### Setting Up Encryption

1. Generate a new encryption key:
```bash
python generate_key.py
```
This will:
- Generate a secure encryption key
- Save it to `shared_config.py`
- Print the key for your reference

2. Verify the setup:
- Check that `shared_config.py` has the `ENCRYPTION_KEY` variable set
- The key should be in the format: `ENCRYPTION_KEY = b'your-key-here'`
- Make sure both server and client have the same key

3. Key Management:
   - Keep your encryption key secure and private
   - The same key must be used on both server and client
   - If you need to change the key:
     1. Generate a new key using `generate_key.py`
     2. Make sure both server and client have the updated `shared_config.py`
     3. All existing connections will need to reconnect

4. Key Security:
   - Never share your encryption key
   - Store it securely in `shared_config.py`
   - Consider using environment variables for production deployments
   - Regularly rotate keys for enhanced security
   - Please don't push `shared_config.py` after modifying ip and key in the file

## Usage

### Server Setup

1. Start the server and web interface (both are integrated in app.py):
```bash
streamlit run app.py
```

This single command starts both:
- The VPN server that handles client connections
- The web interface for managing the server

2. Access the web interface:
   - Open your browser and navigate to `http://localhost:8501`
   - The default interface will show the VPN server management dashboard

### Client Connection

1. Run the client:
```bash
python client.py
```

2. When prompted, enter your credentials:
   - Username and password (must be registered on the server)
   - The client will automatically connect to the VPN server

3. Connection Status:
   - The client will show connection status and statistics
   - You can monitor your connection in the server's web interface
   - To disconnect, press Ctrl+C in the client terminal

### How It Works

When you connect to the VPN:
1. All your internet traffic is encrypted and routed through the VPN server
2. Your IP address will appear as the server's IP address to external services
3. Your actual IP address (e.g., your Mac's IP) is hidden from websites and services
4. The server acts as a middleman, forwarding your traffic while maintaining privacy

For example:
- If you run the server on Windows (IP: 203.0.113.1)
- And connect from your Mac (IP: 192.168.1.100)
- Websites will see your traffic coming from 203.0.113.1
- Your Mac's IP (192.168.1.100) remains hidden

### Default Users
The application comes with two default users:
- Username: `test_user`, Password: `test_pass`
- Username: `admin`, Password: `admin123`

### Managing Users

1. Adding New Users:
   - Use the sidebar in the web interface
   - Enter username and password
   - Click "Add User"

2. Viewing Users:
   - All registered users are displayed in the "All Users" section
   - Connection status and last seen information are shown
   - Active connections are displayed in the "Connected Users" section

### Monitoring

The dashboard provides real-time information about:
- Active connections
- Total connections
- Data transfer statistics
- Server uptime
- User connection status

## Security Features

- End-to-end encryption for all communications
- Secure user authentication
- Encrypted tunnel for data transfer
- Thread-safe user management
- IP privacy protection
- Traffic encryption
- Secure key management with PBKDF2 and Fernet

## Architecture

The application consists of several key components:
- `app.py`: Main application file containing both the VPN server and Streamlit web interface
- `client.py`: Client application for connecting to the VPN
- `tunnel.py`: VPN tunnel implementation
- `crypto_utils.py`: Encryption utilities using the key from shared_config.py
- `shared_config.py`: Configuration settings including the encryption key
- `generate_key.py`: Utility for generating secure encryption keys

## Troubleshooting

### Common Issues

1. Connection Failed:
   - Check that server and client are using the same encryption key
   - Verify the key in `shared_config.py` is properly set
   - Ensure the server is running and accessible

2. Authentication Failed:
   - Verify username and password
   - Check that the user exists on the server
   - Ensure the server is running

3. Encryption Issues:
   - Make sure `pycryptodome` is installed
   - Verify the encryption key is properly set in `shared_config.py`
   - Check that both server and client have the same key

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, please open an issue in the GitHub repository.
