import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def generate_key():
    """Generate a secure encryption key"""
    # Generate a random salt
    salt = os.urandom(16)
    
    # Generate a random password
    password = os.urandom(32)
    
    # Use PBKDF2 to derive a key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    
    # Generate the key
    key = base64.urlsafe_b64encode(kdf.derive(password))
    
    return key

def main():
    # Generate a new key
    key = generate_key()
    
    # Print the key in a format ready to use in shared_config.py
    print("\nGenerated Encryption Key:")
    print("-" * 50)
    print(f"ENCRYPTION_KEY = {key}")
    print("-" * 50)
    
    # Update shared_config.py
    try:
        with open('shared_config.py', 'r') as f:
            content = f.read()
        
        # Replace the existing key
        if 'ENCRYPTION_KEY' in content:
            new_content = content.replace(
                "ENCRYPTION_KEY = b'your-32-byte-encryption-key-here!!'",
                f"ENCRYPTION_KEY = {key}"
            )
        else:
            new_content = content + f"\nENCRYPTION_KEY = {key}"
        
        with open('shared_config.py', 'w') as f:
            f.write(new_content)
        
        print("\n✅ Successfully updated shared_config.py with the new key")
        print("\nImportant: Make sure to use the same key on both server and client!")
        
    except Exception as e:
        print(f"\n❌ Error updating shared_config.py: {e}")
        print("\nPlease manually copy the key above into your shared_config.py file")

if __name__ == "__main__":
    main() 