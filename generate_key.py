import os
import string
import re

def generate_key():
    """Generate a secure 32-byte key for AES encryption"""
    # Use a mix of letters, numbers, and special characters
    chars = string.ascii_letters + string.digits + '+/'
    # Generate 32 random characters
    key = ''.join(os.urandom(32).hex()[:32])
    return key

def main():
    # Generate a new key
    key = generate_key()
    
    # Print the key in a format ready to use in shared_config.py
    print("\nGenerated Encryption Key:")
    print("-" * 50)
    print(f"ENCRYPTION_KEY = b'{key}'")
    print("-" * 50)
    
    # Update shared_config.py
    try:
        with open('shared_config.py', 'r') as f:
            content = f.read()
        
        # Use regex to find and replace the ENCRYPTION_KEY line
        pattern = r"ENCRYPTION_KEY\s*=\s*b'[^']*'"
        new_key_line = f"ENCRYPTION_KEY = b'{key}'"
        
        if re.search(pattern, content):
            new_content = re.sub(pattern, new_key_line, content)
        else:
            new_content = content + f"\n{new_key_line}"
        
        with open('shared_config.py', 'w') as f:
            f.write(new_content)
        
        print("\n✅ Successfully updated shared_config.py with the new key")
        print("\nImportant: Make sure to use the same key on both server and client!")
        
    except Exception as e:
        print(f"\n❌ Error updating shared_config.py: {e}")
        print("\nPlease manually copy the key above into your shared_config.py file")

if __name__ == "__main__":
    main() 