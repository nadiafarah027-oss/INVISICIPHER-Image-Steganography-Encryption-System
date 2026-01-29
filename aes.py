"""
aes.py - Complete AES Image Encryption/Decryption
Place this file in: app/models/encryption/aes.py
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from PIL import Image
import os
import hashlib
import sys

# Ensure library dependencies are met:
# pip install pycryptodome pillow

def derive_key(password):
    """Convert password string to 32-byte AES key"""
    return hashlib.sha256(password.encode('utf-8')).digest()


def encrypt(image_path, output_path, password):
  
    try:
        # Read the image file as binary
        with open(image_path, 'rb') as f:
            image_data = f.read()
        
        # Derive AES key from password
        key = derive_key(password)
        
        # Generate random IV (Initialization Vector)
        iv = get_random_bytes(16)
        
        # Create AES cipher in CBC mode
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Pad the data to be multiple of 16 bytes
        padded_data = pad(image_data, AES.block_size)
        
        # Encrypt the data
        encrypted_data = cipher.encrypt(padded_data)
        
        # Combine IV + encrypted data
        # (IV is needed for decryption, so we store it with the encrypted data)
        final_data = iv + encrypted_data
        
        # Ensure output has .enc extension
        if not output_path.endswith('.enc'):
            output_path = os.path.splitext(output_path)[0] + '.enc'
            
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        with open(output_path, 'wb') as f:
            f.write(final_data)
        
        print(f"  ✅ Encrypted saved: {output_path}")
        print(f"  📊 Original size: {len(image_data)} bytes")
        print(f"  📊 Encrypted size: {len(final_data)} bytes")
        
        return output_path
        
    except Exception as e:
        print(f"  ❌ Encryption failed: {e}")
        import traceback
        traceback.print_exc()
        return None


def decrypt(encrypted_path, output_path, password):
    """
    Decrypt an encrypted image file
    
    Args:
        encrypted_path: Path to encrypted file (.enc)
        output_path: Where to save decrypted image (.png)
        password: Decryption password (must match encryption password)
    
    Returns:
        output_path if successful, None if failed
    """
    print(f"🔓 AES DECRYPT: {os.path.basename(encrypted_path)}")
    
    try:
        # Read encrypted file
        with open(encrypted_path, 'rb') as f:
            encrypted_data = f.read()
        
        # Extract IV (first 16 bytes)
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        print(f"  📊 Encrypted size: {len(encrypted_data)} bytes")
        
        # Derive key from password
        key = derive_key(password)
        
        # Create AES cipher with the same IV
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Decrypt the data
        decrypted_padded = cipher.decrypt(ciphertext)
        
        # Remove padding
        try:
            decrypted_data = unpad(decrypted_padded, AES.block_size)
        except ValueError:
            print("  ❌ Wrong password or corrupted file (Padding Error)!")
            return None
        
        # Save decrypted image
        # Ensure output has an image extension (default to png if none provided)
        if not output_path.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp')):
             output_path = os.path.splitext(output_path)[0] + '.png'

        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)
        
        # Verify it's a valid image
        try:
            img = Image.open(output_path)
            img.verify() # Verify integrity
            print(f"  ✅ Decrypted saved: {output_path}")
            print(f"  📊 Image size: {img.size}")
            print(f"  ✅ Image is valid!")
        except Exception:
            print("  ⚠️  Warning: Decrypted file content does not appear to be a valid image.")
        
        return output_path
        
    except FileNotFoundError:
        print(f"  ❌ File not found: {encrypted_path}")
        return None
    except Exception as e:
        print(f"  ❌ Decryption failed: {e}")
        import traceback
        traceback.print_exc()
        return None


# ==========================================
# TESTING BLOCK
# ==========================================
if __name__ == "__main__":
    """
    Test encryption and decryption directly from terminal
    """
    if len(sys.argv) < 4:
        print("Usage:")
        print("  Encrypt: python aes.py encrypt IMAGE PASSWORD OUTPUT.enc")
        print("  Decrypt: python aes.py decrypt FILE.enc PASSWORD OUTPUT.png")
        sys.exit(1)
    
    mode = sys.argv[1].lower()
    input_file = sys.argv[2]
    password = sys.argv[3]
    output_file = sys.argv[4] if len(sys.argv) > 4 else None
    
    if mode == "encrypt":
        if not output_file:
            output_file = os.path.splitext(input_file)[0] + "_encrypted.enc"
        
        # Calling the renamed function 'encrypt'
        result = encrypt(input_file, output_file, password)
        
        if result:
            print(f"\n✅ SUCCESS! Encrypted file: {result}")
    
    elif mode == "decrypt":
        if not output_file:
            output_file = os.path.splitext(input_file)[0] + "_decrypted.png"
        
        # Calling the renamed function 'decrypt'
        result = decrypt(input_file, output_file, password)
        
        if result:
            print(f"\n✅ SUCCESS! Decrypted image: {result}")
    
    else:
        print(f"❌ Unknown mode: {mode}")