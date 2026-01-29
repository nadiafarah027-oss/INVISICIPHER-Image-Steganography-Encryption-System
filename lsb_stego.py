"""
SIMPLE LSB STEGANOGRAPHY - DROP-IN REPLACEMENT
Just copy these two functions and replace your existing hide_image() and reveal_image() functions
"""

import numpy as np
from PIL import Image
import os

# ==========================================
# HIDING FUNCTION (Replace your hide_image)
# ==========================================
def hide_image(cover_path, secret_path, output_path):
 
    try:
        # Load images
        cover = Image.open(cover_path).convert('RGB')
        secret = Image.open(secret_path).convert('RGB')
        
        original_size = cover.size
        print(f"  📏 Cover size: {original_size}")
        
        # Resize secret to match cover
        if secret.size != cover.size:
            print(f"  🔄 Resizing secret from {secret.size} to {cover.size}")
            secret = secret.resize(cover.size, Image.LANCZOS)
        
        # Convert to numpy arrays
        cover_array = np.array(cover)
        secret_array = np.array(secret)
        
        # LSB Steganography:
        # - Take 4 MSBs from cover (bits 7-4)
        # - Take 4 MSBs from secret (bits 7-4) and shift them to LSBs
        # - Combine them
        stego_array = (cover_array & 0xF0) | (secret_array >> 4)
        
        # Create stego image
        stego_image = Image.fromarray(stego_array.astype(np.uint8))
        
        # Ensure output directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # Save as PNG (lossless)
        stego_image.save(output_path, "PNG")
        
        print(f"  ✅ Stego image saved: {output_path}")
        print(f"  📊 Quality: Cover image is 93.75% preserved")
    
        return output_path
        
    except Exception as e:
        print(f"  ❌ Error during hiding: {e}")
        import traceback
        traceback.print_exc()
        return None


# ==========================================
# REVEALING FUNCTION (Replace your reveal_image)
# ==========================================
def reveal_image(steg_path, output_path):
    """
    Reveal hidden secret image from stego image
    
    Args:
        steg_path: Path to stego image
        output_path: Where to save revealed secret image
    
    Returns:
        output_path if successful, None if failed
    """
    print(f"🔍 LSB REVEAL: Extracting from {steg_path}...")
    
    try:
        # Load stego image
        stego = Image.open(steg_path).convert('RGB')
        stego_array = np.array(stego)
        
        print(f"  📏 Stego size: {stego.size}")
        
        # Extract the 4 LSBs (these contain the secret)
        # Shift them back to MSB positions
        secret_array = (stego_array & 0x0F) << 4
        
        # Duplicate the 4 bits into lower 4 bits for better visibility
        # (Since we only have 4 bits of information, we copy them)
        secret_array = secret_array | (secret_array >> 4)
        
        # Create revealed image
        revealed_image = Image.fromarray(secret_array.astype(np.uint8))
        
        # Ensure output directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # Save revealed image
        revealed_image.save(output_path, "PNG")
        
        print(f"  ✅ Revealed image saved: {output_path}")
        print(f"  📊 Note: Quality is reduced (4-bit per channel)")
        
        return output_path
        
    except Exception as e:
        print(f"  ❌ Error during revealing: {e}")
        import traceback
        traceback.print_exc()
        return None


# ==========================================
# OPTIONAL: Testing function
# ==========================================
if __name__ == "__main__":
    """
    Test the functions directly
    """
    import sys
    
    if len(sys.argv) == 4 and sys.argv[1] == "hide":
        # python lsb_stego.py hide cover.jpg secret.jpg output.png
        cover = sys.argv[2]
        secret = sys.argv[3]
        output = sys.argv[4] if len(sys.argv) > 4 else "stego_output.png"
        
        result = hide_image(cover, secret, output)
        if result:
            print(f"\n✅ SUCCESS! Stego image: {result}")
        else:
            print(f"\n❌ FAILED!")
    
    elif len(sys.argv) == 3 and sys.argv[1] == "reveal":
        # python lsb_stego.py reveal stego.png revealed.png
        stego = sys.argv[2]
        output = sys.argv[3] if len(sys.argv) > 3 else "revealed_output.png"
        
        result = reveal_image(stego, output)
        if result:
            print(f"\n✅ SUCCESS! Revealed image: {result}")
        else:
            print(f"\n❌ FAILED!")
    
    else:
        print("Usage:")
        print("  Hide:   python lsb_stego.py hide cover.jpg secret.jpg output.png")
        print("  Reveal: python lsb_stego.py reveal stego.png revealed.png")