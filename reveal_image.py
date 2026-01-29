"""
reveal_image.py - FIXED WITH LSB METHOD
Replace your entire reveal_image.py file with this code
"""

import numpy as np
from PIL import Image
import os
import sys


def reveal_image(steg_path, output_path):
    """
    Reveal hidden secret image from stego image using LSB method
    
    Args:
        steg_path: Path to the stego image (PNG file)
        output_path: Path where revealed image will be saved
    
    Returns:
        output_path if successful, None if failed
    """
    print(f"🔍 LSB REVEAL: Extracting from {steg_path}...")
    
    try:
        # Load stego image
        stego = Image.open(steg_path).convert('RGB')
        stego_array = np.array(stego, dtype=np.uint8)
        
        print(f"  📏 Stego size: {stego.size}")
        print(f"  📊 Processing {stego_array.shape[0]}x{stego_array.shape[1]} pixels...")
        
        # Extract the 4 LSBs (these contain the hidden secret)
        # Shift them back to MSB positions (multiply by 16 / shift left by 4)
        secret_array = (stego_array & 0x0F) << 4
        
        # Duplicate the 4 bits into lower 4 bits for better visibility
        # This helps because we only have 4 bits of information per channel
        secret_array = secret_array | (secret_array >> 4)
        
        # Create revealed image
        revealed_image = Image.fromarray(secret_array.astype(np.uint8), mode='RGB')
        
        # Ensure output directory exists
        output_dir = os.path.dirname(output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        
        # Save revealed image as PNG
        revealed_image.save(output_path, 'PNG')
        
        print(f"  ✅ Revealed image saved: {output_path}")
        print(f"  ℹ️  Note: Quality is reduced to 4-bit per channel (16 colors)")
        
        return output_path
        
    except Exception as e:
        print(f"  ❌ Error during revealing: {e}")
        import traceback
        traceback.print_exc()
        return None


# ==========================================
# OPTIONAL: CLI Testing
# ==========================================
if __name__ == "__main__":
    """
    Test the reveal function directly from command line:
    python reveal_image.py stego.png revealed.png
    """
    
    if len(sys.argv) < 3:
        print("Usage: python reveal_image.py STEGO_IMAGE OUTPUT_IMAGE")
        print("Example: python reveal_image.py stego.png revealed.png")
        sys.exit(1)
    
    steg_path = sys.argv[1]
    output_path = sys.argv[2]
    
    if not os.path.exists(steg_path):
        print(f"❌ Error: Stego image not found: {steg_path}")
        sys.exit(1)
    
    result = reveal_image(steg_path, output_path)
    
    if result:
        print(f"\n✅ SUCCESS!")
        print(f"   Revealed image saved to: {result}")
    else:
        print(f"\n❌ FAILED! Check error messages above.")
        sys.exit(1)