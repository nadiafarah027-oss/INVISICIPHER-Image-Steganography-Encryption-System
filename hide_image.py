"""
hide_image.py - LSB METHOD FOR HIDING
Create this file in the same folder as reveal_image.py
"""

import numpy as np
from PIL import Image
import os
import sys


def hide_image(cover_path, secret_path, output_path):
    """
    Hide secret image inside cover image using LSB method
    
    Args:
        cover_path: Path to cover image (e.g., flower.jpg)
        secret_path: Path to secret image (e.g., bird.jpg)
        output_path: Path where stego image will be saved (must be .png)
    
    Returns:
        output_path if successful, None if failed
    """
    print(f"🔐 LSB HIDE: Embedding secret into cover...")
    print(f"  📂 Cover: {cover_path}")
    print(f"  🔒 Secret: {secret_path}")
    
    try:
        # Load images as RGB
        cover = Image.open(cover_path).convert('RGB')
        secret = Image.open(secret_path).convert('RGB')
        
        original_size = cover.size
        print(f"  📏 Cover size: {original_size}")
        
        # Resize secret to match cover
        if secret.size != cover.size:
            print(f"  🔄 Resizing secret from {secret.size} to {cover.size}")
            secret = secret.resize(cover.size, Image.LANCZOS)
        
        # Convert to numpy arrays
        cover_array = np.array(cover, dtype=np.uint8)
        secret_array = np.array(secret, dtype=np.uint8)
        
        # LSB Steganography Algorithm:
        # - Keep the 4 most significant bits (MSB) of cover: cover & 0xF0
        # - Take 4 MSB of secret and shift to LSB position: secret >> 4
        # - Combine them: (cover & 0xF0) | (secret >> 4)
        stego_array = (cover_array & 0xF0) | (secret_array >> 4)
        
        # Create stego image
        stego_image = Image.fromarray(stego_array.astype(np.uint8), mode='RGB')
        
        # Ensure output directory exists
        output_dir = os.path.dirname(output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        
        # IMPORTANT: Save as PNG (lossless format)
        # JPEG will destroy the hidden data!
        if not output_path.lower().endswith('.png'):
            print("  ⚠️  Warning: Output should be PNG format. Converting...")
            output_path = os.path.splitext(output_path)[0] + '.png'
        
        stego_image.save(output_path, 'PNG')
        
        print(f"  ✅ Stego image saved: {output_path}")
        print(f"  📊 Cover preservation: 93.75% (4 bits per channel)")
        print(f"  ℹ️  Secret is hidden in the 4 LSBs of each pixel")
        
        return output_path
        
    except Exception as e:
        print(f"  ❌ Error during hiding: {e}")
        import traceback
        traceback.print_exc()
        return None


# ==========================================
# OPTIONAL: CLI Testing
# ==========================================
if __name__ == "__main__":
    """
    Test the hide function directly from command line:
    python hide_image.py cover.jpg secret.jpg stego.png
    """
    
    if len(sys.argv) < 4:
        print("Usage: python hide_image.py COVER_IMAGE SECRET_IMAGE OUTPUT_IMAGE")
        print("Example: python hide_image.py flower.jpg bird.jpg stego.png")
        sys.exit(1)
    
    cover_path = sys.argv[1]
    secret_path = sys.argv[2]
    output_path = sys.argv[3]
    
    if not os.path.exists(cover_path):
        print(f"❌ Error: Cover image not found: {cover_path}")
        sys.exit(1)
    
    if not os.path.exists(secret_path):
        print(f"❌ Error: Secret image not found: {secret_path}")
        sys.exit(1)
    
    result = hide_image(cover_path, secret_path, output_path)
    
    if result:
        print(f"\n✅ SUCCESS!")
        print(f"   Stego image saved to: {result}")
        print(f"   Now reveal it: python reveal_image.py {result} revealed.png")
    else:
        print(f"\n❌ FAILED! Check error messages above.")
        sys.exit(1)
