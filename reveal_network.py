import numpy as np
from PIL import Image
import torch
import os
import sys

# ==========================================
# 1. SETUP PATHS
# ==========================================
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.append(CURRENT_DIR)

# ==========================================
# 2. REVEALER CLASS (What the calling code expects)
# ==========================================
class RevealNetwork(torch.nn.Module):
    """
    Wrapper class that the calling code expects.
    This loads StegoNet and uses its reveal_secret method.
    """
    def __init__(self, device='cpu'):
        super().__init__()
        self.device = device
        
        # Import StegoNet
        try:
            from model import StegoNet
        except ImportError:
            try:
                from .model import StegoNet
            except ImportError:
                raise FileNotFoundError("❌ CRITICAL: model.py not found. Please ensure model.py is in the same directory.")
        
        # Initialize the model
        self.model = StegoNet()
        self.model.to(device)
        self.model.eval()
        
        # Load weights
        self._load_weights()
    
    def _load_weights(self):
        """Load the trained weights"""
        weight_path = os.path.join(CURRENT_DIR, 'invisicipher_final.pth')
        
        # Fallback paths
        if not os.path.exists(weight_path):
            candidates = [
                "app/models/DEEP_STEGO/invisicipher_final.pth",
                "models/DEEP_STEGO/invisicipher_final.pth",
                "invisicipher_final.pth",
                "../invisicipher_final.pth"
            ]
            for c in candidates:
                if os.path.exists(c):
                    weight_path = c
                    break
        
        if os.path.exists(weight_path):
            try:
                state_dict = torch.load(weight_path, map_location=self.device)
                self.model.load_state_dict(state_dict)
                print(f"✅ Loaded weights from: {weight_path}")
            except Exception as e:
                print(f"⚠️ Error loading weights: {e}")
                print("⚠️ Proceeding without weights (output will be random)")
        else:
            print(f"⚠️ WARNING: Weight file not found. Searched: {weight_path}")
            print("⚠️ Model will use random initialization (output will be garbage)")
    
    def forward(self, steg_tensor):
        """
        Forward pass - reveals the hidden image
        Args:
            steg_tensor: Tensor of shape (B, 3, H, W) containing the steganographic image
        Returns:
            revealed_tensor: Tensor of shape (B, 3, H, W) containing the revealed secret
        """
        with torch.no_grad():
            return self.model.reveal_secret(steg_tensor)
    
    def reveal(self, steg_tensor):
        """Alias for forward() for compatibility"""
        return self.forward(steg_tensor)


# ==========================================
# 3. STANDALONE REVEAL FUNCTION
# ==========================================
def reveal_image(steg_path, output_path=None, device='cpu'):
    """
    Reveals the hidden image from a steganographic image file
    
    Args:
        steg_path: Path to the steganographic image
        output_path: Path to save the revealed image (optional)
        device: 'cpu' or 'cuda'
    
    Returns:
        output_path if saved, or numpy array if output_path is None
    """
    print(f"🔍 Revealing hidden image from: {steg_path}")
    
    # Load image
    try:
        steg_image = Image.open(steg_path).convert('RGB')
        steg_array = np.array(steg_image)
    except Exception as e:
        print(f"❌ Error loading image {steg_path}: {e}")
        return None
    
    # Normalize to [0, 1]
    steg_normalized = steg_array.astype(np.float32) / 255.0
    
    # Convert to Tensor (1, 3, H, W)
    steg_tensor = torch.from_numpy(steg_normalized).permute(2, 0, 1).unsqueeze(0)
    steg_tensor = steg_tensor.to(device)
    
    try:
        # Initialize revealer
        revealer = RevealNetwork(device=device)
        
        # Reveal the secret
        with torch.no_grad():
            revealed_tensor = revealer.reveal(steg_tensor)
        
        # Convert back to numpy
        revealed_tensor = revealed_tensor.squeeze(0).permute(1, 2, 0)
        revealed_array = revealed_tensor.cpu().numpy()
        
        # Dynamic normalization (fixes black screen issues)
        val_min = revealed_array.min()
        val_max = revealed_array.max()
        
        if val_max > val_min:
            print(f"📊 Normalizing range [{val_min:.4f}, {val_max:.4f}] -> [0, 1]")
            revealed_array = (revealed_array - val_min) / (val_max - val_min)
        else:
            print(f"⚠️ Warning: Flat output detected (min=max={val_min:.4f})")
        
        # Scale to 0-255
        revealed_array = (revealed_array * 255.0).clip(0, 255).astype(np.uint8)
        
        # Create image
        revealed_image = Image.fromarray(revealed_array, mode='RGB')
        
        # Resize to match input if needed
        if revealed_image.size != steg_image.size:
            print(f"📐 Resizing output from {revealed_image.size} to {steg_image.size}")
            revealed_image = revealed_image.resize(steg_image.size, Image.LANCZOS)
        
        # Save or return
        if output_path:
            revealed_image.save(output_path)
            print(f"✅ Success! Revealed image saved to: {output_path}")
            return output_path
        else:
            return revealed_array
    
    except Exception as e:
        print(f"❌ ERROR during reveal: {e}")
        import traceback
        traceback.print_exc()
        raise


# ==========================================
# 4. COMMAND LINE INTERFACE
# ==========================================
if __name__ == "__main__":
    if len(sys.argv) >= 3:
        reveal_image(sys.argv[1], sys.argv[2])
    else:
        print("Usage: python reveal_network.py <input_steg.png> <output_revealed.png>")
        print("\nExample:")
        print("  python reveal_network.py steg_image.png revealed_secret.png")