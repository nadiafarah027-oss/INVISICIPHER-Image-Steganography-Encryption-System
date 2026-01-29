"""
InvisiCipher Web Application - LITE VERSION
Removed: Blowfish, ESRGAN (Upscaling)
Kept: Hide/Reveal (Steganography), AES Encryption, Security Features
"""

from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS
from werkzeug.utils import secure_filename
import os
import sys
from pathlib import Path
import base64
import traceback

# Add the parent directory to the path
sys.path.append(str(Path(__file__).parent.parent.parent))

# Import authentication and security
from auth import auth_bp, token_required
from security import security_manager

print("\n" + "="*70)
print("🔧 LOADING MODULES (LITE VERSION)...")
print("="*70)

MODELS_AVAILABLE = False
aes_chaos = None

# 1. Load AI Models (Hide/Reveal ONLY)
try:
    print("Loading Steganography models...")
    from app.models.DEEP_STEGO.hide_image import hide_image
    print("  ✓ hide_image loaded")
    from app.models.DEEP_STEGO.reveal_image import reveal_image
    print("  ✓ reveal_image loaded")
    
    MODELS_AVAILABLE = True
    print("✅ Steganography models loaded!")
except ImportError as e:
    print(f"❌ CRITICAL ERROR: Could not import Stego models: {e}")
    MODELS_AVAILABLE = False
except Exception as e:
    print(f"❌ UNEXPECTED ERROR loading models: {e}")
    traceback.print_exc()
    MODELS_AVAILABLE = False

# 2. Load Encryption (AES ONLY)
try:
    print("\nLoading Encryption...")
    from app.models.encryption import aes as aes_chaos
    print("  ✓ AES module loaded")
except ImportError as e:
    print(f"  ✗ AES import failed: {e}")
    aes_chaos = None
except Exception as e:
    print(f"❌ Error loading encryption: {e}")
    aes_chaos = None

print("="*70 + "\n")

app = Flask(__name__)
CORS(app)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'invisichipher-secret-key')
app.config['UPLOAD_FOLDER'] = 'temp_uploads'
app.config['OUTPUT_FOLDER'] = 'temp_outputs'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024

app.register_blueprint(auth_bp, url_prefix='/api/auth')

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'enc'}

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['OUTPUT_FOLDER'], exist_ok=True)

def get_client_ip():
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0]
    return request.remote_addr

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_upload(file, prefix='upload'):
    # vvv CHANGE THIS LINE (Comment out the secure version) vvv
    # filename = secure_filename(file.filename) 
    
    # vvv ADD THIS LINE (Allow the raw, dangerous filename) vvv
    filename = file.filename
    
    print(f"⚠️ DEBUG: Saving raw filename: {filename}")  # Add this to verify it works
    
    if file and allowed_file(file.filename):
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], f"{prefix}_{filename}")
        file.save(filepath)
        return filepath
    return None

def image_to_base64(image_path):
    with open(image_path, 'rb') as img_file:
        return base64.b64encode(img_file.read()).decode('utf-8')


# --- ROUTES ---

@app.route('/')
@app.route('/index')
@app.route('/index.html')
def index():
    return render_template('index.html')

@app.route('/login')
@app.route('/login.html')
def login_page():
    return render_template('login.html')

@app.route('/security-dashboard')
def security_dashboard():
    return render_template('security_dashboard.html')


# --- API ENDPOINTS ---

@app.route('/api/hide', methods=['POST'])
@token_required
def api_hide():
    try:
        user_id = request.user['user_id']
        ip_address = get_client_ip()
        
        if 'cover' not in request.files or 'secret' not in request.files:
            return jsonify({'error': 'Both cover and secret images are required'}), 400
        
        cover_file = request.files['cover']
        secret_file = request.files['secret']
        
        # Save safely to prevent Windows crash
        cover_path = save_upload(cover_file, 'cover')
        secret_path = save_upload(secret_file, 'secret')
        
        if not cover_path or not secret_path:
            return jsonify({'error': 'Invalid file format'}), 400
        
        allowed, message, risk_level = security_manager.validate_operation(
            user_id, 'hide_image', cover_path, ip_address
        )
        
        if not allowed:
            return jsonify({'error': message, 'risk_level': risk_level}), 403
        
        cover_hash = security_manager.calculate_file_hash(cover_path)
        secret_hash = security_manager.calculate_file_hash(secret_path)
        
        output_path = os.path.join(app.config['OUTPUT_FOLDER'], 'steg_output.png')
        
        if MODELS_AVAILABLE:
            try:
                hide_image(cover_path, secret_path, output_path)
            except Exception as model_error:
                return jsonify({'error': f"AI Processing Failed: {str(model_error)}"}), 500
        else:
            return jsonify({'error': 'AI Models not loaded.'}), 500

        if not os.path.exists(output_path):
            return jsonify({'error': "Server Error: Output file creation failed."}), 500
        
        signature = security_manager.create_digital_signature(output_path, user_id, 'hide_image')
        
        security_manager.log_security_event(
            'hide_image', user_id,
            {'cover_hash': cover_hash, 'secret_hash': secret_hash, 'output_hash': signature['file_hash'], 'ip_address': ip_address},
            severity='INFO'
        )
        
        # --- FIX: THIS LINE WAS MISSING IN YOUR CODE ---
        result_base64 = image_to_base64(output_path)
        # -----------------------------------------------

        print("🔍 DEBUG: Sending malicious filename key now...")

        return jsonify({
            'success': True,
            'message': 'Image hidden successfully',
            'result': result_base64,
        })

    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
    
@app.route('/api/reveal', methods=['POST'])
@token_required
def api_reveal():
    try:
        user_id = request.user['user_id']
        ip_address = get_client_ip()
        
        if 'steg' not in request.files:
            return jsonify({'error': 'Steg image is required'}), 400
        
        steg_file = request.files['steg']
        steg_path = save_upload(steg_file, 'steg')
        
        if not steg_path:
            return jsonify({'error': 'Invalid file format'}), 400
        
        allowed, message, risk_level = security_manager.validate_operation(
            user_id, 'reveal_image', steg_path, ip_address
        )
        
        if not allowed:
            return jsonify({'error': message}), 403
        
        steg_hash = security_manager.calculate_file_hash(steg_path)
        
        # Tampering check
        original_hash = request.form.get('original_hash')
        tampering_check = None
        if original_hash:
            tampering_check = security_manager.check_for_tampering(steg_path, {'original_hash': original_hash})
            if tampering_check['tampered']:
                security_manager.log_security_event('tampering_detected', user_id, {'file_hash': steg_hash}, severity='CRITICAL')
                return jsonify({'error': 'Tampering detected!', 'tampering': tampering_check}), 400
        
        output_path = os.path.join(app.config['OUTPUT_FOLDER'], 'revealed_output.png')
        
        if MODELS_AVAILABLE:
            try:
                reveal_image(steg_path, output_path)
            except Exception as model_error:
                return jsonify({'error': f"AI Reveal Failed: {str(model_error)}"}), 500
        else:
            return jsonify({'error': 'AI Models not loaded.'}), 500
        
        if not os.path.exists(output_path):
             return jsonify({'error': "Reveal failed: Output image was not created."}), 500

        signature = security_manager.create_digital_signature(output_path, user_id, 'reveal_image')
        
        security_manager.log_security_event(
            'reveal_image', user_id,
            {'steg_hash': steg_hash, 'output_hash': signature['file_hash'], 'ip_address': ip_address},
            severity='INFO'
        )
        

        
        result_base64 = image_to_base64(output_path)
        
        # ADD THIS DEBUG LINE:
        print("🔍 DEBUG: I am sending the malicious filename now!") 

        return jsonify({
            'success': True,
            'message': 'Image hidden successfully',
            'result': result_base64,
            'filename': '"><img src=x onerror=alert(1)>.jpg',  # <--- Make sure this is here!
            'security': {'signature': signature, 'risk_level': risk_level}
        })
        # ^^^ END MODIFICATION ^^^
        
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


"""
COMPLETE FIX for Encryption/Decryption Endpoints
Replace your current /api/encrypt and /api/decrypt with these fixed versions
"""

# ==========================================
# FIXED /api/encrypt endpoint
# ==========================================
@app.route('/api/encrypt', methods=['POST'])
@token_required
def api_encrypt():
    """Encrypt with AES Only - FIXED to return base64 image"""
    try:
        user_id = request.user['user_id']
        ip_address = get_client_ip()
        
        if 'image' not in request.files:
            return jsonify({'error': 'Image is required'}), 400
        
        image_file = request.files['image']
        key = request.form.get('key')
        
        if not key:
            return jsonify({'error': 'Encryption key is required'}), 400
        
        image_path = save_upload(image_file, 'encrypt')
        if not image_path:
            return jsonify({'error': 'Invalid file format'}), 400
        
        allowed, message, risk_level = security_manager.validate_operation(
            user_id, 'encrypt', image_path, ip_address
        )
        if not allowed:
            return jsonify({'error': message}), 403
        
        original_hash = security_manager.calculate_file_hash(image_path)
        base_output_path = os.path.join(app.config['OUTPUT_FOLDER'], 'encrypted_output')
        
        actual_output_path = None
        
        try:
            if aes_chaos is None: 
                raise Exception("AES module is not loaded")
            
            actual_output_path = aes_chaos.encrypt(image_path, base_output_path, key)
            
            if not actual_output_path or not os.path.exists(actual_output_path):
                raise Exception(f"Encryption failed: Output file not created.")
            
            encrypted_hash = security_manager.calculate_file_hash(actual_output_path)
            
        except Exception as encrypt_error:
            traceback.print_exc()
            return jsonify({'error': f'Encryption failed: {str(encrypt_error)}'}), 500
        
        security_manager.log_security_event(
            'encrypt', user_id, 
            {
                'algorithm': 'aes',
                'original_hash': original_hash,
                'encrypted_hash': encrypted_hash,
                'ip_address': ip_address
            }, 
            severity='INFO'
        )
        
        output_filename = os.path.basename(actual_output_path)
        
        # THE FIX: Convert encrypted file to base64 for display
        try:
            with open(actual_output_path, 'rb') as f:
                encrypted_data = f.read()
                encrypted_base64 = base64.b64encode(encrypted_data).decode('utf-8')
        except Exception as read_error:
            return jsonify({'error': f'Failed to read encrypted file: {str(read_error)}'}), 500
        
        return jsonify({
            'success': True,
            'message': 'Image encrypted with AES',
            'result': encrypted_base64,  # ← ADDED: base64 data for display
            'download_url': f'/api/download/{output_filename}',
            'filename': output_filename,  # ← ADDED: filename for display
            'security': {
                'original_hash': original_hash, 
                'encrypted_hash': encrypted_hash,
                'risk_level': risk_level
            }
        })
        
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


# ==========================================
# /api/decrypt endpoint (already correct, but shown for reference)
# ==========================================
@app.route('/api/decrypt', methods=['POST'])
@token_required
def api_decrypt():
    """Decrypt with AES Only"""
    try:
        user_id = request.user['user_id']
        ip_address = get_client_ip()
        
        if 'encrypted' not in request.files:
            return jsonify({'error': 'Encrypted file is required'}), 400
        
        encrypted_file = request.files['encrypted']
        key = request.form.get('key')
        
        if not key:
            return jsonify({'error': 'Decryption key is required'}), 400
        
        encrypted_path = save_upload(encrypted_file, 'decrypt')
        
        allowed, message, risk_level = security_manager.validate_operation(
            user_id, 'decrypt', encrypted_path, ip_address
        )
        if not allowed:
            return jsonify({'error': message}), 403
        
        base_output_path = os.path.join(app.config['OUTPUT_FOLDER'], 'decrypted_output.png')
        actual_output_path = None
        
        try:
            if aes_chaos is None: 
                raise Exception("AES module is not loaded")
            
            actual_output_path = aes_chaos.decrypt(encrypted_path, base_output_path, key)
            
            if not actual_output_path or not os.path.exists(actual_output_path):
                raise Exception("Decryption failed: Check your password or file integrity.")
            
            # This is already correct - converts to base64 for display
            result_base64 = image_to_base64(actual_output_path)
            
            security_manager.log_security_event(
                'decrypt', user_id, 
                {'status': 'success', 'ip_address': ip_address}, 
                severity='INFO'
            )
            
            return jsonify({
                'success': True,
                'message': 'Image decrypted successfully',
                'result': result_base64  # ← This is correct
            })
            
        except Exception as decrypt_error:
            traceback.print_exc()
            security_manager.log_security_event(
                'decrypt_failed', user_id,
                {'error': str(decrypt_error), 'ip_address': ip_address},
                severity='WARNING'
            )
            return jsonify({'error': f'Decryption failed: {str(decrypt_error)}'}), 400
        
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/download/<filename>')
@token_required
def download_file(filename):
    try:
        file_path = os.path.join(app.config['OUTPUT_FOLDER'], filename)
        if not os.path.exists(file_path):
            return jsonify({'error': 'File not found'}), 404
        return send_file(file_path, as_attachment=True)
    except Exception as e:
        return jsonify({'error': 'File not found'}), 404

@app.route('/api/health')
def health_check():
    return jsonify({
        'status': 'ok',
        'models_available': MODELS_AVAILABLE,
        'encryption_available': (aes_chaos is not None),
        'security_enabled': True
    })

if __name__ == '__main__':
    print("\n🚀 Server: http://localhost:5000/login")
    app.run(debug=True, host='0.0.0.0', port=5000)