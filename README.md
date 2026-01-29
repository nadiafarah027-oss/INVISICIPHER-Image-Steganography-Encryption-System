<p align="center"> <img src="app/ui/logo.png" alt="InvisiCipher Logo" width="120"> </p>

<p align="center"> <strong>Dual-Layer Security: Embedding Secrets with LSB and Hardening with AES-256</strong> </p>

📌 Project Overview
InvisiCipher is a security-focused application designed for my Final Year Project. It provides a robust framework for secure data transmission by combining Steganography and Cryptography. By embedding a secret image within a cover image using Least Significant Bit (LSB) manipulation and subsequently encrypting the result with the Advanced Encryption Standard (AES), the project ensures that even if a hidden message is suspected, it remains computationally infeasible to access without the correct cryptographic key.

🚀 Key Features
LSB Steganography: Efficiently hides a secret image within a 24-bit RGB cover image by utilizing the 4 least significant bits of each color channel.

AES-256 Encryption: Provides a secondary layer of security using AES in CBC (Cipher Block Chaining) mode to encrypt the steganographic output.

Dual Interface: Supports both a modern, Cyberpunk-themed Web UI (Flask/HTML5) and a Command Line Interface (CLI) for automated tasks.

Lossless Processing: Enforces PNG formatting to prevent data corruption common in lossy compression (like JPEG).

Secure Authentication: A full JWT-based login system to restrict access to the steganography suite.

🏗️ System Architecture
The workflow follows a "Defense in Depth" strategy:

Preparation: The secret image is resized to match the dimensions of the cover image.

Embedding (Hide): The 4 Most Significant Bits (MSBs) of the secret are injected into the 4 LSBs of the cover.

Encryption: The resulting "Steg" image is converted to a binary stream and encrypted via AES-256.

Decryption & Extraction (Reveal): The process is reversed using a shared secret key and the LSB extraction algorithm.

🛠️ Tech Stack
Backend: Python 3.x, Flask

Frontend: HTML5, CSS3 (CSS Grid & Animations), JavaScript (Vanilla ES6)

Image Processing: NumPy, Pillow (PIL)

Cryptography: PyCryptodome (AES-256-CBC)

Authentication: JSON Web Tokens (JWT)