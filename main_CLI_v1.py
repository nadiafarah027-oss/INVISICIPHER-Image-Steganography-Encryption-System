from tkinter import filedialog
from app.models.DEEP_STEGO.hide_image import hide_image
from app.models.DEEP_STEGO.reveal_image import reveal_image
from app.models.encryption import aes as aes_chaos

print("InvisiCipher CLI")

""" DEEP STEGANO """
print("--- Image Hiding ---")
print("Select the COVER image:")
cover_filename = filedialog.askopenfilename(title="Select Cover Image", filetypes=(
    ("Image files", "*.png;*.jpg;*.jpeg"), ("All files", "*.*")))

print("Select the SECRET image:")
secret_filename = filedialog.askopenfilename(title="Select Secret Image", filetypes=(
    ("Image files", "*.png;*.jpg;*.jpeg"), ("All files", "*.*")))

if cover_filename and secret_filename:
    hide_image(cover_filename, secret_filename)
    print("Image hidden successfully!\n")
else:
    print("Operation cancelled: Files not selected.\n")


""" ENCRYPTION """
print("--- Encryption ---")
print("1. AES Encryption")
print("2. AES Decryption")
enc_choice = input("Enter your choice (1 or 2): ")

if enc_choice == '1':
    # AES Encryption
    print("Select image to ENCRYPT:")
    filename = filedialog.askopenfilename(title="Select Image to Encrypt", filetypes=(
        ("Image files", "*.png;*.jpg;*.jpeg"), ("All files", "*.*")))
    
    if filename:
        key = input("Enter your secret key: ")
        aes_chaos.encrypt(filename, key)
        print("Encryption complete.")

elif enc_choice == '2':
    # AES Decryption
    print("Select image to DECRYPT:")
    filename = filedialog.askopenfilename(title="Select Image to Decrypt", filetypes=(
        ("All files", "*.*"), ("Encrypted", "*.enc"), ("Image files", "*.png;*.jpg;*.jpeg")))
    
    if filename:
        key = input("Enter your secret key: ")
        aes_chaos.decrypt(filename, key)
        print("Decryption complete.")

else:
    print("Invalid choice or skipped.")

""" REVEAL """
print("\n--- Reveal Hidden Image ---")
reveal_choice = input("Do you want to reveal a hidden image? (y/n): ")

if reveal_choice.lower() == 'y':
    print("Select the STEG image:")
    steg_filename = filedialog.askopenfilename(title="Select Steg Image", filetypes=(
        ("Image files", "*.png;*.jpg;*.jpeg"), ("All files", "*.*")))
    
    if steg_filename:
        reveal_image(steg_filename)
        print("Image revealed successfully.")