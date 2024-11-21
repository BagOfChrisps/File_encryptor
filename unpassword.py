import sys
from tkinter import Tk, simpledialog, messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend

# Derive a key from a password
def derive_key(password, salt, iterations=100000):
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Decrypt a file
def decrypt_file(encrypted_file):
    try:
        # Read the encrypted file
        with open(encrypted_file, "rb") as f:
            data = f.read()

        salt = data[:16]
        iv = data[16:32]
        encrypted_data = data[32:]

        # Password input
        root = Tk()
        root.withdraw()
        password = simpledialog.askstring("Password", "Enter the password to decrypt the file:", show="*")
        if not password:
            return

        # Derive the key and decrypt
        key = derive_key(password, salt)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        unpadder = PKCS7(algorithms.AES.block_size).unpadder()
        original_data = unpadder.update(padded_data) + unpadder.finalize()

        # Save the decrypted file
        original_file = encrypted_file.replace(".enc", "")
        with open(original_file, "wb") as f:
            f.write(original_data)

        messagebox.showinfo("Success", f"File decrypted successfully as '{original_file}'.")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        messagebox.showerror("Error", "Invalid usage. This script requires the encrypted file path.")
    else:
        decrypt_file(sys.argv[1])
