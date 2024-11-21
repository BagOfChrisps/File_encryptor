import os
from tkinter import Tk, filedialog, simpledialog, messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
import secrets

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

# Encrypt a file
def encrypt_file():
    root = Tk()
    root.withdraw()  # Hide the root window

    # File selection
    file_path = filedialog.askopenfilename(title="Select File to Encrypt")
    if not file_path:
        return

    # Password input
    password = simpledialog.askstring("Password", "Enter a password to encrypt the file:", show="*")
    if not password:
        return

    # Encryption
    try:
        salt = secrets.token_bytes(16)
        key = derive_key(password, salt)
        iv = secrets.token_bytes(16)

        with open(file_path, "rb") as f:
            data = f.read()

        padder = PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        encrypted_file = file_path + ".enc"
        with open(encrypted_file, "wb") as f:
            f.write(salt + iv + encrypted_data)

        os.remove(file_path)  # Optional: Delete the original file
        messagebox.showinfo("Success", f"File encrypted successfully as '{encrypted_file}'.")
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {e}")

if __name__ == "__main__":
    encrypt_file()
