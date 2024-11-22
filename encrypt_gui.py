import os
from pathlib import Path
from tkinter import Tk, filedialog, simpledialog, messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
import secrets

def derive_key(password, salt, iterations=100000):
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_data(data, key, iv):
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()

def encrypt_file():
    root = Tk()
    root.withdraw()

    file_path = filedialog.askopenfilename(title="Select File to Encrypt")
    if not file_path:
        return

    password = simpledialog.askstring("Password", "Enter a password to encrypt the file:", show="*")
    if not password:
        return

    try:
        salt_iv = secrets.token_bytes(32)  # 16 bytes salt + 16 bytes IV
        salt, iv = salt_iv[:16], salt_iv[16:]
        key = derive_key(password, salt)

        file_path = Path(file_path)
        encrypted_file = file_path.with_suffix(".enc")

        with file_path.open("rb") as f, encrypted_file.open("wb") as ef:
            ef.write(salt_iv)
            for chunk in iter(lambda: f.read(64 * 1024), b""):
                encrypted_chunk = encrypt_data(chunk, key, iv)
                ef.write(encrypted_chunk)

        file_path.unlink()  # (Optional) to Delete original file
        messagebox.showinfo("Success", f"File encrypted successfully as '{encrypted_file}'.")
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {e}")

if __name__ == "__main__":
    encrypt_file()
