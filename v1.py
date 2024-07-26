import tkinter as tk
from tkinter import filedialog
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2

class AESGUI:
    def __init__(self):
        self.window = tk.Tk()  # Create a new tkinter window
        self.window.title("AES Encryption and Decryption Tool")

        # Create input fields and buttons
        self.password_label = tk.Label(self.window, text="Password:")
        self.password_entry = tk.Entry(self.window, show="*")
        self.file_label = tk.Label(self.window, text="File:")
        self.file_entry = tk.Entry(self.window)
        self.browse_button = tk.Button(self.window, text="Browse", command=self.browse_file)
        self.encrypt_button = tk.Button(self.window, text="Encrypt", command=self.encrypt_file)
        self.decrypt_button = tk.Button(self.window, text="Decrypt", command=self.decrypt_file)
        self.status_label = tk.Label(self.window, text="Status: Ready")

        # Layout input fields and buttons
        self.password_label.grid(row=0, column=0)
        self.password_entry.grid(row=0, column=1)
        self.file_label.grid(row=1, column=0)
        self.file_entry.grid(row=1, column=1)
        self.browse_button.grid(row=1, column=2)
        self.encrypt_button.grid(row=2, column=0)
        self.decrypt_button.grid(row=2, column=1)
        self.status_label.grid(row=3, column=0, columnspan=2)

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        self.file_entry.delete(0, tk.END)
        self.file_entry.insert(0, file_path)

    def encrypt_file(self):
        password = self.password_entry.get().encode()
        file_path = self.file_entry.get()
        try:
            aes_encrypt(file_path, password)
            self.status_label.config(text="Status: Encrypted successfully")
        except Exception as e:
            self.status_label.config(text="Status: Error occurred")

    def decrypt_file(self):
        password = self.password_entry.get().encode()
        file_path = self.file_entry.get()
        try:
            aes_decrypt(file_path, password)
            self.status_label.config(text="Status: Decrypted successfully")
        except Exception as e:
            self.status_label.config(text="Status: Error occurred")

    def run(self):
        self.window.mainloop()

def aes_encrypt(file_path, password, salt=None):
    # Derive a key from the password using PBKDF2
    if salt is None:
        salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32)
    # Generate a random IV
    iv = get_random_bytes(16)
    # Create an AES cipher object
    cipher = AES.new(key, AES.MODE_GCM, iv)
    # Read the file and encrypt it
    with open(file_path, 'rb') as file:
        data = file.read()
    encrypted_data, tag = cipher.encrypt_and_digest(data)
    # Write the salt, IV, and encrypted data to a new file
    with open(file_path + '.enc', 'wb') as file:
        file.write(salt + iv + encrypted_data + tag)

def aes_decrypt(file_path, password):
    # Read the salt, IV, and encrypted data from the file
    with open(file_path, 'rb') as file:
        salt = file.read(16)
        iv = file.read(16)
        encrypted_data = file.read()
        tag = encrypted_data[-16:]
        encrypted_data = encrypted_data[:-16]
    # Derive a key from the password using PBKDF2
    key = PBKDF2(password, salt, dkLen=32)
    # Create an AES cipher object
    cipher = AES.new(key, AES.MODE_GCM, iv)
    # Decrypt the data
    decrypted_data = cipher.decrypt_and_verify(encrypted_data, tag)
    # Write the decrypted data to a new file
    with open(file_path[:-4], 'wb') as file:
        file.write(decrypted_data)

if __name__ == "__main__":
    gui = AESGUI()
    gui.run()