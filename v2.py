import tkinter as tk
import os
from tkinter import filedialog
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2

class AESGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("AES Encryption and Decryption Tool")
        self.master.geometry("300x200")

        self.password_label = tk.Label(master, text="Password:")
        self.password_label.pack()

        self.password_entry = tk.Entry(master, show="*")
        self.password_entry.pack()

        self.file_label = tk.Label(master, text="File:")
        self.file_label.pack()

        self.file_entry = tk.Entry(master)
        self.file_entry.pack()

        self.browse_button = tk.Button(master, text="Browse", command=self.browse_file)
        self.browse_button.pack()

        self.encrypt_button = tk.Button(master, text="Encrypt", command=self.encrypt_file)
        self.encrypt_button.pack()

        self.decrypt_button = tk.Button(master, text="Decrypt", command=self.decrypt_file)
        self.decrypt_button.pack()

        self.status_label = tk.Label(master, text="Status: Ready")
        self.status_label.pack()

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        self.file_entry.delete(0, tk.END)
        self.file_entry.insert(0, file_path)

    def encrypt_file(self):
        password = self.password_entry.get().encode()
        file_path = self.file_entry.get()
        try:
            aes_encrypt(file_path, password)
            os.remove(file_path)
            self.status_label.config(text="Status: Encrypted successfully")
        except Exception as e:
            self.status_label.config(text="Status: Error occurred")

    def decrypt_file(self):
        password = self.password_entry.get().encode()
        file_path = self.file_entry.get()
        try:
            decrypted_file_path = aes_decrypt(file_path, password)
            os.rename(decrypted_file_path, file_path)
            os.remove(file_path + '.enc')
            self.status_label.config(text="Status: Decrypted successfully")
        except Exception as e:
            self.status_label.config(text="Status: Error occurred")

def aes_encrypt(file_path, password, salt=None):

    if salt is None:

        salt = get_random_bytes(16)

    key = PBKDF2(password, salt, dkLen=32)

    iv = get_random_bytes(16)

    cipher = AES.new(key, AES.MODE_GCM, iv)

    with open(file_path, 'rb') as file:

        data = file.read()

    encrypted_data, tag = cipher.encrypt_and_digest(data)

    with open(file_path + '.enc', 'wb') as file:

        file.write(salt + iv + encrypted_data + tag)
def aes_decrypt(file_path, password):

    with open(file_path, 'rb') as file:

        salt = file.read(16)

        iv = file.read(16)

        encrypted_data = file.read()

        tag = encrypted_data[-16:]

        encrypted_data = encrypted_data[:-16]

    key = PBKDF2(password, salt, dkLen=32)

    cipher = AES.new(key, AES.MODE_GCM, iv)

    decrypted_data = cipher.decrypt_and_verify(encrypted_data, tag)

    decrypted_file_path = file_path[:-4] + '_decrypted'

    with open(decrypted_file_path, 'wb') as file:

        file.write(decrypted_data)

    return decrypted_file_path

if __name__ == "__main__":
    root = tk.Tk()
    gui = AESGUI(root)
    root.mainloop()