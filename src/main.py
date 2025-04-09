## @package usb_key_generator
#  Graficzna aplikacja do generowania kluczy RSA i zapisywania ich na pendrive'ach.

import os
import time
import threading
import tkinter as tk
from tkinter import simpledialog, messagebox, scrolledtext, filedialog
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import win32api

## @class USBKeyApp
#  @brief Aplikacja GUI do generowania pary kluczy RSA i zapisywania ich na pendrive.
class USBKeyApp(tk.Tk):
    ## Konstruktor klasy USBKeyApp.
    def __init__(self):
        super().__init__()
        self.title("RSA USB Key Generator")
        self.geometry("600x400")

        self.log = scrolledtext.ScrolledText(self, wrap=tk.WORD)
        self.log.pack(expand=True, fill=tk.BOTH)

        self.log_message("Waiting for USB drive...")
        self.previous_drives = self.get_drive_letters()

        self.poll_usb_thread = threading.Thread(target=self.poll_for_usb, daemon=True)
        self.poll_usb_thread.start()

    ## Loguje wiadomość do okna oraz do konsoli.
    #  @param message Wiadomość do wyświetlenia.
    def log_message(self, message):
        self.log.insert(tk.END, message + "\n")
        self.log.see(tk.END)
        print(message)

    ## Zwraca listę aktualnie podłączonych dysków.
    #  @return Zbiór nazw dysków (np. {'C:\\', 'D:\\'}).
    def get_drive_letters(self):
        drives = win32api.GetLogicalDriveStrings()
        return set(drives.split('\x00')[:-1])

    ## Szyfruje prywatny klucz RSA za pomocą PIN-u użytkownika.
    #  @param private_key_bytes Bajty klucza prywatnego w formacie PEM.
    #  @param pin 4-cyfrowy PIN wprowadzony przez użytkownika.
    #  @return Szyfrowane bajty klucza prywatnego.
    def encrypt_private_key(self, private_key_bytes, pin):
        iv = get_random_bytes(16)
        key = SHA256.new(pin.encode()).digest()
        cipher = AES.new(key, AES.MODE_CFB, iv)
        return iv + cipher.encrypt(private_key_bytes)

    ## Zapisuje publiczny klucz RSA do pliku PEM.
    #  @param private_key Klucz prywatny, z którego generowany jest klucz publiczny.
    #  @return Ścieżka do zapisanego pliku publicznego klucza.
    def save_public_key(self, private_key):
        public_key = private_key.public_key()
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        pub_path = filedialog.asksaveasfilename(
            defaultextension=".pem",
            filetypes=[("PEM files", "*.pem")],
            title="Save Public Key As"
        )

        if not pub_path:
            self.log_message("Public key save cancelled.")
            return None

        with open(pub_path, "wb") as f:
            f.write(pub_bytes)

        self.log_message(f"Public key saved to: {pub_path}")
        return pub_path

    ## Obsługuje włożenie pendrive'a i generuje klucz RSA.
    #  @param drive_letter Nazwa dysku, na którym wykryto pendrive'a.
    def handle_usb_insertion(self, drive_letter):
        self.log_message(f"Pendrive detected at {drive_letter}")

        pin = None
        while True:
            pin = simpledialog.askstring("PIN Entry", "Enter a 4-digit PIN:", parent=self, show="*")
            if pin is None:
                self.log_message("Key generation cancelled by user.")
                return
            if pin.isdigit() and len(pin) == 4:
                break
            messagebox.showerror("Invalid PIN", "PIN must be 4 digits.")

        self.log_message("Generating 4096-bit RSA key pair...")
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

        if self.save_public_key(private_key) is None:
            self.log_message("Public key was not saved. Aborting.")
            return

        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        encrypted = self.encrypt_private_key(private_bytes, pin)

        try:
            encrypted_path = os.path.join(drive_letter, "private_encrypted.pem")
            with open(encrypted_path, "wb") as f:
                f.write(encrypted)
            self.log_message(f"Encrypted private key saved to USB: {encrypted_path}")
        except Exception as e:
            self.log_message(f"Failed to save encrypted key: {e}")

    ## Wątek do monitorowania podłączenia pendrive'a.
    def poll_for_usb(self):
        while True:
            current_drives = self.get_drive_letters()
            new_drives = current_drives - self.previous_drives
            self.previous_drives = current_drives

            if new_drives:
                drive = list(new_drives)[0]
                self.after(0, lambda: self.handle_usb_insertion(drive))
            time.sleep(1)

## Funkcja główna aplikacji.
if __name__ == "__main__":
    app = USBKeyApp()
    app.mainloop()
