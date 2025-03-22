import os
import time
import threading
import tkinter as tk
from tkinter import simpledialog, messagebox, scrolledtext
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
import win32api

PUBLIC_KEY_PATH = os.path.expanduser("~/rsa_public_key.pem")
CERTIFICATE_PATH = os.path.expanduser("~/rsa_certificate.pem")

class USBKeyApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("🔐 RSA USB Key Generator")
        self.geometry("600x400")

        self.log = scrolledtext.ScrolledText(self, wrap=tk.WORD)
        self.log.pack(expand=True, fill=tk.BOTH)

        self.log_message("🔍 Waiting for USB drive...")
        self.previous_drives = self.get_drive_letters()

        self.poll_usb_thread = threading.Thread(target=self.poll_for_usb, daemon=True)
        self.poll_usb_thread.start()

    def log_message(self, message):
        self.log.insert(tk.END, message + "\n")
        self.log.see(tk.END)
        print(message)

    def get_drive_letters(self):
        drives = win32api.GetLogicalDriveStrings()
        return set(drives.split('\x00')[:-1])

    def encrypt_private_key(self, private_key_bytes, pin):
        iv = get_random_bytes(16)
        key = SHA256.new(pin.encode()).digest()
        cipher = AES.new(key, AES.MODE_CFB, iv)
        return iv + cipher.encrypt(private_key_bytes)

    def generate_self_signed_certificate(self, private_key):
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"PL"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Test Organization"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"User A"),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow() - timedelta(days=1)
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        ).sign(private_key, hashes.SHA256())
        return cert

    def save_certificate_and_public_key(self, private_key):
        public_key = private_key.public_key()
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        cert = self.generate_self_signed_certificate(private_key)
        cert_bytes = cert.public_bytes(serialization.Encoding.PEM)

        with open(PUBLIC_KEY_PATH, "wb") as f:
            f.write(pub_bytes)
        with open(CERTIFICATE_PATH, "wb") as f:
            f.write(cert_bytes)

        self.log_message(f"✅ Public key saved to: {PUBLIC_KEY_PATH}")
        self.log_message(f"✅ Certificate saved to: {CERTIFICATE_PATH}")

    def handle_usb_insertion(self, drive_letter):
        self.log_message(f"✅ Pendrive detected at {drive_letter}")

        pin = None
        while True:
            pin = simpledialog.askstring("PIN Entry", "Enter a 4-digit PIN:", parent=self, show="*")
            if pin is None:
                self.log_message("❌ Key generation cancelled by user.")
                return
            if pin.isdigit() and len(pin) == 4:
                break
            messagebox.showerror("Invalid PIN", "PIN must be 4 digits.")

        self.log_message("🔐 Generating 4096-bit RSA key pair...")
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

        self.save_certificate_and_public_key(private_key)

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
            self.log_message(f"✅ Encrypted private key saved to USB: {encrypted_path}")
        except Exception as e:
            self.log_message(f"❌ Failed to save encrypted key: {e}")

    def poll_for_usb(self):
        while True:
            current_drives = self.get_drive_letters()
            new_drives = current_drives - self.previous_drives
            self.previous_drives = current_drives

            if new_drives:
                drive = list(new_drives)[0]
                self.after(0, lambda: self.handle_usb_insertion(drive))
            time.sleep(1)

if __name__ == "__main__":
    app = USBKeyApp()
    app.mainloop()
