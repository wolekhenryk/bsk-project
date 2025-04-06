import os
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, scrolledtext
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import win32api


class SignerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PDF Signer")
        self.geometry("600x400")

        self.log = scrolledtext.ScrolledText(self, wrap=tk.WORD)
        self.log.pack(expand=True, fill=tk.BOTH)

        self.log_message("Waiting for pendrive with 'private_encrypted.pem'...")

        threading.Thread(target=self.wait_for_pendrive_with_key, daemon=True).start()

    def log_message(self, msg):
        self.log.insert(tk.END, msg + "\n")
        self.log.see(tk.END)
        print(msg)

    def wait_for_pendrive_with_key(self):
        while True:
            drives = win32api.GetLogicalDriveStrings().split('\x00')[:-1]
            for drive in drives:
                if os.path.exists(os.path.join(drive, "private_encrypted.pem")):
                    self.drive = drive
                    self.log_message(f"Pendrive detected at {drive}")
                    self.after(0, self.decrypt_flow)
                    return
            time.sleep(2)

    def decrypt_private_key(self, encrypted_data, pin):
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        key = SHA256.new(pin.encode()).digest()
        cipher = AES.new(key, AES.MODE_CFB, iv)
        return cipher.decrypt(ciphertext)

    def decrypt_flow(self):
        try:
            with open(os.path.join(self.drive, "private_encrypted.pem"), "rb") as f:
                encrypted_data = f.read()
        except Exception as e:
            self.log_message(f"Could not read encrypted key: {e}")
            return

        pin = simpledialog.askstring("PIN Entry", "Enter your 4-digit PIN:", parent=self, show="*")
        if not pin:
            self.log_message("PIN entry cancelled.")
            return

        try:
            decrypted_key = self.decrypt_private_key(encrypted_data, pin)
            self.private_key = serialization.load_pem_private_key(decrypted_key, password=None)
        except Exception as e:
            self.log_message(f"Failed to decrypt or load private key: {e}")
            return

        self.after(0, self.prompt_for_pdf)

    def prompt_for_pdf(self):
        file_path = filedialog.askopenfilename(title="Select PDF file to sign", filetypes=[("PDF files", "*.pdf")])
        if not file_path:
            self.log_message("No file selected.")
            return

        with open(file_path, "rb") as f:
            pdf_data = f.read()

        self.log_message("Signing PDF using RSA private key...")

        try:
            digest = SHA256.new(pdf_data).digest()

            signature = self.private_key.sign(
                digest,
                padding.PKCS1v15(),
                hashes.SHA256()
            )

            output_pdf = file_path.replace(".pdf", "_signed.pdf")
            with open(output_pdf, "wb") as f:
                f.write(pdf_data + signature)

            self.log_message(f"PDF signed and saved as: {output_pdf}")
            messagebox.showinfo("Success", f"Signed PDF saved as:\n{output_pdf}")
        except Exception as e:
            self.log_message(f"Signing failed: {e}")


if __name__ == "__main__":
    app = SignerApp()
    app.mainloop()
