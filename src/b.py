## @package pdf_verifier
#  Aplikacja do weryfikacji podpisu cyfrowego w pliku PDF z użyciem klucza publicznego RSA.
import os
import traceback
import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Hash import SHA256
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

## Ładuje klucz publiczny z wybranego przez użytkownika pliku PEM.
#  @return Załadowany klucz publiczny RSA lub None, jeśli operacja została anulowana.
def load_public_key_from_dialog():
    pub_key_path = filedialog.askopenfilename(
        title="Select Public Key File",
        filetypes=[("PEM files", "*.pem")]
    )
    if not pub_key_path:
        return None

    with open(pub_key_path, "rb") as f:
        pub_key_data = f.read()
    return serialization.load_pem_public_key(pub_key_data)

## Weryfikuje podpis cyfrowy w pliku PDF.
#  @param signed_file_path Ścieżka do pliku PDF z podpisem.
def verify_signature_gui():
    signed_file_path = filedialog.askopenfilename(title="Select Signed PDF")
    if not signed_file_path:
        return

    if not os.path.exists(signed_file_path):
        messagebox.showerror("Error", "Signed file not found.")
        return

    public_key = load_public_key_from_dialog()
    if not public_key:
        messagebox.showerror("Error", "Public key not selected.")
        return

    with open(signed_file_path, "rb") as f:
        data = f.read()

    signature = data[-512:]
    original_pdf = data[:-512]

    digest = SHA256.new(original_pdf).digest()

    try:
        public_key.verify(
            signature,
            digest,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        messagebox.showinfo("Success", "Signature is VALID. Document has not been tampered with.")
    except Exception as e:
        messagebox.showerror("Verification Failed", f"Signature verification FAILED:\n\n{e.__class__.__name__}: {e}")
        traceback.print_exc()

## Główna funkcja GUI aplikacji.
def main():
    root = tk.Tk()
    root.title("PDF Signature Verifier")
    root.geometry("300x150")

    btn = tk.Button(root, text="Verify Signed PDF", command=verify_signature_gui, padx=10, pady=5)
    btn.pack(expand=True)

    root.mainloop()

## @brief Główna funkcja aplikacji.
if __name__ == "__main__":
    main()
