import sys

from PyPDF2 import PdfWriter, PdfReader
from PyQt6.QtWidgets import QApplication, QMainWindow, QWidget, QPushButton, QFileDialog, QLabel, QVBoxLayout, QTabWidget
import win32api
import win32file
import base64
import datetime
import io
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import PyPDF2

class MainTab(QWidget):
    _USB_detected = False
    _USB_letter = ""
    _PDF_file = ""
    def __init__(self):
        super().__init__()
        self.DetectUSB()
        layout = QVBoxLayout()
        self.result_label = QLabel("")
        self.open_button = QPushButton("Wybierz PDF")
        self.sign_button = QPushButton("Podpisz PDF")
        self.open_button.clicked.connect(self.open_file_dialog)
        self.sign_button.clicked.connect(self.sign_file)
        if self._USB_detected:
            layout.addWidget(QLabel("Wykryto USB o literze: " + self._USB_letter))
        else:
            layout.addWidget(QLabel("Nie wykryto USB"))
        layout.addWidget(self.result_label)
        layout.addWidget(self.open_button)
        layout.addWidget(self.sign_button)

        self.setLayout(layout)

    def open_file_dialog(self):
        file_dialog = QFileDialog(self)
        file_dialog.setWindowTitle("Open PDF")
        file_dialog.setFileMode(QFileDialog.FileMode.ExistingFile)
        file_dialog.setViewMode(QFileDialog.ViewMode.Detail)

        if file_dialog.exec():
            selected_file = file_dialog.selectedFiles()[0]
            if selected_file.lower().endswith(".pdf"):
                self.result_label.setText("Wybrano poprawny plik PDF.")
                self._PDF_file = selected_file
            else:
                self.result_label.setText("Wybrany plik nie jest plikiem PDF.")

    def sign_file(self):
        if not self._PDF_file:
            self.result_label.setText("Please select a PDF file first.")
            return

        if not self._USB_detected:
            self.result_label.setText("USB drive with private key not found.")
            return

        try:
            # Get PIN from user
            from getpass import getpass
            pin = getpass("Enter your PIN to decrypt the private key: ")

            # Load encrypted private key from USB
            with open(self._USB_letter + "encrypted_private.pem", "r") as f:
                encrypted_data = f.read()

            # Decrypt the private key
            private_key = self.decrypt_private_key(encrypted_data, pin.encode())
            if not private_key:
                self.result_label.setText("Wrong PIN or corrupted private key.")
                return

            # Create PDF signature
            signature = self.create_pdf_signature(private_key, self._PDF_file)

            # Save signed PDF
            output_file = self._PDF_file.replace(".pdf", "_signed.pdf")
            with open(output_file, "wb") as f:
                f.write(signature)

            self.result_label.setText(f"PDF successfully signed and saved as: {output_file}")

        except Exception as e:
            self.result_label.setText(f"Error during signing: {str(e)}")

    def decrypt_private_key(self, encrypted_data, pin):
        try:
            import base64
            from Crypto.Cipher import AES

            # Prepare the key (hash if needed)
            if len(pin) < 32:
                pin = hashlib.sha256(pin).digest()
            elif len(pin) > 32:
                pin = pin[:32]

            # Decode and split the encrypted data
            encrypted_bytes = base64.b64decode(encrypted_data)
            nonce = encrypted_bytes[:15]  # OCB uses 15-byte nonce
            tag = encrypted_bytes[15:31]  # Tag is 16 bytes
            ciphertext = encrypted_bytes[31:]

            # Decrypt
            cipher = AES.new(pin, AES.MODE_OCB, nonce=nonce)
            return cipher.decrypt_and_verify(ciphertext, tag)
        except:
            return None

    def create_pdf_signature(self, private_key, pdf_path):
        """Sign PDF content without affecting verifiability"""
        try:
            # Read original PDF
            with open(pdf_path, "rb") as f:
                original_pdf = PdfReader(f)
                writer = PdfWriter()

                # Copy all pages to preserve content exactly
                for page in original_pdf.pages:
                    writer.add_page(page)

                # Create hash of the original content
                content_buffer = io.BytesIO()
                writer.write(content_buffer)
                content_to_sign = content_buffer.getvalue()
                pdf_hash = SHA256.new(content_to_sign)

                # Sign the hash
                rsa_key = RSA.import_key(private_key)
                signer = pkcs1_15.new(rsa_key)
                signature = signer.sign(pdf_hash)

                # Store signature in document info (doesn't affect content hash)
                writer.add_metadata({
                    '/Signature': base64.b64encode(signature).decode('utf-8'),
                    '/SigningDate': datetime.datetime.now().isoformat()
                })

                # Write signed PDF
                output_buffer = io.BytesIO()
                writer.write(output_buffer)
                return output_buffer.getvalue()

        except Exception as e:
            print(f"Signing error: {str(e)}")
            return None


    def DetectUSB(self):
        # Znajdź USB
        drive_list = win32api.GetLogicalDriveStrings()
        drive_list = drive_list.split("\x00")[0:-1]  # Ostatni element to ""
        for letter in drive_list:
            if win32file.GetDriveType(letter) == win32file.DRIVE_REMOVABLE:  # Sprawdź czy ostatni elemnt to USB
                print("Dysk USB to: " + str(letter))
                self._USB_letter = letter
                self._USB_detected = True
                return
        self._USB_detected = False
        self._USB_letter = ""
        return

class SecondTab(QWidget):
    _PDF_file = ""
    _Key_file = ""
    def __init__(self):
        super().__init__()

        layout = QVBoxLayout()
        self.result_label = QLabel("")
        self.result_label2 = QLabel("")
        self.open_pdf_button = QPushButton("Wybierz PDF")
        self.open_key_button = QPushButton("Wybierz klucz")
        self.verify_button = QPushButton("Zweryfikuj podpis")
        self.open_pdf_button.clicked.connect(self.open_pdf_dialog)
        self.open_key_button.clicked.connect(self.open_key_dialog)
        self.verify_button.clicked.connect(self.verify_signature)
        layout.addWidget(self.result_label)
        layout.addWidget(self.result_label2)
        layout.addWidget(self.open_pdf_button)
        layout.addWidget(self.open_key_button)
        layout.addWidget(self.verify_button)

        self.setLayout(layout)

    def open_key_dialog(self):
        file_dialog = QFileDialog(self)
        file_dialog.setWindowTitle("Open Public Key")
        file_dialog.setFileMode(QFileDialog.FileMode.ExistingFile)
        file_dialog.setViewMode(QFileDialog.ViewMode.Detail)

        if file_dialog.exec():
            selected_file = file_dialog.selectedFiles()[0]
            if selected_file.lower().endswith(".pem"):
                self.result_label2.setText("Wybrano poprawny plik klucza.")
                self._Key_file = selected_file
            else:
                self.result_label2.setText("Wybrany plik nie jest plikiem klucza.")

    def open_pdf_dialog(self):
        file_dialog = QFileDialog(self)
        file_dialog.setWindowTitle("Open PDF")
        file_dialog.setFileMode(QFileDialog.FileMode.ExistingFile)
        file_dialog.setViewMode(QFileDialog.ViewMode.Detail)

        if file_dialog.exec():
            selected_file = file_dialog.selectedFiles()[0]
            if selected_file.lower().endswith(".pdf"):
                self.result_label.setText("Wybrano poprawny plik PDF.")
                self._PDF_file = selected_file
            else:
                self.result_label.setText("Wybrany plik nie jest plikiem PDF.")

    def verify_signature(self):
        if not self._PDF_file:
            self.result_label.setText("Please select a PDF file first.")
            return

        if not self._Key_file:
            self.result_label.setText("Please select a public key file first.")
            return

        try:
            # Load public key
            with open(self._Key_file, "rb") as f:
                public_key_data = f.read()

            # Load the PDF
            with open(self._PDF_file, "rb") as f:
                pdf_content = f.read()

            # Verify the signature
            is_valid = self.verify_pdf_signature(public_key_data, pdf_content)

            if is_valid:
                self.result_label.setText("Signature is VALID")
                self.result_label.setStyleSheet("color: green")
            else:
                self.result_label.setText("Signature is INVALID")
                self.result_label.setStyleSheet("color: red")

        except Exception as e:
            self.result_label.setText(f"Error during verification: {str(e)}")
            self.result_label.setStyleSheet("color: red")

    def verify_pdf_signature(self, public_key_data, pdf_content):
        """Verify PDF signature while ignoring the signature metadata"""
        try:
            # Read PDF
            pdf_reader = PdfReader(io.BytesIO(pdf_content))

            # Get signature from metadata
            if not hasattr(pdf_reader, 'metadata') or not pdf_reader.metadata:
                return False

            signature_b64 = pdf_reader.metadata.get('/Signature', '')
            if not signature_b64:
                return False

            signature = base64.b64decode(signature_b64)

            # Reconstruct original content (without signature metadata)
            writer = PdfWriter()
            for page in pdf_reader.pages:
                writer.add_page(page)

            content_buffer = io.BytesIO()
            writer.write(content_buffer)
            content_to_verify = content_buffer.getvalue()

            # Verify signature
            pdf_hash = SHA256.new(content_to_verify)
            rsa_key = RSA.import_key(public_key_data)
            verifier = pkcs1_15.new(rsa_key)
            verifier.verify(pdf_hash, signature)

            return True

        except (ValueError, TypeError) as e:
            print(f"Verification failed: {str(e)}")
            return False
        except Exception as e:
            print(f"Verification error: {str(e)}")
            return False

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PDF Signer")
        self.setGeometry(100, 100, 400, 300)

        self.tabs = QTabWidget()
        self.main_tab = MainTab()
        self.second_tab = SecondTab()

        self.tabs.addTab(self.main_tab, "Sign")
        self.tabs.addTab(self.second_tab, "Verify")

        self.setCentralWidget(self.tabs)


def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
