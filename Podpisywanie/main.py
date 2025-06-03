import sys
from PyQt6.QtWidgets import QApplication, QMainWindow, QWidget, QPushButton, QFileDialog, QLabel, QVBoxLayout, QTabWidget
import win32api
import win32file


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
        #TO DO
        return


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
        self.open_pdf_button = QPushButton("Wybierz PDF")
        self.open_key_button = QPushButton("Wybierz klucz")
        self.verify_button = QPushButton("Zweryfikuj podpis")
        self.open_pdf_button.clicked.connect(self.open_pdf_dialog)
        self.open_pdf_button.clicked.connect(self.open_key_dialog)
        self.verify_button.clicked.connect(self.verify_signature)
        layout.addWidget(self.result_label)
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
                self.result_label.setText("Wybrano poprawny plik klucza.")
            else:
                self.result_label.setText("Wybrany plik nie jest plikiem klucza.")

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
        #TO DO
        return


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
