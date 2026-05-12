"""Main window for RSA-OAEP-256 encryption/decryption GUI."""
from __future__ import annotations
import sys
from pathlib import Path

from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QIcon, QPalette, QColor
from PyQt5.QtWidgets import (
    QApplication,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QRadioButton,
    QSizePolicy,
    QStatusBar,
    QVBoxLayout,
    QWidget,
    QButtonGroup,
    QFrame,
    QSplitter,
    QGroupBox,
)

# Worker thread
class _CryptoWorker(QThread):
    """Run keygen / encrypt / decrypt off the main thread."""
    progress = pyqtSignal(int)          # 0-100
    status   = pyqtSignal(str)
    finished = pyqtSignal(bool, str)    # success, message

    def __init__(self, task: str, **kwargs):
        super().__init__()
        self.task   = task
        self.kwargs = kwargs

    def run(self):
        try:
            if self.task == "keygen":
                self._keygen()
            elif self.task == "encrypt":
                self._encrypt()
            elif self.task == "decrypt":
                self._decrypt()
        except Exception as exc:
            self.finished.emit(False, str(exc))

    def _keygen(self):
        from src.rsa_oaep.rsa import generate_keypair
        from src.rsa_oaep.key_io import save_public_key, save_private_key

        self.status.emit("Generating 2048-bit RSA keypair…")
        self.progress.emit(10)
        pub, priv = generate_keypair(bits=2048)
        self.progress.emit(80)

        pub_path  = self.kwargs["pub_path"]
        priv_path = self.kwargs["priv_path"]
        save_public_key(pub, pub_path)
        save_private_key(priv, priv_path)
        self.progress.emit(100)
        self.finished.emit(True, f"Keys saved:\n  {pub_path}\n  {priv_path}")

    def _encrypt(self):
        from src.rsa_oaep.key_io import load_public_key
        from src.rsa_oaep.rsaes_oaep import encrypt

        key_path    = self.kwargs["key_path"]
        input_path  = self.kwargs["input_path"]
        output_path = self.kwargs["output_path"]

        self.status.emit("Loading public key…")
        self.progress.emit(10)
        pub = load_public_key(key_path)

        self.status.emit("Reading input file…")
        self.progress.emit(20)
        plaintext = Path(input_path).read_bytes()

        self.status.emit("Encrypting…")
        self.progress.emit(40)
        ciphertext = encrypt(plaintext, pub)

        self.status.emit("Writing output file…")
        self.progress.emit(90)
        Path(output_path).write_bytes(ciphertext)

        self.progress.emit(100)
        size_kb = len(ciphertext) / 1024
        self.finished.emit(True, f"Encrypted successfully.\nOutput: {output_path}\nSize: {size_kb:.1f} KB")

    def _decrypt(self):
        from src.rsa_oaep.key_io import load_private_key
        from src.rsa_oaep.rsaes_oaep import decrypt

        key_path    = self.kwargs["key_path"]
        input_path  = self.kwargs["input_path"]
        output_path = self.kwargs["output_path"]

        self.status.emit("Loading private key…")
        self.progress.emit(10)
        priv = load_private_key(key_path)

        self.status.emit("Reading ciphertext…")
        self.progress.emit(20)
        ciphertext = Path(input_path).read_bytes()

        self.status.emit("Decrypting…")
        self.progress.emit(40)
        plaintext = decrypt(ciphertext, priv)

        self.status.emit("Writing output file…")
        self.progress.emit(90)
        Path(output_path).write_bytes(plaintext)

        self.progress.emit(100)
        size_kb = len(plaintext) / 1024
        self.finished.emit(True, f"Decrypted successfully.\nOutput: {output_path}\nSize: {size_kb:.1f} KB")


# Helper widgets
class _FilePicker(QWidget):
    """A label + line-edit + Browse button row."""

    def __init__(self, label: str, placeholder: str = "", save: bool = False,
                 filter: str = "All Files (*)", parent=None):
        super().__init__(parent)
        self._save   = save
        self._filter = filter

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        lbl = QLabel(label)
        lbl.setFixedWidth(110)
        lbl.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        layout.addWidget(lbl)

        from PyQt5.QtWidgets import QLineEdit
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText(placeholder)
        self.path_edit.setReadOnly(True)
        layout.addWidget(self.path_edit)

        btn = QPushButton("Browse…")
        btn.setFixedWidth(90)
        btn.clicked.connect(self._browse)
        layout.addWidget(btn)

    def _browse(self):
        if self._save:
            path, _ = QFileDialog.getSaveFileName(self, "Save File", "", self._filter)
        else:
            path, _ = QFileDialog.getOpenFileName(self, "Open File", "", self._filter)
        if path:
            self.path_edit.setText(path)

    def path(self) -> str:
        return self.path_edit.text()

    def set_path(self, p: str):
        self.path_edit.setText(p)


# Main window
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("RSA-OAEP-256  ·  Crypto Tool")
        self.setMinimumSize(800, 680)
        self._worker: QThread | None = None
        self._build_ui()
        self._apply_theme()

    # UI construction
    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(24, 20, 24, 16)
        root.setSpacing(16)

        # Title
        title = QLabel("RSA-OAEP-256")
        title.setObjectName("appTitle")
        title.setAlignment(Qt.AlignCenter)
        root.addWidget(title)

        subtitle = QLabel("2048-bit RSA · SHA-256 · Implemented from scratch")
        subtitle.setObjectName("subtitle")
        subtitle.setAlignment(Qt.AlignCenter)
        root.addWidget(subtitle)

        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setObjectName("divider")
        root.addWidget(sep)

        # Mode selector
        mode_grp = QGroupBox("Mode")
        mode_layout = QHBoxLayout(mode_grp)
        self.rb_encrypt = QRadioButton("🔒  Encrypt")
        self.rb_decrypt = QRadioButton("🔓  Decrypt")
        self.rb_encrypt.setChecked(True)
        bg = QButtonGroup(self)
        bg.addButton(self.rb_encrypt)
        bg.addButton(self.rb_decrypt)
        mode_layout.addWidget(self.rb_encrypt)
        mode_layout.addWidget(self.rb_decrypt)
        mode_layout.addStretch()
        self.rb_encrypt.toggled.connect(self._on_mode_changed)
        root.addWidget(mode_grp)

        # Key generation
        keygen_grp = QGroupBox("Key Pair Generation")
        keygen_layout = QVBoxLayout(keygen_grp)
        keygen_layout.setSpacing(8)

        btn_row = QHBoxLayout()
        self.btn_keygen = QPushButton("⚙  Generate Key Pair")
        self.btn_keygen.setObjectName("primaryBtn")
        self.btn_keygen.setFixedHeight(36)
        self.btn_keygen.clicked.connect(self._on_keygen)
        btn_row.addWidget(self.btn_keygen)
        btn_row.addStretch()
        keygen_layout.addLayout(btn_row)

        self.key_preview = QPlainTextEdit()
        self.key_preview.setReadOnly(True)
        self.key_preview.setPlaceholderText(
            "Public key (hex) will appear here after generation…"
        )
        self.key_preview.setFixedHeight(72)
        self.key_preview.setObjectName("hexPreview")
        keygen_layout.addWidget(self.key_preview)

        root.addWidget(keygen_grp)

        # File selectors
        files_grp = QGroupBox("Files")
        files_layout = QVBoxLayout(files_grp)
        files_layout.setSpacing(10)

        self.picker_input  = _FilePicker("Input file:", "Select plaintext / ciphertext…",
                                         save=False, filter="All Files (*)")
        self.picker_key    = _FilePicker("Key file:", "Select public.key / private.key…",
                                         save=False, filter="Key Files (*.key);;All Files (*)")
        self.picker_output = _FilePicker("Output file:", "Choose save location…",
                                          save=True, filter="All Files (*)")

        files_layout.addWidget(self.picker_input)
        files_layout.addWidget(self.picker_key)
        files_layout.addWidget(self.picker_output)
        root.addWidget(files_grp)

        # Run button
        self.btn_run = QPushButton("▶  Run")
        self.btn_run.setObjectName("runBtn")
        self.btn_run.setFixedHeight(44)
        self.btn_run.clicked.connect(self._on_run)
        root.addWidget(self.btn_run)

        # Progress & status
        self.progress = QProgressBar()
        self.progress.setValue(0)
        self.progress.setTextVisible(True)
        root.addWidget(self.progress)

        self.status_bar = self.statusBar()
        self.status_bar.showMessage("Ready.")

        self._on_mode_changed()

    # Theme
    def _apply_theme(self):
        self.setStyleSheet("""
            QMainWindow, QWidget {
                background-color: #0f1117;
                color: #e2e8f0;
                font-family: 'JetBrains Mono', 'Consolas', 'Courier New', monospace;
                font-size: 13px;
            }

            #appTitle {
                font-size: 28px;
                font-weight: 700;
                letter-spacing: 4px;
                color: #f8fafc;
                padding: 8px 0 2px 0;
            }

            #subtitle {
                font-size: 11px;
                color: #64748b;
                letter-spacing: 1px;
                padding-bottom: 4px;
            }

            #divider {
                background-color: #1e293b;
                max-height: 1px;
                border: none;
            }

            QGroupBox {
                border: 1px solid #1e293b;
                border-radius: 8px;
                margin-top: 10px;
                padding: 12px 12px 12px 12px;
                background-color: #0d1117;
                font-size: 11px;
                color: #475569;
                letter-spacing: 1px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 8px;
                left: 12px;
                top: -1px;
                color: #64748b;
                text-transform: uppercase;
            }

            QRadioButton {
                spacing: 8px;
                font-size: 13px;
                color: #cbd5e1;
                padding: 4px 16px 4px 0;
            }
            QRadioButton::indicator {
                width: 16px;
                height: 16px;
                border-radius: 8px;
                border: 2px solid #334155;
                background: #0f1117;
            }
            QRadioButton::indicator:checked {
                background: #3b82f6;
                border: 2px solid #3b82f6;
            }

            QLineEdit {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 6px;
                padding: 6px 10px;
                color: #e2e8f0;
                selection-background-color: #3b82f6;
            }
            QLineEdit:focus {
                border-color: #3b82f6;
            }

            QPlainTextEdit#hexPreview {
                background-color: #0a0e1a;
                border: 1px solid #1e293b;
                border-radius: 6px;
                padding: 6px 10px;
                color: #38bdf8;
                font-size: 11px;
                font-family: 'JetBrains Mono', 'Consolas', monospace;
            }

            QPushButton {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 6px;
                padding: 6px 16px;
                color: #e2e8f0;
            }
            QPushButton:hover {
                background-color: #273548;
                border-color: #3b82f6;
            }
            QPushButton:pressed {
                background-color: #1a2740;
            }
            QPushButton:disabled {
                color: #334155;
                border-color: #1e293b;
            }

            QPushButton#primaryBtn {
                background-color: #1e3a5f;
                border-color: #2563eb;
                color: #93c5fd;
            }
            QPushButton#primaryBtn:hover {
                background-color: #1d4ed8;
                color: #fff;
            }

            QPushButton#runBtn {
                background-color: #14532d;
                border: 1px solid #16a34a;
                border-radius: 8px;
                color: #86efac;
                font-size: 15px;
                font-weight: 600;
                letter-spacing: 2px;
            }
            QPushButton#runBtn:hover {
                background-color: #15803d;
                color: #fff;
            }
            QPushButton#runBtn:disabled {
                background-color: #0f2a1a;
                border-color: #166534;
                color: #166534;
            }

            QProgressBar {
                border: 1px solid #1e293b;
                border-radius: 6px;
                background-color: #0d1117;
                height: 20px;
                text-align: center;
                color: #94a3b8;
                font-size: 11px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1d4ed8, stop:1 #3b82f6);
                border-radius: 5px;
            }

            QStatusBar {
                background-color: #0d1117;
                color: #475569;
                font-size: 11px;
                border-top: 1px solid #1e293b;
            }

            QLabel {
                color: #94a3b8;
            }
        """)

    # Slots
    def _on_mode_changed(self):
        encrypting = self.rb_encrypt.isChecked()
        self.picker_input.set_path("")
        self.picker_key.set_path("")
        self.picker_output.set_path("")
        self.progress.setValue(0)
        self.status_bar.showMessage("Ready.")
        self.picker_key.path_edit.setPlaceholderText(
            "Select public.key…" if encrypting else "Select private.key…"
        )
        self.btn_run.setText("▶  Encrypt" if encrypting else "▶  Decrypt")

    def _on_keygen(self):
        pub_path, _ = QFileDialog.getSaveFileName(
            self, "Save Public Key", "public.key", "Key Files (*.key);;All Files (*)"
        )
        if not pub_path:
            return
        priv_path, _ = QFileDialog.getSaveFileName(
            self, "Save Private Key", "private.key", "Key Files (*.key);;All Files (*)"
        )
        if not priv_path:
            return

        self._start_worker("keygen", pub_path=pub_path, priv_path=priv_path,
                           on_success=lambda _: self._preview_key(pub_path))

    def _preview_key(self, pub_path: str):
        try:
            text = Path(pub_path).read_text(encoding="utf-8")
            lines = text.strip().splitlines()
            preview = lines[0][:120] + "…" if lines and len(lines[0]) > 120 else (lines[0] if lines else "")
            self.key_preview.setPlainText(f"n = {preview}")
        except Exception:
            pass

    def _on_run(self):
        input_path  = self.picker_input.path()
        key_path    = self.picker_key.path()
        output_path = self.picker_output.path()

        if not input_path:
            QMessageBox.warning(self, "Missing input", "Please select an input file.")
            return
        if not key_path:
            QMessageBox.warning(self, "Missing key", "Please select a key file.")
            return
        if not output_path:
            QMessageBox.warning(self, "Missing output", "Please specify an output file.")
            return

        task = "encrypt" if self.rb_encrypt.isChecked() else "decrypt"
        self._start_worker(task, key_path=key_path,
                           input_path=input_path, output_path=output_path)

    # Worker management
    def _start_worker(self, task: str, on_success=None, **kwargs):
        self._set_busy(True)
        self.progress.setValue(0)
        self._on_success_cb = on_success

        self._worker = _CryptoWorker(task, **kwargs)
        self._worker.progress.connect(self.progress.setValue)
        self._worker.status.connect(self.status_bar.showMessage)
        self._worker.finished.connect(self._on_worker_finished)
        self._worker.start()

    def _on_worker_finished(self, success: bool, message: str):
        self._set_busy(False)
        if success:
            self.status_bar.showMessage("Done.")
            if self._on_success_cb:
                self._on_success_cb(message)
            QMessageBox.information(self, "Success", message)
        else:
            self.status_bar.showMessage("Error.")
            QMessageBox.critical(self, "Error", message)

    def _set_busy(self, busy: bool):
        self.btn_run.setEnabled(not busy)
        self.btn_keygen.setEnabled(not busy)
        self.rb_encrypt.setEnabled(not busy)
        self.rb_decrypt.setEnabled(not busy)


# Entry point
def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()