import sys
from ClientBL import ClientBL
from PyQt6.QtGui import QRegularExpressionValidator
from PyQt6.QtWidgets import QApplication, QMainWindow
from PyQt6.QtCore import QRegularExpression, QTimer
from PyQt6.uic import loadUi

from src.Protocol import Protocol


class MainWindow(QMainWindow, ClientBL):
    def __init__(self):
        super(MainWindow, self).__init__()
        loadUi('client.ui', self)
        self.pushButton_connect.clicked.connect(self.connect_pressed)
        self.pushButton_send_key.clicked.connect(self.send_key_pressed)
        self.lineEdit_port.setValidator(QRegularExpressionValidator(QRegularExpression(r"^(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[0-9]{1,4})$")))
        self.timer = QTimer(self)
        self.timer.setInterval(100)
        self.timer.timeout.connect(self.update_incoming)
        self.timer.start()

    def update_incoming(self):
        data = self.receive()
        # print("a")
        while data:
            self.plainTextEdit_incoming.appendPlainText(data.decode(Protocol.FORMAT))
            data = self.receive()

    def connect_pressed(self):
        host = self.lineEdit_host.text()
        port = self.lineEdit_port.text()
        if not host or not self.validate_host(host):
            self.label_error.setText("Host could not be interpreted")
            return
        if not port:
            self.label_error.setText("Port could not be interpreted")
            return
        self._host = host
        self._port = int(port)
        self.connect()
        self.key_exchange()
        self.plainTextEdit_incoming.appendPlainText("Aboba")
        self._socket.settimeout(0.01)

    def send_key_pressed(self):
        self.send("Hello, World!", "MSG")

    @staticmethod
    def validate_host(host: str) -> bool:
        def is_valid_ip(ip_str):
            from ipaddress import ip_address
            try:
                ip_address(ip_str)
                return True
            except ValueError:
                return False

        def resolve_domain(domain):
            from socket import gethostbyname, gaierror
            try:
                return gethostbyname(domain)
            except gaierror:
                return None

        if is_valid_ip(host) or resolve_domain(host):
            return True
        return False


def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()