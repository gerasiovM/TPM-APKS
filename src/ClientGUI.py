import sys
from ClientBL import ClientBL
from PyQt6.QtGui import QRegularExpressionValidator
from PyQt6.QtWidgets import QApplication, QMainWindow, QWidget
from PyQt6.QtCore import QRegularExpression, QTimer
from PyQt6.uic import loadUi

from src.Protocol import Protocol


class ClientGUI(QMainWindow, ClientBL):
    def __init__(self):
        super(ClientGUI, self).__init__()
        loadUi('client.ui', self)
        self.pushButton_connect.clicked.connect(self.connect_pressed)
        self.pushButton_send_key.clicked.connect(self.send_key_pressed)
        self.pushButton_login.clicked.connect(self.login_pressed)
        self.lineEdit_port.setValidator(QRegularExpressionValidator(QRegularExpression(r"^(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[0-9]{1,4})$")))
        self.plainTextEdit_incoming.setReadOnly(True)
        self.timer = QTimer(self)
        self.timer.setInterval(100)
        # self.timer.timeout.connect(self.update_incoming)
        # self.timer.start()

    # def update_incoming(self):
    #     data = self.receive()
    #     # print("a")
    #     while data:
    #         self.plainTextEdit_incoming.appendPlainText(data.decode(Protocol.FORMAT))
    #         data = self.receive()

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
        if self.connect():
            if self.key_exchange():
                self.pushButton_login.setEnabled(True)
                self.pushButton_connect.setEnabled(False)
                self.lineEdit_host.setReadOnly(True)
                self.lineEdit_port.setReadOnly(True)
                self._socket.settimeout(0.01)

    def login_pressed(self):
        self.login_wnd = LoginGUI([self.login, self.receive, self._logged_in])
        self.login_wnd.show()


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


class LoginGUI(QWidget):
    def __init__(self, callbacks):
        super(LoginGUI, self).__init__()
        loadUi('login.ui', self)

        self.login = callbacks[0]
        self.receive = callbacks[1]
        self.logged_in = True

        self.pushButton_login_user.clicked.connect(self.login_user_pressed)
        self.pushButton_login_admin.clicked.connect(self.login_admin_pressed)

    def login_user_pressed(self):
        login = self.lineEdit_login.text()
        password = self.lineEdit_password.text()
        if not login:
            self.label_login_info.setText("Login field must be filled")
            return
        self.label_login_info.setText("")
        if not password:
            self.label_password_info.setText("Password field must be filled")
            return
        self.label_password_info.setText("")
        self.login(login, password)
        login_response = self.receive().decode(Protocol.FORMAT)
        print(login_response)
        it = 0
        while login_response == b"".decode(Protocol.FORMAT) and it != 100:
            login_response = self.receive().decode(Protocol.FORMAT)
            it += 1
        if login_response == "Success":
            self.logged_in = True
            self.close()
        elif login_response == "":
            self.label_password_info.setText("Couldn't get response from server")
        else:
            self.label_password_info.setText(login_response)

    def login_admin_pressed(self):
        pass


def main():
    app = QApplication(sys.argv)
    window = ClientGUI()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()