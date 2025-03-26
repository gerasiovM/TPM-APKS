import sys
from ClientBL import ClientBL
from PyQt6.QtGui import QRegularExpressionValidator
from PyQt6.QtWidgets import QApplication, QMainWindow, QWidget, QTableView, QDialog
from PyQt6.QtCore import QRegularExpression, QTimer, pyqtSignal, QObject
from PyQt6.QtSql import QSqlDatabase, QSqlTableModel
from PyQt6.uic import loadUi

from src.Protocol import Protocol


class ClientGUI(QMainWindow, ClientBL):
    def __init__(self):
        super(ClientGUI, self).__init__()
        loadUi('../resources/ui/client.ui', self)
        self.pushButton_connect.clicked.connect(self.connect_pressed)
        self.pushButton_send_key.clicked.connect(self.send_key_pressed)
        self.pushButton_send_key.setEnabled(False)
        self.pushButton_login.clicked.connect(self.login_pressed)
        self.lineEdit_port.setValidator(QRegularExpressionValidator(QRegularExpression(r"^(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[0-9]{1,4})$")))
        self.plainTextEdit_incoming.setReadOnly(True)
        self.timer = QTimer(self)
        self.timer.setInterval(100)

        self.admin_wnd: AdminGUI = None
        self.login_wnd: LoginGUI = None
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
            if self.establish_secure_connection():
                self.pushButton_login.setEnabled(True)
                self.pushButton_send_key.setEnabled(True)
                self.pushButton_connect.setEnabled(False)
                self.lineEdit_host.setReadOnly(True)
                self.lineEdit_port.setReadOnly(True)
                self._socket.settimeout(0.01)

    def login_pressed(self):
        self.login_wnd = LoginGUI([self.login, self.login_admin, self.receive])
        self.login_wnd.login_signal.connect(self.update_login_status)
        self.login_wnd.show()

    def update_login_status(self, login_type):
        self._logged_in = login_type
        if self._logged_in == "Admin":
            self.admin_wnd = AdminGUI([self.retrieve_database, self.add_user])
            self.admin_wnd.show()

    def closeEvent(self, event):
        if self.login_wnd is not None:
            self.login_wnd.close()

        if self.admin_wnd is not None:
            self.admin_wnd.close()

        event.accept()

    def send_key_pressed(self):
        if not self._logged_in == "User":
            self.label_error.setText("You need to be logged in as user to send the key")
        else:
            self.label_error.setText("")
            self.authenticate()

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
    login_signal = pyqtSignal(str)

    def __init__(self, callbacks):
        super(LoginGUI, self).__init__()
        loadUi('../resources/ui/login.ui', self)

        self.login = callbacks[0]
        self.login_admin = callbacks[1]
        self.receive = callbacks[2]
        self.logged_in = None

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
        success, response = self.login(login, password)
        if success:
            self.logged_in = "User"
            self.login_signal.emit(self.logged_in)
            self.close()
        else:
            self.label_login_info.setText(response)

    def login_admin_pressed(self):
        login = self.lineEdit_login.text()
        if not login:
            self.label_login_info.setText("Login field must be filled")
            return
        self.label_login_info.setText("")
        success, response = self.login_admin(login)
        if success:
            self.logged_in = "Admin"
            self.login_signal.emit(self.logged_in)
            self.close()
        else:
            self.label_login_info.setText(response)


class AdminGUI(QWidget):
    def __init__(self, callbacks):
        super(AdminGUI, self).__init__()
        loadUi('../resources/ui/admin.ui', self)
        self.tableView: QTableView = self.tableView
        self.retrieve_database = callbacks[0]
        self.add_user = callbacks[1]
        self.retrieve_database()
        self.setup_database()
        self.setup_model()

        self.pushButton_update_db.clicked.connect(self.reload_database)
        self.pushButton_add_user.clicked.connect(self.add_user)

    def update_db_clicked(self):
        self.retrieve_database()
        self.model.select()

    def add_user_clicked(self):
        dialog = AddUserDialog()
        if dialog.exec() == QDialog.DialogCode.Accepted:
            login, password = dialog.get_user_info()
            self.add_user(login, password)

    def setup_database(self):
        self.db = QSqlDatabase.addDatabase('QSQLITE')
        self.db.setDatabaseName("../resources/db/users.db")
        if not self.db.open():
            print("Failed to connect to the database")
            sys.exit(1)

    def setup_model(self):
        self.model = QSqlTableModel()
        self.model.setTable("users")
        self.model.select()

        self.tableView.setModel(self.model)
        self.tableView.resizeColumnsToContents()

class AddUserDialog(QDialog):
    def __init__(self):
        super().__init__()
        loadUi("adduser.ui", self)

        # Connect buttons to their functions
        self.pushButton_ok.clicked.connect(self.accept)
        self.pushButton_cancel.clicked.connect(self.reject)

    def get_user_info(self):
        login = self.lineEdit_login.text()
        password = self.lineEdit_password.text()
        return login, password

def main():
    app = QApplication(sys.argv)
    window = ClientGUI()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()