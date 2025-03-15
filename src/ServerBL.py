from tpm2_pytss import TPM2B_PUBLIC, TPMT_SIGNATURE
from Protocol import LOG_FILE, Protocol
import logging
import sqlite3
import socket
import threading
import os
import base64
import cryptography.exceptions
from cryptography.hazmat.primitives import serialization, hmac, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.fernet import Fernet
from argon2 import PasswordHasher
from tpm2_pytss.utils import make_credential

from src.CertificateManager import CertificateManager


class ServerBL:

    def __init__(self, host, port):

        # Open the log file in write mode, which truncates the file to zero length
        with open(LOG_FILE, 'w'):
            pass  # This block is empty intentionally
        self._con = sqlite3.connect("users.db", check_same_thread=False)
        self._con_lock = threading.Lock()
        cursor = self._con.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
        	`id` integer primary key NOT NULL UNIQUE,
        	`login` TEXT NOT NULL UNIQUE,
        	`hash` BLOB NOT NULL,
        	`salt` BLOB NOT NULL,
        	`public_key` BLOB
        );''')
        cursor.close()
        self._host = host
        self._port = port
        self._server_socket = None
        self._is_srv_running = True
        self._client_handlers: list[ClientHandler] = []

    def check_client_handlers(self):
        return self._client_handlers

    def check_user_exists(self, login) -> bool:
        cursor = self._con.cursor()
        exists = cursor.execute('''SELECT 1 FROM users WHERE login = ? LIMIT 1''',
                                (login,)).fetchone()
        cursor.close()
        return bool(exists)

    def check_user_correct_password(self, login, password_hash):
        cursor = self._con.cursor()
        required_hash = cursor.execute('''SELECT hash FROM users WHERE login = ? LIMIT 1''',
                                       (login,)).fetchone()[0]
        print(password_hash)
        print(required_hash)
        cursor.close()
        if password_hash == required_hash:
            return True
        return False

    def check_user_has_key(self, login):
        cursor = self._con.cursor()
        result = cursor.execute('''SELECT public_key FROM users WHERE login = ?''', (login,)).fetchone()[0]
        cursor.close()
        return bool(result)


    def get_user_salt(self, login):
        cursor = self._con.cursor()
        salt = cursor.execute('''SELECT salt FROM users WHERE login = ? LIMIT 1''',
                              (login,)).fetchone()[0]
        cursor.close()
        return salt

    def get_user_key(self, login):
        cursor = self._con.cursor()
        key = cursor.execute('''SELECT public_key FROM users WHERE login = ?''', (login,)).fetchone()[0]
        cursor.close()
        return key

    def save_user_key(self, login, public_key):
        with self._con_lock:
            print(login)
            cursor = self._con.cursor()
            cursor.execute('''UPDATE users SET public_key = ? WHERE login = ?''', (public_key, login))
            self._con.commit()
            cursor.close()

    def stop_server(self):
        try:
            self._is_srv_running = False
            # Close server socket
            if len(self._client_handlers) > 0:
                for client_thread in self._client_handlers:
                    client_thread.stop()

            if self._server_socket is not None:
                self._server_socket.close()
                self._server_socket = None

        except Exception as e:
            logging.error("[SERVER_BL] Exception in Stop_Server fn : {}".format(e))

    def start_server(self):
        try:
            self._is_srv_running = True
            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_socket.bind((self._host, self._port))
            self._server_socket.listen(5)
            logging.debug(f"[SERVER_BL] listening...")

            while self._is_srv_running and self._server_socket is not None:

                # Accept socket request for connection
                client_socket, address = self._server_socket.accept()
                logging.debug(f"[SERVER_BL] Client connected {client_socket}{address} ")

                # Start Thread
                cl_handler = ClientHandler(client_socket, address, self._client_handlers,
                                           [
                                               self.check_user_exists,
                                               self.check_user_correct_password,
                                               self.check_user_has_key,
                                               self.get_user_salt,
                                               self.get_user_key,
                                               self.save_user_key])
                cl_handler.start()
                self._client_handlers.append(cl_handler)
                logging.debug(f"[SERVER_BL] ACTIVE CONNECTION {threading.active_count() - 1}")

        # ??? something happens here
        # except Exception as e:
        #    write_to_log("[SERVER_BL] Exception in start_server fn : {}".format(e))
        finally:
            logging.debug(f"[SERVER_BL] Server thread is DONE")


class ClientHandler(threading.Thread):
    def __init__(self, client_socket, address: tuple[str, int], client_handlers, callbacks):
        super().__init__()

        self._client_socket: socket.socket = client_socket
        self._client_handlers = client_handlers
        self._address = address

        self._check_user_exists = callbacks[0]
        self._check_user_correct_password = callbacks[1]
        self._check_user_has_key = callbacks[2]
        self._get_user_salt = callbacks[3]
        self._get_user_key = callbacks[4]
        self._save_user_key = callbacks[5]

        self._p = Protocol()
        self._mode = "KEY"
        self._hmac_manager = None
        self._login = None
        self._fernet = None
        self._cred_fernet = None
        self._admin_check_fernet = None
        self._ak_pub = None
        self._connected = False

    def run(self):
        # This code run in separate thread for every client
        self._connected = True
        while self._connected:
            # 1. Get message from socket and check it
            valid_data, data_type, data_hmac, data = self._p.receive(self._client_socket)
            response = ""
            response_data_type = "MSG"
            if valid_data:
                # Logging
                if len(data) > 1024:
                    logging.debug(f"[SERVER_BL] Received from {self._address} LARGE data of type {data_type}")
                else:
                    logging.debug(f"[SERVER_BL] Received from {self._address} data - {data}")
                if self._mode == "KEY":
                    response, response_data_type = self.process_key_exchange(data, data_type)
                else:
                    response, response_data_type = self.process_authenticated_data(data, data_type, data_hmac)
            # else:
                # logging.warning("[SERVER_BL] Received invalid data")
                # response = "Data is invalid"

            sent = self.send_response(response, response_data_type)
            if not sent:
                self.stop()


        self._client_socket.close()
        logging.info(f"[SERVER_BL] Thread closed for : {self._address} ")
        self._client_handlers.remove(self)

    def process_key_exchange(self, data, data_type):
        response, response_data_type = "", "MSG"
        if data_type == "KEY":
            try:
                print(data)
                pub_key = serialization.load_pem_public_key(data)
                secret = os.urandom(128)
                fernet_key = Fernet.generate_key()
                self._hmac_manager = hmac.HMAC(key=secret, algorithm=self._p.HASH_ALG)
                self._fernet = Fernet(fernet_key)
                print("FERNEEEEEEET")
                response = pub_key.encrypt(plaintext=(secret + fernet_key), padding=self._p.PADDING)
                print(response)
                response_data_type = "KEY"
            except Exception as e:
                logging.error("[SERVER_BL] Exception on loading public key : {}".format(e))
                response = "Public key could not be loaded, make sure that it's in a correct format (PEM)"
        else:
            logging.warning("[SERVER_BL] Received data type is not KEY, discarding")
            response = "Wrong data type, please provide a public key"
        return response, response_data_type

    def process_authenticated_data(self, data, data_type, data_hmac):
        response, response_data_type = "", "MSG"
        try:
            # HMAC verification
            print(data_type, data_hmac, data)
            hmac_manager_local = self._hmac_manager.copy()
            hmac_manager_local.update(data)
            hmac_manager_local.verify(data_hmac)

            # Decrypting
            data = self._fernet.decrypt(data)
            print(data)
            response = f"Data received! - {data}"
            if data_type == "LGN":
                response = self.handle_login_user(data)
            if data_type == "LGNA" or data_type == "LGNB":
                response = self.handle_login_admin(data, data_type)
            if data_type == "AUTH":
                response, response_data_type = self.handle_enrollment(data)
            if data_type == "KEY2":
                response = self.handle_key_submission(data)
        except cryptography.exceptions.InvalidSignature:
            logging.warning("[SERVER_BL] Received invalid HMAC, discarding data")
            response = "Wrong HMAC, make sure you are using the correct hashing algorithm"
        except cryptography.fernet.InvalidToken:
            logging.warning("[SERVER_BL] Received data could not be decrypted, discarding")
            response = "Data could not be decrypted, make sure you are using the correct key"
        return response, response_data_type

    def handle_login_user(self, data):
        if self._mode != "NOT_LOGGED_IN":
            response = "Already logged in"
        else:
            login = data[:20].lstrip(b'\x00').decode(Protocol.FORMAT)
            print("LOGIN:", login)
            if not self._check_user_exists(login):
                response = "User doesn't exist"
            else:
                password = data[20:]
                salt = self._get_user_salt(login)
                ph = PasswordHasher()
                password_hash = ph.hash(password, salt=salt).split("$")[-1]
                if self._check_user_correct_password(login, password_hash):
                    self._mode = "LOGGED_IN_USER"
                    self._login = login
                    response = "Success"
                    print("AAAAAAAAAAAAAA")
                else:
                    response = "Login and password don't match"
        return response

    def handle_login_admin(self, data, data_type):
        response, response_data_type = "Something went wrong", "MSG"
        if self._mode != "NOT_LOGGED_IN":
            response = "Already logged in"
        else:
            if data_type == "LGNA":
                pem_key = self._get_user_key()
                key = serialization.load_pem_public_key(pem_key)
                new_fernet_key = Fernet.generate_key()
                self._admin_check_fernet = Fernet(new_fernet_key)
                encrypted_secret = key.encrypt(new_fernet_key, padding=Protocol.PADDING)
                response = encrypted_secret
                response_data_type = "LGNA"
            elif data_type == "LGNB":
                if self._admin_check_fernet:
                    try:
                        confirmation = self._admin_check_fernet.decrypt(data)
                        self._fernet, self._admin_check_fernet = self._admin_check_fernet, None
                        self._mode = "LOGGED_IN_ADMIN"
                        response = "Success"
                    except cryptography.fernet.InvalidToken:
                        response = "Failure"
                        logging.warning("[SERVER_BL] Could not decrypt admin login confirmation message")
                else:
                    response = "Wrong LGN order"
        return response, response_data_type

    def handle_enrollment(self, data):
        response_data_type = "MSG"
        if self._mode == "LOGGED_IN_USER":
            ek_pub_bytes, ak_pub_bytes, ek_cert = data.split(self._p.DELIMITER)
            ek_pub = TPM2B_PUBLIC.unmarshal(ek_pub_bytes)[0]
            self._ak_pub = TPM2B_PUBLIC.unmarshal(ak_pub_bytes)[0]
            cm = CertificateManager(ek_cert)
            if not cm.check_key(ek_pub.to_der()) or not cm.check_certificate():
                response = "Invalid certificate"
            else:
                cred_secret = os.urandom(32)
                print("Cred secret: " + str(cred_secret))
                self._cred_fernet = Fernet(base64.urlsafe_b64encode(cred_secret))
                cred_blob, cred_enc_secret = make_credential(ek_pub, cred_secret, self._ak_pub.get_name())
                print(cred_blob.marshal())
                print(cred_enc_secret.marshal())
                response = cred_blob.marshal() + Protocol.DELIMITER + cred_enc_secret.marshal()
                response_data_type = "CRED"
        else:
            response = "User not logged in, can't accept authentication request"
        return response, response_data_type

    def handle_key_submission(self, data):
        if self._mode == "LOGGED_IN_USER" and not self._check_user_has_key(self._login):
            if self._ak_pub is not None:
                key_pub_bytes, signature_bytes = data.split(self._p.DELIMITER)
                key_pub_bytes_decrypted = self._cred_fernet.decrypt(key_pub_bytes)
                signature = TPMT_SIGNATURE.unmarshal(signature_bytes)[0]
                signature.verify_signature(self._ak_pub, key_pub_bytes_decrypted)
                key_pub = TPM2B_PUBLIC.unmarshal(key_pub_bytes_decrypted)[0]
                print("SAVING USER KEY")
                self._save_user_key(self._login, key_pub.to_pem())
                response = "Success"
            else:
                response = "No associated ak with the connection"
        else:
            response = "User not logged in, can't accept key"
        return response

    def send_response(self, response, response_data_type):
        if self._mode == "KEY":
            if type(response) is str:
                sent = self._p.send_str(self._client_socket, response_data_type, b"", response)
            else:
                sent = self._p.send_bytes(self._client_socket, response_data_type, b"", response)
            self._mode = "NOT_LOGGED_IN"
        else:
            if type(response) is str:
                response = response.encode(Protocol.FORMAT)
            response = self._fernet.encrypt(response)
            hmac_manager_local = self._hmac_manager.copy()
            hmac_manager_local.update(response)
            response_hmac = hmac_manager_local.finalize()
            sent = self._p.send_bytes(self._client_socket, response_data_type, response_hmac, response)
            logging.info(f"[SERVER_BL] Sent message to client - ///////{response}")
        return sent

    def stop(self):
        self._connected = False


    def get_address(self) -> tuple[str, str]:
        return self._address[0], str(self._address[1])


def main():
    server = ServerBL("127.0.0.1", 8081)
    server.start_server()


if __name__ == "__main__":
    main()
