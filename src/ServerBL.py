from Protocol import LOG_FILE, Protocol
import logging
import sqlite3
import socket
import threading
import os
import cryptography.exceptions
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives import hmac
from cryptography.fernet import Fernet


class ServerBL:

    def __init__(self, host, port):

        # Open the log file in write mode, which truncates the file to zero length
        with open(LOG_FILE, 'w'):
            pass  # This block is empty intentionally
        self._con = sqlite3.connect("users.db")
        # cursor = self._con.cursor()
        # cursor.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY,login TEXT NOT NULL,password TEXT NOT NULL,key TEXT NOT NULL)''')
        # cursor.close()
        self._host = host
        self._port = port
        self._server_socket = None
        self._is_srv_running = True
        self._awaiting_registration = []
        self._client_handlers: list[ClientHandler] = []

    def get_client_handlers(self):
        return self._client_handlers

    def get_awaiting_registration(self):
        return self._awaiting_registration

    def stop_server(self):
        try:
            self._is_srv_running = False
            # Close server socket
            if self._server_socket is not None:
                self._server_socket.close()
                self._server_socket = None

            if len(self._client_handlers) > 0:
                # Waiting to close all opened threads
                # for client_thread in self._client_handlers:
                #     client_thread.join()
                # write_to_log(f"[SERVER_BL] All Client threads are closed")
                for client_thread in self._client_handlers:
                    client_thread.stop()

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
                cl_handler = ClientHandler(client_socket, address, self._client_handlers, [lambda x: self._awaiting_registration.append(x)])
                cl_handler.start()
                self._client_handlers.append(cl_handler)
                logging.debug(f"[SERVER_BL] ACTIVE CONNECTION {threading.active_count() - 1}")

        # ??? something happens here
        # except Exception as e:
        #    write_to_log("[SERVER_BL] Exception in start_server fn : {}".format(e))
        finally:
            logging.debug(f"[SERVER_BL] Server thread is DONE")


class ClientHandler(threading.Thread):

    _client_socket = None
    _address = None

    def __init__(self, client_socket, address: tuple[str, int], client_handlers, callbacks):
        super().__init__()

        self._client_socket: socket.socket = client_socket
        self._client_handlers = client_handlers
        self._address = address
        self._callbacks = callbacks
        self._p = Protocol()
        self._mode = "KEY"
        self._hmac_manager = None
        self._fernet = None
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
                    if data_type == "KEY":
                        try:
                            print(data)
                            pub_key = serialization.load_pem_public_key(data)
                            secret = os.urandom(128)
                            fernet_key = Fernet.generate_key()
                            self._hmac_manager = hmac.HMAC(key=secret, algorithm=self._p.HASH_ALG)
                            self._fernet = Fernet(fernet_key)
                            response = pub_key.encrypt(plaintext=(secret + fernet_key), padding=self._p.PADDING)
                            print(response)
                            response_data_type = "KEY"
                        except Exception as e:
                            logging.error("[SERVER_BL] Exception on loading public key : {}".format(e))
                            response = "Public key could not be loaded, make sure that it's in a correct format (PEM)"
                    else:
                        logging.warning("[SERVER_BL] Received data type is not KEY, discarding")
                        response = "Wrong data type, please provide a public key"
                elif self._mode == "MAIN":
                    try:
                        # HMAC verification
                        print(data_type, data_hmac, data)
                        hmac_manager_local = self._hmac_manager.copy()
                        hmac_manager_local.update(data)
                        hmac_manager_local.verify(data_hmac)

                        # Decrypting
                        data = self._fernet.decrypt(data)
                        if data == Protocol.DISCONNECT_MSG:
                            self._mode = "STOP"
                            logging.info(f"Received disconnect msg from {self._client_socket}")
                    except cryptography.exceptions.InvalidSignature:
                        logging.warning("[SERVER_BL] Received invalid HMAC, discarding data")
                        response = "Wrong HMAC, make sure you are using the correct hashing algorithm"
                    except cryptography.fernet.InvalidToken:
                        logging.warning("[SERVER_BL] Received data could not be decrypted, discarding")
                        response = "Data could not be decrypted, make sure you are using the correct key"
            # else:
                # logging.warning("[SERVER_BL] Received invalid data")
                # response = "Data is invalid"

            if self._mode == "KEY":
                if type(response) is str:
                    self._p.send_str(self._client_socket, response_data_type, b"", response)
                else:
                    self._p.send_bytes(self._client_socket, response_data_type, b"", response)
                self._mode = "MAIN"
            elif self._mode == "MAIN":
                if type(response) is str:
                    response = response.encode(Protocol.FORMAT)
                response = self._fernet.encrypt(response)
                hmac_manager_local = self._hmac_manager.copy()
                hmac_manager_local.update(response)
                response_hmac = hmac_manager_local.finalize()
                self._p.send_bytes(self._client_socket, response_data_type, response_hmac, response)


        self._client_socket.close()
        logging.debug(f"[SERVER_BL] Thread closed for : {self._address} ")
        self._client_handlers.remove(self)

    def stop(self):
        self._connected = False


    def get_address(self):
        return self._address[0], str(self._address[1])


def main():
    server = ServerBL("127.0.0.1", 8080)
    server.start_server()


if __name__ == "__main__":
    main()
