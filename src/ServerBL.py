import random

from Protocol import LOG_FILE
import logging
import sqlite3
import socket
import threading
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.fernet import Fernet

from src.Protocol import Protocol


class CServerBL:

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
        self._client_handlers: list[CClientHandler] = []

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
                cl_handler = CClientHandler(client_socket, address, self._client_handlers, [lambda x: self._awaiting_registration.append(x)])
                cl_handler.start()
                self._client_handlers.append(cl_handler)
                logging.debug(f"[SERVER_BL] ACTIVE CONNECTION {threading.active_count() - 1}")

        # ??? something happens here
        # except Exception as e:
        #    write_to_log("[SERVER_BL] Exception in start_server fn : {}".format(e))
        finally:
            logging.debug(f"[SERVER_BL] Server thread is DONE")


class CClientHandler(threading.Thread):

    _client_socket = None
    _address = None

    def __init__(self, client_socket, address: tuple[str, int], client_handlers, callbacks):
        super().__init__()

        self._client_socket: socket.socket = client_socket
        self._client_socket.setblocking(False)
        self._client_handlers = client_handlers
        self._address = address
        self._callbacks = callbacks
        self._p = Protocol()
        self._mode = "KEY"
        self._secret = None
        self._fernet = None
        self._connected = False

    def run(self):
        # This code run in separate thread for every client
        self._connected = True
        while self._connected:
            # 1. Get message from socket and check it
            valid_data, data_type, data = self._p.receive(self._client_socket)
            response = ""
            if valid_data:
                # Logging
                if len(data) > 1024:
                    logging.debug(f"[SERVER_BL] Received from {self._address} LARGE data of type {data_type}")
                else:
                    logging.debug(f"[SERVER_BL] Received from {self._address} data - {data}")
                if self._mode == "KEY":
                    if data_type == "KEY":
                        try:
                            pub_key = serialization.load_pem_public_key(data)
                            self._secret = os.urandom(128)
                            fernet_key = Fernet.generate_key()
                            self._fernet = Fernet(fernet_key)
                            response = pub_key.encrypt(plaintext=)
                        except Exception as e:
                            logging.error("[SERVER_BL] Exception on loading public key : {}".format(e))
                            response = "Public key could not be loaded, make sure that it's in a correct format (PEM)"
                    else:
                        logging.warning("[SERVER_BL] Received data type is not KEY, discarding")
                        response = "Wrong data type, please provide a public key"
            else:
                logging.warning("[SERVER_BL] Received invalid data")
            # valid_msg, msg = read_buffer(self._client_socket)
            # if valid_msg:
            #     # 2. Save to log
            #     logging.debug(f"[SERVER_BL] received from {self._address}] - {msg}")
            #     # 3. If valid command - create response
            #     command, args = (msg.split(">") + [""])[:2]
            #     used_protocol = check_cmd(command, self._client_socket, self._callbacks)
            #     if used_protocol:
            #         # 4. Create response
            #         response = used_protocol.create_response(command, args)
            #         # 5. Save to log
            #         write_to_log("[SERVER_BL] send - " + response)
            #         # 6. Send response to the client
            #         self._client_socket.send(response.encode(used_protocol.FORMAT))
            #     else:
            #         # if received command not supported by protocol, just send it back "as is"
            #         # 4. Create response
            #         response = "Non-supported cmd"
            #         response = f"{len(response):0{CProtocol.HEADER_LEN}}{response}"
            #         # 5. Save to log
            #         write_to_log("[SERVER_BL] send - " + response)
            #         # 6. Send response to the client
            #         self._client_socket.send(response.encode(used_protocol.FORMAT))
            #
            #     # Handle DISCONNECT command
            #     if msg == used_protocol.DISCONNECT_MSG:
            #         self._connected = False

        self._client_socket.close()
        logging.debug(f"[SERVER_BL] Thread closed for : {self._address} ")
        self._client_handlers.remove(self)

    def stop(self):
        self._connected = False


    def get_address(self):
        return self._address[0], str(self._address[1])


if __name__ == "__main__":
    server = CServerBL(CProtocol.SERVER_HOST, CProtocol.PORT)
    server.start_server()
