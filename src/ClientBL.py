import socket
import logging
from Protocol import Protocol
import cryptography.exceptions
from cryptography import fernet
from cryptography.hazmat.primitives import hmac, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
class ClientBL:
    def __init__(self):
        self._socket: socket.socket = None
        self._host: str = None
        self._port: int = None
        self._p = Protocol()
        self._fernet: fernet.Fernet = None
        self._hmac_manager: hmac.HMAC = None

    def connect(self):
        try:
            self._socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            # Might have to use settimeout here
            self._socket.connect((self._host,self._port))
            logging.debug(f"[CLIENT_BL] {self._socket.getsockname()} connected")
            return self._socket
        except Exception as e:
            logging.error("[CLIENT_BL] Exception on connect: {}".format(e))
            return None

    def disconnect(self):
        try:
            self.send(self._p.DISCONNECT_MSG, "MSG")
            self._socket.shutdown(socket.SHUT_RDWR)
            self._socket.close()
            logging.debug(f"[CLIENT_BL] {self._socket.getsockname()} disconnected")
            self._socket = None
        except Exception as e:
            logging.error("[CLIENT_BL] Exception on disconnect: {}".format(e))

    def send(self, data: bytes or str, data_type: str) -> bool:
        if type(data) is str:
            data = data.encode(Protocol.FORMAT)
        try:
            encrypted_data = self._fernet.encrypt(data)
            hmac_manager_local = self._hmac_manager.copy()
            hmac_manager_local.update(encrypted_data)
            data_hmac = hmac_manager_local.finalize()
            print(data_type, data_hmac, encrypted_data)
            self._p.send_bytes(self._socket, data_type, data_hmac, encrypted_data)
            return True
        except Exception as e:
            logging.error("[CLIENT_BL] Exception on send: {}".format(e))
            return False

    def receive(self) -> bytes:
        if not self._socket:
            return ""
        try:
            valid_data, data_type, data_hmac, data = self._p.receive(self._socket)
            if valid_data:
                try:
                    # HMAC verification
                    hmac_manager_local = self._hmac_manager.copy()
                    hmac_manager_local.update(data)
                    hmac_manager_local.verify(data_hmac)

                    data = self._fernet.decrypt(data)
                except cryptography.exceptions.InvalidSignature as e:
                    logging.warning("[CLIENT_BL] Received invalid HMAC, discarding")
                except fernet.InvalidToken as e:
                    logging.warning("[CLIENT_BL] Received data could not be decrypted, discarding")
            else:
                pass
        except Exception as e:
            logging.error("[CLIENT_BL] Exception on receive: {}".format(e))

    def key_exchange(self):
        private_key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
        public_key = private_key.public_key()
        pem_pub = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                          format=serialization.PublicFormat.SubjectPublicKeyInfo)
        print(pem_pub)
        self._p.send_bytes(self._socket, "KEY", b"", pem_pub)
        response_enc = self._p.receive(self._socket)[3]
        print(response_enc)
        response = private_key.decrypt(response_enc, padding=Protocol.PADDING)
        secret = response[:128]
        fernet_key = response[128:]
        self._hmac_manager = hmac.HMAC(key=secret, algorithm=Protocol.HASH_ALG)
        self._fernet = fernet.Fernet(fernet_key)


def main():
    c = ClientBL()
    c._host = "127.0.0.1"
    c._port = 8080
    c.connect()
    c.key_exchange()
    c.send("Hello World!", "MSG")
    msg = input()
    while msg != "EXIT":
        c.send(msg, "MSG")
        msg = input()
    c.disconnect()

if __name__ == "__main__":
    main()