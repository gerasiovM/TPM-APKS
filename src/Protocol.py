import socket
from datetime import datetime
import logging
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

#LOG_FILE = f'LOG-{datetime.now().strftime("%d%m%Y-%H%M")}.log'
LOG_FILE = 'LOG.log'
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class Protocol:
    BUFFER_SIZE = 1024
    HEADER_DATA_TYPE_SIZE = 4
    HEADER_DATA_SIZE = 8
    HEADER_HMAC_SIZE = 32
    LOGIN_SIZE = 20
    DELIMITER = b"/|\\/|\\"
    HASH_ALG = hashes.SHA256()
    PADDING = padding.OAEP(
        mgf=padding.MGF1(algorithm=HASH_ALG),
        algorithm=HASH_ALG,
        label=None
    )
    FORMAT = 'utf-8'
    DISCONNECT_MSG = '!DISCONNECT'

    def create_header(self, data_type: str, data_size: int, hmac: bytes) -> bytes:
        return (
                self.standardize_str(data_type, self.HEADER_DATA_TYPE_SIZE) +
                self.standardize_str(str(data_size), self.HEADER_DATA_SIZE) +
                self.standardize(hmac, self.HEADER_HMAC_SIZE)
        )

    def send_bytes(self, s: socket.socket, data_type: str, signature: bytes, data: bytes) -> bool:
        header = self.create_header(data_type, len(data), signature)
        to_send = header + data
        try:
            s.sendall(to_send)
            return True
        except Exception as e:
            logging.exception(e)
            return False

    def send_str(self, s: socket.socket, data_type: str, signature: bytes, data: str) -> bool:
        return self.send_bytes(s, data_type, signature, data.encode(self.FORMAT))

    def receive_large(self, s: socket.socket, data_size: int) -> bytes|None:
        data = b''
        while data_size:
            chunk = s.recv(min(self.BUFFER_SIZE, data_size))
            if not chunk:
                break
            data += chunk
            data_size = data_size-len(chunk)
            print(len(data), "|", data_size)
        if data_size:
            logging.error("not enough data in the socket")
            return None
        print(f"receive_large: recived={len(data)}")
        return data

    # Uses a socket to receive packets
    def receive(self, s: socket.socket) -> [bool, str, bytes, bytes]: # [valid_msg, data_type, data_hmac, data]
        try:
            # Receives data_type, data_size and data_hmac that must come with every message
            data_type = s.recv(self.HEADER_DATA_TYPE_SIZE).lstrip(b'\x00').decode(self.FORMAT)
            data_size = s.recv(self.HEADER_DATA_SIZE).lstrip(b'\x00').decode(self.FORMAT)
            data_hmac = s.recv(self.HEADER_HMAC_SIZE)

            # Checks if the decoded data_size strings consists of numbers
            if not data_size.isnumeric():
                logging.error("Received data size is invalid, aborting")
                return [False, data_type, data_hmac, '']

            data = self.receive_large(s, int(data_size))
            if data is None:
                return [False, data_type, data_hmac, '']

            if not data:
                return [False, data_type, data_hmac, b""]
            return [True, data_type, data_hmac, data]
        # For sockets that use timeout
        except TimeoutError:
            return [False, "Timeout", b"", b""]

    @classmethod
    def decode(cls, data: bytes) -> str:
        return data.decode(cls.FORMAT)

    @classmethod
    def standardize_str(cls, data: str, size: int) -> bytes:
        return cls.standardize(data.encode(cls.FORMAT), size)

    @staticmethod
    def standardize(data: bytes, size: int) -> bytes:
        return data.rjust(size, b'\x00')

    @staticmethod
    def hash(data: bytes) -> bytes:
        digest = hashes.Hash(Protocol.HASH_ALG)
        digest.update(data)
        return digest.finalize()
