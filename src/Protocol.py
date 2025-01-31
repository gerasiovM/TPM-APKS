import socket
from datetime import datetime
import logging
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

#LOG_FILE = f'LOG-{datetime.now().strftime("%d%m%Y-%H%M")}.log'
LOG_FILE = 'LOG.log'
logging.basicConfig(filename=LOG_FILE, level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

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

    def create_request(self, cmd: str, args: str) -> str:
        """Create a valid protocol message, will be sent by client, with length field"""
        request = f"{len(cmd + '>' + args):0{self.HEADER_DATA_SIZE}}{cmd + '>' + args}"
        return request

    def create_header(self, data_type: str, data_size: int, hmac: bytes) -> bytes:
        return (
                self.standardize_str(data_type, self.HEADER_DATA_TYPE_SIZE) +
                self.standardize_str(str(data_size), self.HEADER_DATA_SIZE) +
                self.standardize(hmac, self.HEADER_HMAC_SIZE)
        )

    def send_bytes(self, s: socket.socket, data_type: str, signature: bytes, data: bytes):
        header = self.create_header(data_type, len(data), signature)
        to_send = header + data
        try:
            s.sendall(to_send)
            return True
        except Exception as e:
            logging.error(e)
            return False

    def send_str(self, s: socket.socket, data_type: str, signature: bytes, data: str) -> bool:
        return self.send_bytes(s, data_type, signature, data.encode(self.FORMAT))

    def receive_large(self, s: socket.socket, data_size: int) -> bytes:
        data = b''
        while len(data) < data_size:
            received = s.recv(self.BUFFER_SIZE)
            data += received
        return data

    # returns [valid_msg, data_type, data_hmac, data]
    def receive(self, s: socket.socket) -> [bool, str, bytes, bytes]:
        try:
            data_type = s.recv(self.HEADER_DATA_TYPE_SIZE).lstrip(b'\x00').decode(self.FORMAT)
            data_size = s.recv(self.HEADER_DATA_SIZE).lstrip(b'\x00').decode(self.FORMAT)
            # Probably don't need to lstrip, but check on this later if errors
            data_hmac = s.recv(self.HEADER_HMAC_SIZE)
            if not data_size.isnumeric():
                logging.error("Received data size is invalid, aborting")
                return [False, data_type, data_hmac, '']
            print(data_type)
            print(data_size)
            if int(data_size) > self.BUFFER_SIZE:
                data = self.receive_large(s, int(data_size))
            else:
                data = s.recv(int(data_size))
            return [True, data_type, data_hmac, data]
        # For sockets that use timeout
        except TimeoutError:
            return [False, "", b"", b""]

    def decode(self, data: bytes):
        return data.decode(self.FORMAT)

    def standardize_str(self, data: str, size: int) -> bytes:
        return self.standardize(data.encode(self.FORMAT), size)

    @staticmethod
    def standardize(data: bytes, size: int) -> bytes:
        return data.rjust(size, b'\x00')

    @staticmethod
    def hash(data: bytes):
        digest = hashes.Hash(Protocol.HASH_ALG)
        digest.update(data)
        return digest.finalize()
