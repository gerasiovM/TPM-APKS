import socket
from datetime import datetime
import logging
from cryptography.hazmat.primitives.asymmetric import rsa

#LOG_FILE = f'LOG-{datetime.now().strftime("%d%m%Y-%H%M")}.log'
LOG_FILE = 'LOG.log'
logging.basicConfig(filename=LOG_FILE, level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

class Protocol:
    BUFFER_SIZE = 1024
    HEADER_DATA_TYPE_SIZE = 4
    HEADER_DATA_SIZE = 8
    FORMAT = 'utf-8'
    DISCONNECT_MSG = '!DISCONNECT'

    def create_request(self, cmd: str, args: str) -> str:
        """Create a valid protocol message, will be sent by client, with length field"""
        request = f"{len(cmd + '>' + args):0{self.HEADER_DATA_SIZE}}{cmd + '>' + args}"
        return request

    def create_header(self, data_type: str, data_size: int) -> bytes:
        return self.standardize(data_type, self.HEADER_DATA_TYPE_SIZE) + self.standardize(
            str(data_size), self.HEADER_DATA_SIZE)

    def send_bytes(self, s: socket.socket, data_type: str, data: bytes):
        header = self.create_header(data_type, len(data))
        to_send = header + data
        try:
            s.sendall(to_send)
            return True
        except Exception as e:
            logging.error(e)
            return False

    def send_str(self, s: socket.socket, data_type: str, data: str) -> bool:
        return self.send_bytes(s, data_type, data.encode(self.FORMAT))

    def receive_large(self, s: socket.socket, data_size: int) -> bytes:
        data = b''
        while len(data) < data_size:
            received = s.recv(self.BUFFER_SIZE)
            data += received
        return data

    def receive(self, s: socket.socket) -> [bool, bytes]:
        data_type = s.recv(self.HEADER_DATA_TYPE_SIZE).lstrip(b'\x00').decode(self.FORMAT)
        print(data_type)
        data_size = s.recv(self.HEADER_DATA_SIZE).lstrip(b'\x00').decode(self.FORMAT)
        print(data_size)
        if not data_size.isnumeric():
            logging.error("Received data size is invalid, aborting")
            return [False, '']
        if data_type == "LRG":
            data = self.receive_large(s, int(data_size))
        else:
            data = s.recv(int(data_size))
        return data

    def decode(self, data: bytes):
        return data.decode(self.FORMAT)

    def standardize(self, data: str, size: int) -> bytes:
        return data.encode(self.FORMAT).rjust(size, b'\x00')

    @staticmethod
    def create_rsa_key_pair():
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return private_key, private_key.public_key()