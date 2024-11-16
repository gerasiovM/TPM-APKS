import socket
from datetime import datetime
import logging

LOG_FILE = f'LOG-{datetime.now().strftime("%d%m%Y-%H%M")}.log'
logging.basicConfig(filename=LOG_FILE, level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

class Protocol:
    BUFFER_SIZE = 1024
    HEADER_DATA_TYPE_SIZE = 4
    HEADER_DATA_SIZE = 4
    FORMAT = 'utf-8'
    DISCONNECT_MSG = '!DISCONNECT'

    def create_request(self, cmd: str, args: str) -> str:
        """Create a valid protocol message, will be sent by client, with length field"""
        request = f"{len(cmd + '>' + args):0{self.HEADER_LEN}}{cmd + '>' + args}"
        return request

    def send(self, s: socket.socket, data_type: str, data: str) -> bool:
        main_data = data.encode(self.FORMAT)
        header = self.standardize(data_type, self.HEADER_DATA_TYPE_SIZE) + self.standardize(str(len(main_data)), self.HEADER_DATA_SIZE)
        to_send = header + main_data
        try:
            s.sendall(to_send)
            return True
        except Exception as e:
            logging.error(e)
            return False

    def receive_large(self, s: socket.socket, data_size: int) -> bytes:
        data = b''
        while len(data) < data_size:
            received = s.recv(self.BUFFER_SIZE)
            data += received
        return data

    def receive(self, s: socket.socket) -> [bool, str]:
        data_type = s.recv(self.HEADER_DATA_TYPE_SIZE).lstrip(b'\x00').decode('utf-8')
        data_size = s.recv(self.HEADER_DATA_SIZE).lstrip(b'\x00').decode('utf-8')
        if not data_size.isnumeric():
            logging.error("Received data size is invalid, aborting")
            return [False, '']
        if data_type == "LRG":
            data = self.receive_large(s, int(data_size))
        else:
            data = s.recv(int(data_size))
        return data.decode(self.FORMAT)

    def standardize(self, data: str, size: int) -> bytes:
        return data.encode(self.FORMAT).rjust(size, b'\x00')