import socket
import logging
from Protocol import Protocol
import cryptography.exceptions
from cryptography import fernet
from cryptography.hazmat.primitives import hmac, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from tpm2_pytss import ESAPI, TPMT_SYM_DEF, TPM2_ALG, TPMU_SYM_KEY_BITS, TPMU_SYM_MODE, TPM2_SE, TPMA_SESSION, \
    TPM2B_ID_OBJECT, TPM2B_ENCRYPTED_SECRET, TSS2_Exception
from tpm2_pytss.utils import NVReadEK, create_ek_template
from tpm2_pytss.types import TPM2B_SENSITIVE_CREATE
from tpm2_pytss.constants import ESYS_TR

class ClientBL:
    def __init__(self):
        self._socket: socket.socket = None
        self._host: str = None
        self._port: int = None
        self._p = Protocol()
        self._logged_in = False
        self._fernet: fernet.Fernet = None
        self._hmac_manager: hmac.HMAC = None
        self._ek_handle: ESYS_TR = None
        self._ak_handle: ESYS_TR = None

    def connect(self) -> bool:
        try:
            self._socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            # Might have to use settimeout here
            self._socket.connect((self._host,self._port))
            logging.debug(f"[CLIENT_BL] {self._socket.getsockname()} connected")
            return True
        except Exception as e:
            logging.error("[CLIENT_BL] Exception on connect: {}".format(e))
            return False

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

    def send_no_enc(self, data: bytes or str, data_type: str) -> bool:
        if type(data) is str:
            data = data.encode(Protocol.FORMAT)
        self._p.send_bytes(self._socket, data_type, b"", data)

    def receive(self) -> bytes:
        if not self._socket:
            return b""
        try:
            valid_data, data_type, data_hmac, data = self._p.receive(self._socket)
            if valid_data:
                logging.info(f"[CLIENT_BL] Received message from server - {data}")
                try:
                    # HMAC verification
                    hmac_manager_local = self._hmac_manager.copy()
                    hmac_manager_local.update(data)
                    hmac_manager_local.verify(data_hmac)

                    data = self._fernet.decrypt(data)
                    return data
                except cryptography.exceptions.InvalidSignature as e:
                    logging.warning("[CLIENT_BL] Received invalid HMAC, discarding")
                except fernet.InvalidToken as e:
                    logging.warning("[CLIENT_BL] Received data could not be decrypted, discarding")
            else:
                pass
        except Exception as e:
            logging.error("[CLIENT_BL] Exception on receive: {}".format(e))
        return b""

    @staticmethod
    def setup_session(ectx, ek_handle):
        sym = TPMT_SYM_DEF(algorithm=TPM2_ALG.XOR,
                           keyBits=TPMU_SYM_KEY_BITS(exclusiveOr=TPM2_ALG.SHA256),
                           mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB))
        session = ectx.start_auth_session(tpm_key=ek_handle,
                                          bind=ESYS_TR.NONE,
                                          session_type=TPM2_SE.POLICY,
                                          symmetric=sym,
                                          auth_hash=TPM2_ALG.SHA256)
        nonce = ectx.trsess_get_nonce_tpm(session)
        expiration = -(10 * 365 * 24 * 60 * 60)
        ectx.policy_secret(ESYS_TR.ENDORSEMENT, session, nonce, b"", b"", expiration)
        ectx.trsess_set_attributes(session, TPMA_SESSION.ENCRYPT | TPMA_SESSION.DECRYPT)
        return session

    def authenticate(self):
        try:
            with ESAPI() as ectx:
                nv_read = NVReadEK(ectx)
                ek_cert, ek_template = create_ek_template("EK-RSA2048", nv_read)
                self.ek_handle, ek_pub, _, _, _ = ectx.create_primary(TPM2B_SENSITIVE_CREATE(), ek_template, ESYS_TR.RH_ENDORSEMENT)
                session = self.setup_session(ectx, self.ek_handle)
                ak_priv, ak_pub, _, _, _ = ectx.create(self.ek_handle, in_sensitive=None, session1=session)
                session = self.setup_session(ectx, self.ek_handle)
                self.ak_handle = ectx.load(self.ek_handle, ak_priv, ak_pub, session1=session)
                self.send(ek_pub.to_pem() + Protocol.DELIMITER + ak_pub.to_pem() + Protocol.DELIMITER + ek_cert, "AUTH")
                response = self.receive()
                while not response:
                    response = self.receive()
                credblob, secret = response.split(Protocol.DELIMITER)
                session = self.setup_session(ectx, self.ek_handle)
                certinfo = ectx.activate_credential(self.ak_handle, self.ek_handle, TPM2B_ID_OBJECT.unmarshal(credblob), TPM2B_ENCRYPTED_SECRET.unmarshal(secret), session2=session)[2:]
                print(certinfo)
        except TSS2_Exception as e:
            logging.error("[CLIENT_BL] Exception on authenticate, confirm that the user has the permission to interact with the tpm {}".format(e))
        except Exception as e:
            logging.error("[CLIENT_BL] Unknown exception on authenticate: {}".format(e))



    def login(self, login: str, password: str):
        login = Protocol.standardize(login[:20].encode(Protocol.FORMAT), Protocol.LOGIN_SIZE)
        self.send(login + password.encode(Protocol.FORMAT), "LGN")


    def key_exchange(self) -> bool:
        try:
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
            return True
        except Exception as e:
            logging.error("[CLIENT_BL] Exception when attempting key exchange: {}".format(e))
            return False


def main():
    c = ClientBL()
    c._host = "127.0.0.1"
    c._port = 8080
    c.connect()
    c.key_exchange()
    c.send("Hello World!", "MSG")
    print(c.receive().decode(Protocol.FORMAT))
    msg = input()
    while msg != "EXIT":
        c.send(msg, "MSG")
        print(c.receive().decode(Protocol.FORMAT))
        msg = input()
    c.disconnect()

if __name__ == "__main__":
    main()