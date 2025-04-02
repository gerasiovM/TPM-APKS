import base64
import socket
import logging
import subprocess
import os
from Protocol import Protocol
from KeyManager import KeyManager
from templates import parent_template, child_template
import threading
import cryptography.exceptions
from cryptography import fernet
from cryptography.hazmat.primitives import hmac, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from tpm2_pytss import ESAPI, TPMT_SYM_DEF, TPM2_ALG, TPMU_SYM_KEY_BITS, TPMU_SYM_MODE, TPM2_SE, TPMA_SESSION, \
    TPM2B_ID_OBJECT, TPM2B_ENCRYPTED_SECRET, TSS2_Exception, TPMT_TK_HASHCHECK, TPMT_SIG_SCHEME, TPMT_RSA_DECRYPT
from tpm2_pytss.utils import NVReadEK, create_ek_template
from tpm2_pytss.types import TPM2B_SENSITIVE_CREATE, TPM2_HANDLE, TPMU_ASYM_SCHEME, TPMS_SCHEME_HASH
from tpm2_pytss.constants import ESYS_TR, TPM2_ST, TPM2_RH


class ClientBL:
    def __init__(self):
        self._socket: socket.socket = None
        self._host: str = None
        self._port: int = None
        self._p = Protocol()
        self._logged_in = None
        self._fernet: fernet.Fernet = None
        self._temp_admin_fernet: fernet.Fernet = None
        self._hmac_manager: hmac.HMAC = None
        self.parent_creation_thread = threading.Thread(target=self.check_and_create_threading)

    @staticmethod
    def check_and_create_threading():
        with ESAPI() as ectx:
            km = KeyManager(ectx)
            if km.get_key_persistent("storage_primary_key") is None:
                ClientBL.create_storage_primary_key(ectx)

    def connect(self) -> bool:
        try:
            self._socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            # Might have to use settimeout here
            print(self._host, self._port)
            self._socket.connect((self._host,self._port))
            logging.debug(f"[CLIENT_BL] {self._socket.getsockname()} connected")
            return True
        except Exception as e:
            logging.exception("[CLIENT_BL] Exception on connect: {}".format(e))
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
            logging.exception("[CLIENT_BL] Exception on send: {}".format(e))
            return False

    def send_no_enc(self, data: bytes or str, data_type: str) -> bool:
        if type(data) is str:
            data = data.encode(Protocol.FORMAT)
        return self._p.send_bytes(self._socket, data_type, b"", data)

    def receive(self) -> [bytes, bytes]: # [data_type, data]
        if not self._socket:
            return None, b""
        try:
            import select
            ready, _, _ = select.select([self._socket], [], [], 2)
            valid_data, data_type, data_hmac, data = self._p.receive(self._socket)
            if valid_data:
                logging.info(f"[CLIENT_BL] Received message from server - {data}")
                try:
                    # HMAC verification
                    hmac_manager_local = self._hmac_manager.copy()
                    hmac_manager_local.update(data)
                    hmac_manager_local.verify(data_hmac)

                    data = self._fernet.decrypt(data)
                    return data_type, data
                except cryptography.exceptions.InvalidSignature as e:
                    logging.warning("[CLIENT_BL] Received invalid HMAC, discarding")
                except fernet.InvalidToken as e:
                    logging.warning("[CLIENT_BL] Received data could not be decrypted, discarding")
            else:
                pass
        except Exception as e:
            logging.exception("[CLIENT_BL] Exception on receive: {}".format(e))
        return None, b""

    @staticmethod
    def create_storage_primary_key(ectx):
        storage_primary_handle, storage_primary_pub, _, _, _ = ectx.create_primary(
            in_sensitive=TPM2B_SENSITIVE_CREATE(),
            in_public=parent_template,
            primary_handle=ESYS_TR.OWNER
        )
        km = KeyManager(ectx)
        handle = km.find_available_persistent_handle("storage_primary_key")
        ectx.evict_control(ESYS_TR.OWNER, storage_primary_handle, handle)
        km.save_key_handle("storage_primary_key", handle)
        return handle

    @staticmethod
    def create_storage_key(ectx, parent_handle):
        storage_priv, storage_pub, _, _, _ = ectx.create(
            parent_handle=parent_handle,
            in_sensitive=None,
            in_public=child_template
        )
        storage_handle = ectx.load(parent_handle, storage_priv, storage_pub)
        km = KeyManager(ectx)
        handle = km.find_available_persistent_handle("storage_key")
        ectx.evict_control(ESYS_TR.OWNER, storage_handle, handle)
        km.save_key_handle("storage_key", handle)
        return handle

    @staticmethod
    def setup_session(ectx, ek_handle) -> ESYS_TR:
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

    def register_ek_ak(self, ectx: ESAPI) -> [ESYS_TR, fernet.Fernet]:
        # Creating a helper utility for reading NV storage with EK certificates/templates
        nv_read = NVReadEK(ectx)
        # Fetching certificate and template for an EK of type RSA with 2048 bits
        ek_cert, ek_template = create_ek_template("EK-RSA2048", nv_read)
        # Creating an EK key using the template
        ek_handle, ek_pub, _, _, _ = ectx.create_primary(TPM2B_SENSITIVE_CREATE(), ek_template, ESYS_TR.RH_ENDORSEMENT)
        # If Client has an fTPM ek_cert will be None, need to use tpm2-tools getekcertificate command instead
        if not ek_cert:
            # Creating a file with public bytes of EK
            with open("ek.pub", "wb") as f:
                f.write(ek_pub.marshal())
            # Executing the command to get EK certificate
            command = ["tpm2_getekcertificate", "-o", "ek.cert", "-u", "ek.pub"]
            subprocess.run(command)
            # Reading the generated EK certificate
            with open("ek.cert", "rb") as f:
                ek_cert = f.read()
        # Every time we want to do anything connected to the AK, we need to provide authentication using sessions
        # Session keeps record of every time it's used, so it can't be used multiple times and needs to be recreated
        session = self.setup_session(ectx, ek_handle)
        # Creating an AK with EK as its parent
        ak_priv, ak_pub, _, _, _ = ectx.create(ek_handle, in_sensitive=None, session1=session)
        session = self.setup_session(ectx, ek_handle)
        # Loading AK into TPM memory
        ak_handle = ectx.load(ek_handle, ak_priv, ak_pub, session1=session)

        # Sending to the Server all information that it needs to check our keys and encrypt a secret
        self.send(ek_pub.marshal() + Protocol.DELIMITER + ak_pub.marshal() + Protocol.DELIMITER + ek_cert, "AUTH")
        data_type, response = self.receive()
        # Server needs to perform several http request which takes time, so we need to try and receive several times
        it = 0
        while not response and it < 20:
            data_type, response = self.receive()
            it += 1

        credblob, secret = response.split(Protocol.DELIMITER)
        session = self.setup_session(ectx, ek_handle)
        # Decrypting the secret
        certinfo = ectx.activate_credential(ak_handle, ek_handle, TPM2B_ID_OBJECT.unmarshal(credblob)[0],
                                            TPM2B_ENCRYPTED_SECRET.unmarshal(secret)[0], session2=session).marshal()[2:]
        # Making a fernet for encrypting a response
        cred_fernet = fernet.Fernet(base64.urlsafe_b64encode(certinfo))
        return ak_handle, cred_fernet

    #
    def authenticate(self) -> [bool, bytes]:
        try:
            # Opening a connection with the TPM through tabrmd
            with ESAPI(tcti="tabrmd") as ectx:
                ak_handle, cred_fernet = self.register_ek_ak(ectx)
                # Creating an instance of KeyManager that helps with key storage
                km = KeyManager(ectx)
                # Getting the persistent handle of the storage primary key
                handle = km.get_key_persistent("storage_primary_key")
                if handle is None:
                    handle = self.create_storage_primary_key(ectx)
                parent_handle = ectx.tr_from_tpmpublic(TPM2_HANDLE(handle))
                # Getting the persistent handle of the storage key to be used in asymmetric encryption
                handle = km.get_key_persistent("storage_key")
                if handle is None:
                    handle = self.create_storage_key(ectx, parent_handle)
                key_handle = ectx.tr_from_tpmpublic(TPM2_HANDLE(handle))
                # Getting the public part of the key to send to server
                key_pub = ectx.read_public(key_handle)[0]
                # Signing the key using AK so the Server knows it resides on the TPM
                validation = TPMT_TK_HASHCHECK(tag=TPM2_ST.HASHCHECK, hierarchy=TPM2_RH.OWNER)
                digest, ticket = ectx.hash(key_pub.marshal(), hash_alg=TPM2_ALG.SHA256, hierarchy=ESYS_TR.OWNER)
                scheme = TPMT_SIG_SCHEME(scheme=TPM2_ALG.RSASSA)
                scheme.details.any.hashAlg = TPM2_ALG.SHA256
                signature = ectx.sign(key_handle=ak_handle,
                                      digest=digest,
                                      in_scheme=scheme,
                                      validation=validation)
                self.send(cred_fernet.encrypt(key_pub.marshal()) + self._p.DELIMITER + signature.marshal(), "KEY2")
                response_type, response = self.receive()
                if response != "Success":
                    return False, response
        except TSS2_Exception as e:
            logging.exception("[CLIENT_BL] Exception on authenticate, confirm that the user has the permission to interact with the tpm. Error: {}".format(e))
        # except Exception as e:
        #     logging.error("[CLIENT_BL] Unknown exception on authenticate: {}".format(e))

    def login(self, login: str, password: str) -> [bool, str]:
        login = Protocol.standardize(login[:20].encode(Protocol.FORMAT), Protocol.LOGIN_SIZE)
        self.send(login + password.encode(Protocol.FORMAT), "LGN")
        response_type, login_response = self.receive()
        it = 0
        while response_type is None and it != 100:
            response_type, login_response = self.receive()
            it += 1
        if login_response.decode(Protocol.FORMAT) == "Success":
            return True, ""
        elif response_type is None:
            return False, "Could not get a response from server"
        else:
            return False, login_response.decode(Protocol.FORMAT)

    def login_admin(self, login: str) -> [bool, str]:
        try:
            with ESAPI(tcti="tabrmd") as ectx:
                km = KeyManager(ectx)
                persistent_handle = km.get_key_persistent("storage_key")
                if not persistent_handle:
                    logging.warning("No storage key found, can't admin login")
                    return False, "No key found on computer, can't login"
                storage_key_handle = ectx.tr_from_tpmpublic(TPM2_HANDLE(persistent_handle))
                self.send(login, "LGNA")
                response_type, response = self.receive()
                if response_type == "MSG":
                    logging.warning("Failed admin login, response: {}".format(response))
                    return False, response.decode(Protocol.FORMAT)
                scheme = TPMT_RSA_DECRYPT(
                    scheme=TPM2_ALG.OAEP,
                    details=TPMU_ASYM_SCHEME(oaep=TPMS_SCHEME_HASH(hashAlg=TPM2_ALG.SHA256))
                )
                fernet_key = ectx.rsa_decrypt(storage_key_handle, response, scheme).marshal()
                self._temp_admin_fernet = fernet.Fernet(fernet_key)
                self.send(self._temp_admin_fernet.encrypt(b"Answer"), "LGNB")
                self._fernet, self._temp_admin_fernet = self._temp_admin_fernet, self._fernet
                response_type, response = self.receive()
                if response_type is not None:
                    return True, "Success"
                else:
                    self._fernet, self._temp_admin_fernet = self._temp_admin_fernet, self._fernet
                    return False, response.decode(Protocol.FORMAT)
        except TSS2_Exception as e:
            logging.exception("[CLIENT_BL] Exception on authenticate, confirm that the user has the permission to interact with the tpm. Error: {}".format(e))
            return False, "TSS Exception"

    def retrieve_database(self) -> [bool, str|bytes]:
        if self._logged_in != "Admin":
            return [False, "Must be logged in as Admin"]
        self.send("Request", "DB")
        response_type, db_response = self.receive()
        print(response_type, db_response)
        if not os.path.exists("../resources/db/"):
            os.mkdir("../resources/db/")
        with open("../resources/db/users.db", "wb") as f:
            f.write(db_response)

    def add_user(self, login: str, password: str) -> [bool, str]:
        self.send(login.encode(Protocol.FORMAT) + Protocol.DELIMITER + password.encode(Protocol.FORMAT), "REG")
        response_type, response = self.receive()
        if response.decode(Protocol.FORMAT) == "Success":
            return [True, response]
        else:
            return [False, response]

    def establish_secure_connection(self) -> bool:
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
            logging.exception("[CLIENT_BL] Exception when attempting key exchange: {}".format(e))
            return False


def main():
    c = ClientBL()
    c._host = "127.0.0.1"
    c._port = 8080
    c.connect()
    c.establish_secure_connection()
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