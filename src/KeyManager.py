from tpm2_pytss import ESAPI, TPM2_CAP
import os
class KeyManager:
    def __init__(self, ectx):
        self.ectx = ectx

    # Returns the handle for a persistent key if there is one
    def get_key_persistent(self, key_type) -> int | None: # key_type is either storage_primary_key or storage_key
        import json
        try:
            with open("../resources/handles/persistent-handles.json", "r") as f:
                handles = json.load(f)
                if key_type not in handles:
                    return None
                handle = handles[key_type]
                # Querying the TPM for existing persistent handles, to check if it still exists on the computer
                _, cap_data = self.ectx.get_capability(TPM2_CAP.HANDLES, handle)
                if handle in cap_data.data.handles:
                    return handle
                else:
                    return None
        # If there is no file we can't know if there are keys on the computer
        except FileNotFoundError:
            return None

    def find_available_persistent_handle(self, key_type) -> int | None:
        ranges = {"storage_primary_key": 0x81000000, "storage_key": range(0x81008000, 0x8100ffff, 255)}
        if key_type == "storage_primary_key":
            return ranges[key_type]
        _, cap_data = self.ectx.get_capability(TPM2_CAP.HANDLES, ranges[key_type][0], 100)
        used_handles = {handle for handle in cap_data.data.handles}

        # Find the first available handle
        for handle in ranges["storage_key"]:
            if handle not in used_handles:
                return handle

    @staticmethod
    def save_key_handle(name, handle):
        import json
        try:
            with open("../resources/handles/persistent-handles.json", "r") as f:
                handle_data = json.load(f)
                handle_data[name] = handle
        except FileNotFoundError:
            handle_data = {name: handle}
            os.mkdir("../resources/handles")
        with open("../resources/handles/persistent-handles.json", "w") as f:
            json.dump(handle_data, f)