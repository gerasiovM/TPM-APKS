from tpm2_pytss import ESAPI, TPM2_CAP
import os
class KeyManager:
    def __init__(self, ectx):
        self.ectx = ectx

    def get_key_persistent(self, key_type) -> int:
        import json
        try:
            with open("../resources/handles/persistent-handles.json", "r") as f:
                handles = json.load(f)
                if key_type not in handles:
                    print("a")
                    print(handles)
                    return None
                handle = handles[key_type]
                _, cap_data = self.ectx.get_capability(TPM2_CAP.HANDLES, handle)
                if handle in cap_data.data.handles:
                    return handle
                else:
                    print("b")
                    return None
        except FileNotFoundError:
            print("c")
            return None

    def find_available_persistent_handle(self, key_type):
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