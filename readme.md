This is a rough instruction on how to set up this project on debian:
```
sudo apt install libtss2-dev tss2 tpm2-tools tpm2-abrmd libtss2-tcti-tabrmd-dev pkgconf gcc python3-dev
sudo adduser {user} tss
python3 -m venv tpmenv
source tpmenv/bin/activate
pip install -r requirements.txt
```
