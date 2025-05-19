This is a rough instruction on how to set up this project on debian:
```
sudo apt install libtss2-dev tss2 tpm2-tools tpm2-abrmd libtss2-tcti-tabrmd-dev pkgconf gcc python3-dev
sudo adduser {user} tss
python3 -m venv tpmenv
source tpmenv/bin/activate
pip install -r requirements.txt
```

If you get an access error when running this command:
`tpm2_getcap -T tabrmd`

Then you might not have tpm rules set up. Create a "70-tpm.rules" file in /etc/udev/rules.d:
```
# tpm devices can only be accessed by the tss user but the tss
# group members can access tpmrm devices
KERNEL=="tpm[0-9]*", TAG+="systemd", MODE="0660", OWNER="tss", GROUP="tss"
KERNEL=="tpmrm[0-9]*", TAG+="systemd", MODE="0660", GROUP="tss"
KERNEL=="tcm[0-9]*", TAG+="systemd", MODE="0660", OWNER="tss", GROUP="tss"
KERNEL=="tcmrm[0-9]*", TAG+="systemd", MODE="0660", GROUP="tss
```