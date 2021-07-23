import requests
from mTransKey.transkey import mTransKey

ID = ""
PW = ""

sess = requests.session()
mtk = mTransKey(sess, "https://hcs.eduro.go.kr/transkeyServlet")

pw_pad = mtk.new_keypad("number", "password", "password", "password")

encrypted = pw_pad.encrypt_password("")
hm = mtk.hmac_digest(encrypted.encode())
passs = {"raon": [
    {
        "id": "password",
        "enc": encrypted,
        "hmac": hm,
        "keyboardType": "number",
        "keyIndex": mtk.crypto.rsa_encrypt(b"32"), #음.. numberSize까지 랜덤(min: 0, max: 67) 이긴한데 그냥 고정을(?) 
        "fieldType": "password",
        "seedKey": mtk.crypto.get_encrypted_key(),
        "initTime": mtk.initTime,
        "ExE2E": "false"
    }
]}

print(passs)
import json
k = sess.post("https://icehcs.eduro.go.kr/v2/validatePassword", headers={
    "User-Agent": "",
    "Referer": "https://hcs.eduro.go.kr/",
    "Authorization": "Bearer ",
    "X-Requested-With": "XMLHttpRequest",
    "Content-Type": "application/json;charset=utf-8"
}, data=json.dumps({
    "password": json.dumps(passs),
    "deviceUuid": "",
    "makeSession": True
}))

print(k.text)
