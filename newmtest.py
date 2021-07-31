import requests
from mTransKey.transkey import mTransKey

sess = requests.session()
mtk = mTransKey(sess, "https://hcs.eduro.go.kr/transkeyServlet")

pw_pad = mtk.new_keypad("number", "password", "password", "password")

encrypted = pw_pad.encrypt_password("1415")
hm = mtk.hmac_digest(encrypted.encode())
passs = {"raon": [
    {
        "id": "password",
        "enc": encrypted,
        "hmac": hm,
        "keyboardType": "number",
        "keyIndex": pw_pad.get_key_index(), 
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
