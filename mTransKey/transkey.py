import re
import requests

from . import crypto
from .keypad import KeyPad

from random import randint

keyboardTypes = {
    "number": "number"
}


class mTransKey():
    def __init__(self, sess, servlet_url):
        self.sess: requests.Session = sess
        self.servlet_url = servlet_url
        self.crypto = crypto.Crypto()
        self.token = ""

        self.initTime = ""
        self.useSession = False

        self.number = []
        self.allocIndex = str(randint(0, 0xffffffff))

        self._get_token()
        self._get_init_time()
        self._get_public_key()
        self._get_key_info()

    def _get_token(self):
        txt = self.sess.get("{}?op=getToken".format(self.servlet_url)).text
        self.token = re.findall("var TK_requestToken=(.*);", txt)[0]

    def _get_init_time(self):
        txt = self.sess.get("{}?op=getInitTime".format(self.servlet_url)).text
        self.initTime = re.findall("var initTime='(.*)';", txt)[0]
        self.useSession = re.findall("var useSession=(.*);", txt)[0] == "true"

    def _get_public_key(self):
        key = self.sess.post(self.servlet_url, data={
            "op": "getPublicKey",
            "TK_requestToken": self.token
        }).text

        self.crypto.set_pub_key(key)

    def _get_key_info(self):
        key_data = self.sess.post(self.servlet_url, data={
            "op": "getKeyInfo",
            "key": self.crypto.get_encrypted_key(),
            "transkeyUuid": self.crypto.uuid,
            "useCert": "true",
            "TK_requestToken": self.token,
            "mode": "common"
        }).text

        _, num = key_data.split("var number = new Array();")
        number_keys = []

        for p in num.split("number.push(key);")[:-1]:
            points = re.findall("key\.addPoint\((\d+), (\d+)\);", p)
            number_keys.append(points[0])

        self.number = number_keys

    def new_keypad(self, key_type, name, inputName, fieldType="password"):
        if key_type != "number":
            raise Exception("Only Number")

        key_index = requests.post(self.servlet_url, data={
            "op": "getKeyIndex",
            "name": "password",
            "keyType": "single",
            "keyboardType": "number",
            "fieldType": "password",
            "inputName": "password",
            "parentKeyboard": "false",
            "transkeyUuid": self.crypto.uuid,
            "exE2E": "false",
            "TK_requestToken": self.token,
            "isCrt": "false",
            "allocationIndex": self.allocIndex,
            "keyIndex": "",
            "initTime": self.initTime,
            "talkBack": "true"
        }).text

        skip_data = self.sess.post(self.servlet_url, data={
            "op": "getDummy",
            "name": name,
            "keyType": "single",
            "keyboardType": keyboardTypes[key_type],
            "fieldType": fieldType,
            "inputName": inputName,
            "transkeyUuid": self.crypto.uuid,
            "exE2E": "false",
            "isCrt": "false",
            "allocationIndex": self.allocIndex,
            "keyIndex": key_index,
            "initTime": self.initTime,
            "TK_requestToken": self.token,
            "dummy": "undefined",
            "talkBack": "true",
        }).text

        skip = skip_data.split(",")

        return KeyPad(self.crypto, key_type, skip, self.number, key_index, self.initTime)

    def hmac_digest(self, message):
        return self.crypto.hmac_digest(message)

    def get_uuid(self):
        return self.crypto.uuid

    # def get_encrypted_keyIndex(self):
    #     return self.crypto.rsa_encrypt(self.keyIndex.encode("ascii"))
