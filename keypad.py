from . import chars
from random import randint

class KeyPad():
    def __init__(self, crypto, key_type, skip_data, keys):
        if key_type != "number":
            raise Exception("Only Number")

        self.crypto = crypto
        self.key_type = key_type
        self.skip_data = skip_data
        self.keys = keys

    def get_geo(self, message):
        geos = []
        for val in list(message):
            if val.isnumeric():
                geos.append(self.keys[self.skip_data.index(val)])
            else:
                raise Exception("Only Number")
        return geos

    def geos_encrypt(self, geos):
        out = ""
        for geo in geos:
            x, y = geo
            
            xbytes = bytes(map(int, list(x)))
            ybytes = bytes(map(int, list(y)))
            randnum = randint(0, 100)

            if self.key_type == "number":
                data = b"%b %b e%c" % (xbytes, ybytes, randnum)
                
            iv = bytes([0x4d, 0x6f, 0x62, 0x69, 0x6c, 0x65, 0x54, 0x72,
                        0x61, 0x6e, 0x73, 0x4b, 0x65, 0x79, 0x31, 0x30])

            out += "$"+self.crypto.seed_encrypt(iv, data).hex(",")
        return out
    
    def encrypt_password(self, pw):
        geos = self.get_geo(pw)
        return self.geos_encrypt(geos)