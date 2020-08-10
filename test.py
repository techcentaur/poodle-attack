import hashlib
from Crypto.Cipher import AES
import base64

def get_random_bytes(l=16):
    return open("/dev/urandom", "rb").read(l)

class AESCipher(object):

    def __init__(self, key): 
        self.bs = 16
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw, iv):
        print(self.padding(raw.encode()))
        raw = self._pad(raw)
        print(raw)
        # iv = get_random_bytes()
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return (iv + cipher.encrypt(raw.encode()))

    def padding(self, data):
        rem = len(data) % self.bs
        num_pads = self.bs-rem-1
        padded_data = data + get_random_bytes(num_pads) + bytes([num_pads])
        return padded_data

    def decrypt(self, enc, iv):
        # iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        # return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

if __name__ == '__main__':
    a = AESCipher("ankit")

    # k2 = get_random_bytes(16)
    iv = get_random_bytes(16)
    K2 = get_random_bytes(10)

    x = a.encrypt("ankitsolan", iv)
    print(x)
    y = a.decrypt(x, iv)
    print(y)