import hashlib
from Crypto.Cipher import AES
from Crypto import Random

class SSLv3:
    '''SSLv3 Protocol'''

    def __init__(self, b_length=16):
        self.b_length = b_length
        self.cipher_key = SSLv3.get_random_bytes(16)
    def padding(self, data):
        rem = len(data) % self.b_length
        return data + SSLv3.get_random_bytes(self.b_length-rem-1) + bytes([self.b_length-rem-1])

    @staticmethod
    def get_random_bytes(size=16):
        return Random.get_random_bytes(size)

    def fragment_blocks(self, data):
        return [data[i: i+self.b_length] for i in range(0, len(data), self.b_length)]

    def encrypt_data(self, data):
        return self.encrypt_cipher_block(self.padding(data + hashlib.new('md5', data).digest()))

    def decrypt_data(self, data):
        data = self.decrypt_cipher_block(data)
        if not (data[-1] <= 15 and data[-1] >= 0):
            return False

        data = data[ : -(data[-1]+1)]
        plain, mac = data[ : -16], data[-16 : ]
        
        return False if hashlib.new('md5', plain).digest() != mac else True

    def encrypt_cipher_block(self, data):
        self.iv = SSLv3.get_random_bytes(self.b_length)
        
        iv = self.iv
        cipher_data = []
        for b in self.fragment_blocks(data):
            cipher = AES.new(self.cipher_key, AES.MODE_CBC, iv=iv).encrypt(b)
            cipher_data.append(cipher)
            iv = cipher
        return b''.join(cipher_data)

    def decrypt_cipher_block(self, data):
        iv = self.iv
        plain_data = []

        blocks = self.fragment_blocks(data)
        for i in range(len(blocks)-1, -1, -1):
            iv = self.iv if i==0 else blocks[i-1]
            plain_data.append(AES.new(self.cipher_key, AES.MODE_CBC, iv=iv).decrypt(blocks[i]))

        plain_data.reverse()
        return b''.join(plain_data)
