"""
simulating poodle man in the middle attack on SSLv3
"""
import hashlib
from Crypto.Cipher import AES

class SSLv3:
    '''SSLv3 Protocol'''
    def __init__(self, block_length=16):
        self.block_length = block_length
        self.create_cipher_key(16)

    def create_cipher_key(self, length):
        self.cipher_key = get_random_bytes(length)

    @staticmethod
    def get_random_bytes(l=16):
        return open("/dev/urandom", "rb").read(l)

    def padding(self, data):
        rem = len(data) % self.block_length
        num_pads = self.block_length-rem-1
        padded_data = data + SSLv3.get_random_bytes(num_pads) + bytes([num_pads])
        return padded_data

    @staticmethod
    def perform_xor(a1, a2):
        return bytes(a ^ b for (a, b) in zip(a1, a2))

    def fragment_blocks(self, data):
        blocks = []
        for i in range(0, len(data), self.block_length):
            blocks.append(data[i: i+self.block_length])
        return blocks

    def encrypt_data(self, data):
        data = data + hashlib.new('md5', data).digest()
        return self.encrypt_cipher_block(self.padding(data))

    def decrypt_data(self, data):
        decrypted_data = self.decrypt_cipher_block(data)
        # TODO


    def encrypt_cipher_block(self, data):
        self.iv = get_random_bytes(self.block_length)
        blocks = fragment_blocks(data)

        cipher_data = []

        iv = self.iv
        for b in blocks:
            cipher = AES.new(self.cipher_key, AES.MODE_CBC, iv).encrypt(self.perform_xor(iv, b))
            iv = cipher

            cipher_data.append(cipher)
        cipher_bytes_data = b''.join(cipher_data)
        return cipher_bytes_data

    def decrypt_cipher_block(self, data):
        blocks = fragment_blocks(data)
        blocks.reverse()
        
        plain_data = []
        for i, b in enumerate(blocks):
            if i==len(blocks)-1:
                iv = self.iv
            else:
                iv = blocks[i+1]
            v = AES.new(self.cipher_key, AES.MODE_CBC, iv).decrypt(b)
            plain = self.perform_xor(iv, v)
            plain_data.append(plain)

        plain_data.reverse()
        plain_bytes_data = b''.join(plain_data)
        return plain_bytes_data



if __name__ == '__main__':
    x = padding(bytearray("Ankit"))  
    print(x)
    
    bytearray(random.getrandbits(8) for _ in xrange(4))
