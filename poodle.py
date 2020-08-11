import hashlib
from Crypto.Cipher import AES
from Crypto import Random

class SSLv3:
    '''Simulating SSLv3 Protocol'''

    def __init__(self, b_length=16):
        '''generate a random 16 byte key every time protocol is initiated'''
        
        self.b_length = b_length
        self.cipher_key = SSLv3.get_random_bytes(16)
    
    def padding(self, data):
        '''return a padded data of length of next multiple of 16'''

        rem = len(data) % self.b_length
        return data + SSLv3.get_random_bytes(self.b_length-rem-1) + bytes([self.b_length-rem-1])

    def fragment_blocks(self, data):
        '''return fragment of blocks each of length block-length'''

        return [data[x: x + self.b_length] for x in range(0, len(data), self.b_length)]

    @staticmethod
    def get_random_bytes(size=16):
        '''return `size` random bytes. This is a static method'''
        return Random.get_random_bytes(size)

    def encrypt_data(self, data):
        '''
        @param: data <- unencrypted data
        - calculate the MAC of input data using md5 hash
        - append this mac to data as: data = data + mac
        - add necessary padding to the data 
        - return data encrypted by AES in CBC mode 
        '''

        return self.encrypt_cipher_block(self.padding(data + hashlib.new('md5', data).digest()))

    def decrypt_data(self, data):
        '''
        @param: data <- encrypted data
        - decrypt data using AES in CBC mode
        - reject if last byte doesn't belong to [0, 15] i.e., wrong padding
        - else remove padding and check mac of data
            - if mac not correct, reject request
            - else accept it (return True)
        '''

        data = self.decrypt_cipher_block(data)
        if not (data[-1] <= 15 and data[-1] >= 0):
            return False

        data = data[ : -(data[-1]+1)]
        plain, mac = data[ : -16], data[-16 : ]
        
        return False if hashlib.new('md5', plain).digest() != mac else True

    def encrypt_cipher_block(self, data):
        '''@param: data
        - create random 16 byte i-vector (iv) for initiating encryption
        - encrypt data block by block where last encrypted block is used as iv (and we save the iv for first block)
        - return the encrypted data
        '''

        self.iv = SSLv3.get_random_bytes(self.b_length)
        
        iv = self.iv
        cipher_data = []
        for b in self.fragment_blocks(data):
            cipher = AES.new(self.cipher_key, AES.MODE_CBC, iv=iv).encrypt(b)
            cipher_data.append(cipher)
            iv = cipher
        return b''.join(cipher_data)

    def decrypt_cipher_block(self, data):
        ''' @param: encrypted data
        - decrypt the data block by block in backwards manner using iv as encrypted previous block
        (where last block will have saved iv from encryption)
        - return reversed decrypted data
        '''

        plain_data = []

        blocks = self.fragment_blocks(data)
        for i in range(len(blocks)-1, -1, -1):
            iv = self.iv if i==0 else blocks[i-1]
            plain_data.append(AES.new(self.cipher_key, AES.MODE_CBC, iv=iv).decrypt(blocks[i]))

        plain_data.reverse()
        return b''.join(plain_data)

class Attack:
    '''Handle the Poodle vulnerability attack'''
    def __init__(self, poodle=None):
        # save poodle instance
        self.poodle = poodle

    def pad_full_block(self, enc_data):
        '''add X character in data until a full padded block is obtained as last block'''

        add = b''
        curr_len = len(enc_data)
        while True:
            if curr_len != len(enc_data):
                return enc_data, add
            add += b'X'
            enc_data = self.poodle.client(add, 0)

    def perform_attack(self, enc_data):
        ''' @param: enc_data
        - start from 2nd block till 2nd-last block (exclusive) where the data is present (design choice)
        - attack block by block and return collected decrypted data
        '''

        enc_data, add = self.pad_full_block(enc_data)
        dec_text = b''
        for i in range(1, (len(enc_data) // self.poodle.b_length)-2):
            dec_text += self.poodle.block_decryption(add, i)
        return dec_text

class Poodle:
    '''Simulate the attacker using poodle vulnerability'''

    def __init__(self, data=None, b_length=16):
        self.data, self.b_length = data, b_length

    def change_request(self, add=b'', strip=0):
        '''@param: add <- add these bytes in request
                 : strip <- strip these bytes from data
        - Request is assumed to utilize this structure:
        - GET / <here-we-add-data> HTTPS/1.1 <data-that-we-want-to-take>
        - return: updated request
        '''

        return  b'GET /' + add + b' HTTPS/1.1 ' + self.data[:len(self.data) - strip] 

    def client(self, add=b'', strip=0):
        '''@param: add <- add these bytes in request
                 : strip <- strip these bytes from data
        - create a sslv3 client
        - simulating client: return the encrypted data after changing request
        '''

        self.ssl = SSLv3(self.b_length)
        return self.ssl.encrypt_data(self.change_request(add, strip))

    def server(self, enc_data):
        '''@param: enc_data <- encrypted data
        - simulating server: return boolean whether if encrypted data is accepted by the server
        '''

        return self.ssl.decrypt_data(enc_data)

    def block_decryption(self, add, b_index):
        '''
        function to decrypt one block (say X) at a time:
        - target 1st byte of the block need to be decrypted:
            - intercept the encrypted data coming from client
            - modify it making it such as the last full block is padded block
            - replace the last block with X block and send to server
            - if rejected, repeat the process each time new last byte is encrypted
                - else: accepted -> we have successfuly decrypted the byte
            - move to next byte by adding one byte in request
        - return the decrypted block 
        '''

        print("[#] Block: {}".format(b_index))

        plain = []
        _range = None
        if b_index == 1:
            _range = self.b_length - len(add)
        else:
            _range  = self.b_length

        for b in range(_range):
            count = 0
            while True:
                count += 1
                cip = self.client(add + b'x'* b, b)
                new_cip = cip[:-self.b_length] + cip[b_index*self.b_length: b_index*self.b_length+self.b_length]
                if self.server(new_cip):
                   break

            new_blocks = self.ssl.fragment_blocks(new_cip)
            val = new_blocks[b_index-1][-1] ^ 15 ^ new_blocks[len(new_blocks)-2][-1]
            print("\t[*] #{} byte | attempts - {} decode: {}".format(b, count, bytes([val])))

            plain.append(bytes([val]))
        plain.reverse()

        print("[*] Decrypted Block: {}\n".format(str(b''.join(plain))))
        return b''.join(plain)

if __name__ == '__main__':
    '''if data is given by CLI use it else use the harcoded one'''

    import sys
    
    data = None
    try:
        data = bytes(str(sys.argv[1]), 'utf-8')
    except:
        data = bytes('Cryptography Assignment 3 by Ankit', 'utf-8')
    print("[?] Secret data: ", data.decode())   
    
    attack = Attack(Poodle(data))
    encoded_data = attack.poodle.client()
    
    dec = attack.perform_attack(encoded_data)
    print("[$] Decrypted data: ", dec.decode('utf-8'))