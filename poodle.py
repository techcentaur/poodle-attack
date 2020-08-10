import code

class PoodleAttack:
    def __init__(self, data=None, b_length=16):
        self.data, self.b_length = data, b_length

    def change_path(self, add=b'', strip=0):
        return  b'GET /' + add + b' HTTPS/1.1 ' + self.data[:len(self.data) - strip] 

    def client(self, add=b'', strip=0):
        self.ssl = code.SSLv3(self.b_length)
        return self.ssl.encrypt_data(self.change_path(add, strip))

    def server(self, enc_data):
        return self.ssl.decrypt_data(enc_data)

    def pad_full_block(self, enc_data):
        add = b''
        curr_len = len(enc_data)
        while True:
            if curr_len != len(enc_data):
                return enc_data, add
            add += b'A'
            enc_data = self.client(add=add, strip=0)

    def attack(self, enc_data):
        enc_data, add = self.pad_full_block(enc_data)
        dec_text = b''
        for i in range(1, (len(enc_data) // self.b_length)-2):
            dec_text += self.block_decryption(add, i)
        return dec_text

    def block_decryption(self, add, b_index):
        print("[#] Block: {}".format(b_index))

        plain = []
        limit = self.b_length - len(add) if b_index == 1 else self.b_length
        for b in range(limit):
            count = 0
            while True:
                count += 1
                cip = self.client(add + b'a'* b, b)
                new_cip = cip[:-self.b_length] + cip[b_index*self.b_length: b_index*self.b_length+self.b_length]
                if self.server(new_cip):
                   break

            new_blocks = self.ssl.fragment_blocks(new_cip)
            val = new_blocks[b_index-1][-1] ^ 15 ^ new_blocks[len(new_blocks)-2][-1]
            print("\t[*] Byte: #{} Attempts - {} Decoding: {}".format(b, count, bytes([val])))

            plain.append(bytes([val]))
        plain.reverse()

        print("[*] Decrypted Block: {}\n".format(str(b''.join(plain))))
        return b''.join(plain)

if __name__ == '__main__':
    data = bytes('This is Cryptography Assignment 3', 'utf-8')
    
    pattack = PoodleAttack(data)
    encoded_data = pattack.client()
    print("Data: ", data.decode())   
    
    dec = pattack.attack(encoded_data)
    print("Decrypted data: ", dec)
