import secrets
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor

magenta = "\u001b[35m"
RESET = "\033[0m"


Sbox = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

InvSbox = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)


# learnt from http://cs.ucsb.edu/~koc/cs178/projects/JT/aes.c
xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)


Rcon = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
)


def text2matrix(text):
    matrix = []
    for i in range(16):
        byte = (text >> (8 * (15 - i))) & 0xFF
        if i % 4 == 0:
            matrix.append([byte])
        else:
            matrix[i // 4].append(byte)
    return matrix


def matrix2text(matrix):
    text = 0
    for i in range(4):
        for j in range(4):
            text |= (matrix[i][j] << (120 - 8 * (4 * i + j)))
    return text

def generate_random(l):
    # AES requires a 16-byte IV
    return secrets.token_bytes(l)


class AES:
    def __init__(self, master_key, mode=None, iv=None, nonce=None):
        self.change_key(master_key) #round keys
        self.iv = iv  #initiate iv if its parsed from the constructor
        self.nonce = nonce #same here
        # making sure that the chosed mode exists, thoe already handle_argv does this
        if mode not in ["ECB","CBC", "CTR", "GCM", None]:
            raise ValueError("Invalid mode. Supported modes are 'CBC' and 'CTR'") 
        self.mode = mode;
        # if the values are not initialized by the user, we generate them using the secrets module
        if self.mode == "CBC" and self.iv == None:
            self.iv = generate_random(16)
            print("The generated iv is: " + str(self.iv.hex()))
        if self.mode == "CTR" and self.nonce == None:
            self.nonce = generate_random(16)
            print("The generated nonce is " + str(self.nonce.hex()))
        if self.mode == "GCM" and self.iv == None:
            self.iv = generate_random(12)
            print("The generated nonce is " + str(self.iv.hex()))

    def set_key(self, key):
        self.change_key(key)

    def get_iv(self):
        if self.mode == "CTR":
            return self.nonce
        elif self.mode == "CBC":
            return self.iv
    
    #generate the round keys
    def change_key(self, master_key):
        self.round_keys = text2matrix(master_key)
        # print self.round_keys

        for i in range(4, 4 * 11):
            self.round_keys.append([])
            if i % 4 == 0:
                byte = self.round_keys[i - 4][0]        \
                     ^ Sbox[self.round_keys[i - 1][1]]  \
                     ^ Rcon[i // 4]
                self.round_keys[i].append(byte)

                for j in range(1, 4):
                    byte = self.round_keys[i - 4][j]    \
                         ^ Sbox[self.round_keys[i - 1][(j + 1) % 4]]
                    self.round_keys[i].append(byte)
            else:
                for j in range(4):
                    byte = self.round_keys[i - 4][j]    \
                         ^ self.round_keys[i - 1][j]
                    self.round_keys[i].append(byte)

        # print self.round_keys

   

    #encryption
    def encrypt(self, plaintext):
        if self.mode == None:
            self.__status()
            return self.__encrypt_16bits(plaintext)
        if self.mode == 'CBC':
            self.__status()
            return self.__encrypt_cbc(plaintext)
        if self.mode == 'CTR':
            self.__status()
            return self.__encrypt_ctr(plaintext)
        if self.mode == 'GCM':
            return self.__encrypt_gcm(plaintext)
        if self.mode == 'ECB':
            print("\033[91mWARNING: AES-ECB is not secure, use it just for testing purposes\033[0m")
            return self.__encrypt_ecb(plaintext)


    def __encrypt_16bits(self, plaintext):
        self.plain_state = text2matrix(plaintext)

        self.__add_round_key(self.plain_state, self.round_keys[:4])

        for i in range(1, 10):
            self.__round_encrypt(self.plain_state, self.round_keys[4 * i : 4 * (i + 1)])

        self.__sub_bytes(self.plain_state)
        self.__shift_rows(self.plain_state)
        self.__add_round_key(self.plain_state, self.round_keys[40:])

        return matrix2text(self.plain_state)
    
    # AES Counter mode
    def __encrypt_ctr(self, plaintext):
        block_size = 16
        plaintext_bytes = plaintext.to_bytes((plaintext.bit_length() + 7) // 8, byteorder='big')
        num_blocks = (len(plaintext_bytes) + block_size - 1) // block_size
        ciphertext = b''
        if not hasattr(self, 'nonce'):
            self.nonce = generate_random(16)
        for i in tqdm(range(num_blocks), desc='Encrypting (CTR)', ncols=110):
            counter = self.nonce + i.to_bytes(8, byteorder='big') # 64-bit counter (8 bytes)
            keystream = self.__encrypt_16bits(int(counter.hex(), 16)).to_bytes(16, byteorder='big')
            
            
            start = i * block_size
            end = start + block_size

            # Extract the block
            block = plaintext_bytes[start:end]
            
            # XOR the block with the keystream
            encrypted_block = bytes(a ^ b for a, b in zip(block, keystream))

            ciphertext += encrypted_block

        return ciphertext
    
    #AES cipher block chaining
    def __encrypt_cbc(self, plaintext):
        block_size = 16
        previous_block = self.iv
        
        plaintext_bytes = plaintext.to_bytes((plaintext.bit_length() + 7) // 8, byteorder='big')
        num_blocks = (len(plaintext_bytes) + block_size - 1) // block_size

        ciphertext = b""
        
        for block_start in tqdm(range(num_blocks), desc='Encrypting (CBC)', ncols=110):
            block = plaintext_bytes[block_start * block_size:(block_start + 1) * block_size]
            while len(block) < block_size:
                block += b'0' 
            block = bytes(a ^ b for a, b in zip(block, previous_block))
            
            encrypted_block = self.__encrypt_16bits(int(block.hex(), 16)).to_bytes(16, byteorder='big')
            ciphertext += encrypted_block
            
            previous_block = encrypted_block

        return ciphertext


    #AES Electronic Code book
    def __encrypt_ecb(self, plaintext):
        block_size = 16
        plaintext_bytes = plaintext.to_bytes((plaintext.bit_length() + 7) // 8, byteorder='big')
        num_blocks = (len(plaintext_bytes) + block_size - 1) // block_size

        ciphertext = b''
        
        for i in tqdm(range(num_blocks), desc='Encrypting ECB', ncols=110):
            start = i*block_size
            end = start + block_size
            block = plaintext_bytes[start:end]
            while len(block) < block_size:
                block += b'0'    
            encrypted_block = self.__encrypt_16bits(int(block.hex(), 16)).to_bytes(16, byteorder='big')
            ciphertext+= encrypted_block

        return ciphertext
    

   
    

    #decryption
        
    def decrypt(self, ciphertext):
        if self.mode == None:
            return self.__decrypt_16bits(ciphertext)
        if self.mode == "CTR":
            return self.__decrypt_ctr(ciphertext)
        if self.mode == "CBC":
            return self.__decrypt_cbc(ciphertext)
        if self.mode == "GCM":
            return self.__decrypt_gcm(ciphertext)
        if self.mode == "ECB":
            print("\033[91mWARNING: AES-ECB is not secure, use it just for testing purposes\033[0m")
            return self.__decrypt_ecb(ciphertext)

    def __decrypt_16bits(self, ciphertext):
        self.cipher_state = text2matrix(ciphertext)

        self.__add_round_key(self.cipher_state, self.round_keys[40:])
        self.__inv_shift_rows(self.cipher_state)
        self.__inv_sub_bytes(self.cipher_state)

        for i in range(9, 0, -1):
            self.__round_decrypt(self.cipher_state, self.round_keys[4 * i : 4 * (i + 1)])

        self.__add_round_key(self.cipher_state, self.round_keys[:4])

        return matrix2text(self.cipher_state)
    
    def __decrypt_ctr(self, ciphertext):
        block_size = 16
        num_blocks = (len(ciphertext) + block_size - 1) // block_size

        ciphertext_bytes = ciphertext

        plaintext = b''

        for i in tqdm(range(num_blocks), desc='Decryption(CTR)', ncols=110):
            counter = self.nonce + i.to_bytes(8, byteorder='big')  # 64-bit counter (8 bytes)
            keystream = self.__encrypt_16bits(int(counter.hex(), 16)).to_bytes(16, byteorder='big')

            start = i * block_size
            end = start + block_size

            # Extract the block
            block = ciphertext_bytes[start:end]

            # XOR the block with the keystream
            decrypted_block = bytes(a ^ b for a, b in zip(block, keystream))

            plaintext += decrypted_block

        return plaintext
    
    def __decrypt_cbc(self, ciphertext):
        block_size = 16
        previous_block = self.iv
        
        num_blocks = (len(ciphertext) + block_size - 1) // block_size
        plaintext = b''

        for block_start in tqdm(range(num_blocks), desc='Decryption (CBC)', ncols=110):
            block = ciphertext[block_start * block_size:(block_start + 1) * block_size]
            
            decrypted_block = self.__decrypt_16bits(int(block.hex(), 16)).to_bytes(16, byteorder='big')
            decrypted_block_xor = bytes(a ^ b for a, b in zip(decrypted_block, previous_block))
            plaintext += decrypted_block_xor
            
            previous_block = block

        return plaintext


    def __decrypt_ecb(self, ciphertext):
        block_size = 16
        num_blocks = len(ciphertext) // block_size
        print(num_blocks)

        plaintext = b''

        for i in tqdm(range(num_blocks), desc='Decryption (ECB)', ncols=110):
            start = i * block_size
            end = start + block_size
            block = ciphertext[start:end]
            
            decrypted_block = self.__decrypt_16bits(int(block.hex(), 16)).to_bytes(16, byteorder='big')
            plaintext += decrypted_block

        return plaintext


    




    def __add_round_key(self, s, k):
        for i in range(4):
            for j in range(4):
                s[i][j] ^= k[i][j]


    def __round_encrypt(self, state_matrix, key_matrix):
        self.__sub_bytes(state_matrix)
        self.__shift_rows(state_matrix)
        self.__mix_columns(state_matrix)
        self.__add_round_key(state_matrix, key_matrix)


    def __round_decrypt(self, state_matrix, key_matrix):
        self.__add_round_key(state_matrix, key_matrix)
        self.__inv_mix_columns(state_matrix)
        self.__inv_shift_rows(state_matrix)
        self.__inv_sub_bytes(state_matrix)

    def __sub_bytes(self, s):
        for i in range(4):
            for j in range(4):
                s[i][j] = Sbox[s[i][j]]


    def __inv_sub_bytes(self, s):
        for i in range(4):
            for j in range(4):
                s[i][j] = InvSbox[s[i][j]]


    def __shift_rows(self, s):
        s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
        s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
        s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]


    def __inv_shift_rows(self, s):
        s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
        s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
        s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]

    def __mix_single_column(self, a):
        # please see Sec 4.1.2 in The Design of Rijndael
        t = a[0] ^ a[1] ^ a[2] ^ a[3]
        u = a[0]
        a[0] ^= t ^ xtime(a[0] ^ a[1])
        a[1] ^= t ^ xtime(a[1] ^ a[2])
        a[2] ^= t ^ xtime(a[2] ^ a[3])
        a[3] ^= t ^ xtime(a[3] ^ u)


    def __mix_columns(self, s):
        for i in range(4):
            self.__mix_single_column(s[i])


    def __inv_mix_columns(self, s):
        # see Sec 4.1.3 in The Design of Rijndael
        for i in range(4):
            u = xtime(xtime(s[i][0] ^ s[i][2]))
            v = xtime(xtime(s[i][1] ^ s[i][3]))
            s[i][0] ^= u
            s[i][1] ^= v
            s[i][2] ^= u
            s[i][3] ^= v

        self.__mix_columns(s)

    def __status(self):
        print(magenta + "Your plaintext is being ciphered using AES 128 bits cipher with mode "+ self.mode + RESET)

    


