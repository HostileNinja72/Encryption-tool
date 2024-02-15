from tqdm import tqdm



class ChaCha20:
    def __init__(self, key, nonce):
        self.original_state = [
            0x61707865, 0x3320646E, 0x79622D32, 0x6B206574,
            *self._to_word_array(key),
            *self._to_word_array(nonce, length=3),
            0
        ]
        self.state = self.original_state.copy()

    def _reset_state(self):
            self.state = self.original_state.copy()
    @staticmethod
    def _to_word_array(byte_arr, length=8):
        arr = []
        for i in range(0, length * 4, 4):
            arr.append(int.from_bytes(byte_arr[i:i + 4], byteorder='little'))
        return arr

    @staticmethod
    def _quarter_round(x, a, b, c, d):
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF
        x[d] = ChaCha20._rotate_left(x[d] ^ x[a], 16)
        x[c] = (x[c] + x[d]) & 0xFFFFFFFF
        x[b] = ChaCha20._rotate_left(x[b] ^ x[c], 12)
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF
        x[d] = ChaCha20._rotate_left(x[d] ^ x[a], 8)
        x[c] = (x[c] + x[d]) & 0xFFFFFFFF
        x[b] = ChaCha20._rotate_left(x[b] ^ x[c], 7)


    @staticmethod
    def _rotate_left(val, n):
        return ((val << n) & 0xFFFFFFFF) | (val >> (32 - n))

    def _chacha_block(self):
        x = self.state.copy()
        for _ in range(10):
            # Column rounds
            self._quarter_round(x, 0, 4,  8, 12)
            self._quarter_round(x, 1, 5,  9, 13)
            self._quarter_round(x, 2, 6, 10, 14)
            self._quarter_round(x, 3, 7, 11, 15)
            # Diagonal rounds
            self._quarter_round(x, 0, 5, 10, 15)
            self._quarter_round(x, 1, 6, 11, 12)
            self._quarter_round(x, 2, 7,  8, 13)
            self._quarter_round(x, 3, 4,  9, 14)
        for i in range(16):
            x[i] = (x[i] + self.state[i]) & 0xFFFFFFFF
        self.state[12] = (self.state[12] + 1) & 0xFFFFFFFF
        if self.state[12] == 0:
            self.state[13] = (self.state[13] + 1) & 0xFFFFFFFF
        return x
    

    def encrypt(self, plaintext):
        # Reset the state (including the counter) for a fresh operation
        self._reset_state()

        block_size = 64
        encrypted = b''
        for i in tqdm(range(0, len(plaintext), block_size), desc ="Encryption/Decryption using ChaCha20", ):
            block = plaintext[i:i + block_size]
            keystream = self._chacha_block()
            keystream_bytes = b''.join(word.to_bytes(4, byteorder='little') for word in keystream)
            encrypted_block = bytes(a ^ b for a, b in zip(block, keystream_bytes[:len(block)]))
            encrypted += encrypted_block
        return encrypted



