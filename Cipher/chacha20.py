from z3 import *
from copy import deepcopy

class Chacha20():

    def __init__(self, prefix="message"):
        self.Nr = 10
        ## We store the initial state, the round state (after quarter round) and the final state
        self.state = [0] * (self.Nr + 2)
        for k in range(self.Nr+2):
            self.state[k] = [0] * 4
            for j in range(4):
                if (k == 0):
                    self.state[k][j] = BitVecs(["state" + "_%02d_%02d" %(j, i) for i in range(4)], 32)
                else:
                    self.state[k][j] = [0] * 4

        self.const   = self.state[0][0]
        self.key     = [self.state[0][1], self.state[0][2]]
        self.counter = self.state[0][3][0]
        self.nonce   = [self.state[0][3][1], self.state[0][3][2], self.state[0][3][3]]

        self.plaintext = BitVecs([prefix+"_%02d" %(i) for i in range(512)], 8)

        self.ciphertext = BitVecs(["cipher_%02d" %(i) for i in range(512)], 8)

        self.s = Chacha20.resetSolver(self)
        
        self.encryption()



    def resetSolver(self):
        s = Solver()
        """ Create a Solver and init with the const value of the state """

        s.add(self.const[0] == int.from_bytes(b"expa", "little"))
        s.add(self.const[1] == int.from_bytes(b"nd 3", "little"))
        s.add(self.const[2] == int.from_bytes(b"2-by", "little"))
        s.add(self.const[3] == int.from_bytes(b"te k", "little"))


        return s

    def encryption(self):

        for l in range(1, self.Nr+1):
            # We copy the initial state from index 0,
            # So the odd/even round are inverted with l
            self.state[l] = deepcopy(self.state[l-1])

            self.quarter_round(l, 0, 4, 8, 12)
            self.quarter_round(l, 1, 5, 9, 13)
            self.quarter_round(l, 2, 6, 10, 14)
            self.quarter_round(l, 3, 7, 11, 15)

            self.quarter_round(l, 0, 5, 10, 15)
            self.quarter_round(l, 1, 6, 11, 12)
            self.quarter_round(l, 2, 7,  8, 13)
            self.quarter_round(l, 3, 4,  9, 14)

        # Final step : Addition with the initial state
        for i in range(4):
            for j in range(4):
                self.state[-1][i][j] = self.state[-2][i][j] + self.state[0][i][j] 

        self.keystream = [0] * 4
        # Create keystream from final state
        for i in range(4):
            self.keystream[i] = [0] * 4
            for j in range(4):
                # We start by the shifting >> 24 extends the sign bit
                # So 0x000000ff remove this side effect
                self.first_byte  = ((self.state[-1][i][j] << 24) & 0xff000000)
                self.second_byte = ((self.state[-1][i][j] << 8)  & 0x00ff0000)
                self.third_byte  = ((self.state[-1][i][j] >> 8)  & 0x0000ff00)
                self.fourth_byte = ((self.state[-1][i][j] >> 24) & 0x000000ff)
                self.keystream[i][j] = self.first_byte ^ self.second_byte ^ self.third_byte ^ self.fourth_byte
        
        for i in range(0, 64, 4):
            # Put in equation the encryption
            word_plain = Concat(self.plaintext[i:i+4])
            word_cipher = word_plain ^ self.keystream[i//16][i%4]
            self.s.add(word_cipher == Concat(self.ciphertext[i:i+4]))
        
            # Put in equation the decryption
            word_cipher = Concat(self.ciphertext[i:i+4])
            word_plain = word_cipher ^ self.keystream[i//16][i%4]
            self.s.add(word_plain == Concat(self.plaintext[i:i+4]))

    def quarter_round(self, l, index_a, index_b, index_c, index_d):

        a = self.state[l][index_a // 4][index_a % 4]
        b = self.state[l][index_b // 4][index_b % 4]
        c = self.state[l][index_c // 4][index_c % 4]
        d = self.state[l][index_d // 4][index_d % 4]

        a = a + b
        d = d ^ a
        d = RotateLeft(d, 16)
        c = c + d
        b = b ^ c
        b = RotateLeft(b, 12)
        a = a + b
        d = d ^ a
        d = RotateLeft(d, 8)
        c = c + d
        b = b ^ c
        b = RotateLeft(b, 7)

        self.state[l][index_a // 4][index_a % 4] = a
        self.state[l][index_b // 4][index_b % 4] = b
        self.state[l][index_c // 4][index_c % 4] = c
        self.state[l][index_d // 4][index_d % 4] = d

    def reset(self):
        """ reset the solver of the class """
        self.s.reset()
        self.s = Chacha20.resetSolver(self)
        self.encryption()

    def addMessage(self, message, message_len):
        for i in range(0, message_len, 4):
            word_plain = Concat(self.plaintext[i:i+4])
            for j in range(0, 4):
                self.s.add((self.plaintext[i+j]) == int(message[2*(i+j):2*(i+j+1)], 16))

    def addCipher(self, cipher, cipher_len):
        for i in range(0, cipher_len, 4):
            word_cipher = Concat(self.ciphertext[i:i+4])
            for j in range(0, 4):
                self.s.add((self.ciphertext[i+j]) == int(cipher[2*(i+j):2*(i+j+1)], 16))

    def addNonce(self, nonce, nonce_len):
        for i in range(0, nonce_len, 8):
            # Convert 4 bytes into int (ex 00:01:02:03 -> 03020100)
            nonce_tmp = int(nonce[i:i+8], 16)
            nonce_tmp = int.from_bytes(nonce_tmp.to_bytes(4, "little"), "big")
            self.s.add(self.nonce[i//8] == nonce_tmp)

    def addCounter(self, counter, counter_len):
        for i in range(0, counter_len, 8):
            # No need to convert into little endian
            counter_tmp = int(counter[i:i+8], 16)
            self.s.add(self.counter == counter_tmp)

    def encrypt(self, key, nonce, counter, plain):
        assert(len(key) == 2 * 32)

        plain_len = len(plain) // 2
        assert(plain_len <= (2 * 32))

        counter_len = len(counter)
        assert(counter_len == 8)

        nonce_len = len(nonce)
        assert(nonce_len == 24)

        # We iterate on 8 key blocks
        for i in range(0, len(key), 8):
            # Convert 4 bytes into little endian int (ex 00:01:02:03 -> 03020100)
            key_tmp = int(key[i:i+8], 16)
            key_tmp = int.from_bytes(key_tmp.to_bytes(4, "little"), "big")
            self.s.add( key_tmp == self.key[i//32][(i//8)%4] )

        self.addMessage(plain, plain_len)

        self.addCounter(counter, counter_len)

        self.addNonce(nonce, nonce_len)

        if (self.s.check() == sat):
            print("Encryption")
            print("#"*10)
            for i in range(plain_len):
                print("{:02x}".format(int(str(self.s.model().evaluate(self.plaintext[i])))), end=' ')
            print()

            print("#"*10)
            for i in range(plain_len):
                print("{:02x}".format(int(str(self.s.model().evaluate(self.ciphertext[i])))), end=' ')
            print()

    def decrypt(self, key, nonce, counter, cipher):
        assert(len(key) == 2 * 32)

        cipher_len = len(cipher) // 2
        assert(cipher_len <= 2 * 32)

        counter_len = len(counter)
        assert(counter_len == 8)

        nonce_len = len(nonce)
        assert(nonce_len == 24)

        # We iterate on 8 key blocks
        for i in range(0, len(key), 8):
            # Convert 4 bytes into little endian int (ex 00:01:02:03 -> 03020100)
            key_tmp = int(key[i:i+8], 16)
            key_tmp = int.from_bytes(key_tmp.to_bytes(4, "little"), "big")
            self.s.add( key_tmp == self.key[i//32][(i//8)%4] )

        self.addCipher(cipher, cipher_len)

        for i in range(0, counter_len, 8):
            # No need to convert into little endian
            counter_tmp = int(counter[i:i+8], 16)
            self.s.add(self.counter == counter_tmp)

        for i in range(0, nonce_len, 8):
            # Convert 4 bytes into int (ex 00:01:02:03 -> 03020100)
            nonce_tmp = int(nonce[i:i+8], 16)
            nonce_tmp = int.from_bytes(nonce_tmp.to_bytes(4, "little"), "big")
            self.s.add(self.nonce[i//8] == nonce_tmp)

        if (self.s.check() == sat):
            print("Decryption")
            print("#"*10)
            for i in range(cipher_len):
                print("{:02x}".format(int(str(self.s.model().evaluate(self.ciphertext[i])))), end=' ')
            print()

            print("#"*10)
            for i in range(cipher_len):
                print("{:02x}".format(int(str(self.s.model().evaluate(self.plaintext[i])))), end=' ')
            print()



a = Chacha20()
a.encrypt("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "000000000000004a00000000", "00000001", "4c61646965732061")
a.reset()
a.decrypt("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "000000000000004a00000000", "00000001", "f1b784f8b7c598cf")
a.reset()

