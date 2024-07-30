from z3 import *
from copy import deepcopy

class Chacha20():
    
    def __init__(self, prefix="message"):
        self.Nr = 10
        self.state = [0] * (self.Nr + 1)
        for k in range(self.Nr+1):
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
            # So the odd/even round are inverted
            self.state[l] = deepcopy(self.state[l-1])

            self.quarter_round(l, 0, 4, 8, 12)
            self.quarter_round(l, 1, 5, 9, 13)
            self.quarter_round(l, 2, 6, 10, 14)
            self.quarter_round(l, 3, 7, 11, 15)
                         
            self.quarter_round(l, 0, 5, 10, 15)
            self.quarter_round(l, 1, 6, 11, 12)
            self.quarter_round(l, 2, 7,  8, 13)
            self.quarter_round(l, 3, 4,  9, 14)

        for i in range(4):
            for j in range(4):
                self.state[-1][i][j] = self.state[-2][i][j] + self.state[0][i][j]

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

    def encrypt(self, key, nonce, counter, plain):
        assert(len(key) == 2 * 32)
        
        # We iterate on 8 key blocks
        for i in range(0, len(key), 8):
            # Convert 4 bytes into int (ex 00:01:02:03 -> 03020100)
            key_tmp = int(key[i:i+8], 16)
            key_tmp = int.from_bytes(key_tmp.to_bytes(4, "little"), "big")
            self.s.add( key_tmp == self.key[i//32][(i//8)%4] )

        plain_len = len(plain) // 2

        assert(plain_len <= 32)

        plaintext = BitVecs(["plain_%02d" %(i) for i in range(plain_len)], 8)
        
        ciphertext = BitVecs(["cipher_%02d" %(i) for i in range(plain_len)], 8)
        
        for i in range(0, plain_len, 4):
            word_plain = Concat(plaintext[i:i+4])
            for j in range(0, 4):
                self.s.add((plaintext[i+j]) == int(plain[2*(i+j):2*(i+j+1)]))
            word_cipher = word_plain ^ self.state[-1][i//16][i//4]
            self.s.add(word_cipher == Concat(ciphertext[i:i+4]))
        
        assert(len(counter) == 8)
        counter_len = len(counter)

        for i in range(0, counter_len, 8):
            # No need to convert into little endian
            counter_tmp = int(counter[i:i+8], 16)
            self.s.add(self.counter == counter_tmp)

        assert(len(nonce) == 24)
        nonce_len = len(nonce)

        for i in range(0, nonce_len, 8):
            # Convert 4 bytes into int (ex 00:01:02:03 -> 03020100)
            nonce_tmp = int(nonce[i:i+8], 16)
            nonce_tmp = int.from_bytes(nonce_tmp.to_bytes(4, "little"), "big")
            self.s.add(self.nonce[i//8] == nonce_tmp)

        if (self.s.check() == sat):
            print("Encryption")
            for i in range(4):
                for j in range(4):
                    print("{:08x}".format(int(str(self.s.model().evaluate(self.state[0][i][j])))), end=' ')
                print()
            print("#"*10)
            for i in range(4):
                for j in range(4):
                    print("{:08x}".format(int(str(self.s.model().evaluate(self.state[-1][i][j])))), end=' ')
                print()
        

            

a = Chacha20()
a.encrypt("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "000000090000004a00000000", "00000001", "00"*8)
