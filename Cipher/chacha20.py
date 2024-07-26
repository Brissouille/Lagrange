from z3 import *
from copy import deepcopy

class Chacha20():
    
    def __init__(self, prefix="message"):
        self.state = [0] * 4
        for j in range(4):
            self.state[j] = BitVecs(["state" + "_%02d_%02d" %(j, i) for i in range(4)], 32)

        self.const   = self.state[0]
        self.key     = [self.state[1], self.state[2]]
        self.counter = [self.state[3][0], self.state[3][1]]
        self.nonce   = [self.state[3][2], self.state[3][3]]
        

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
        state_tmp = deepcopy(self.state)
        
        for i in range(10):
            # Odd round
            state_tmp[0][0], state_tmp[1][0], state_tmp[2][0], state_tmp[3][0] = self.quarter_round(state_tmp[0][0], state_tmp[1][0], state_tmp[2][0], state_tmp[3][0])
            state_tmp[0][1], state_tmp[1][1], state_tmp[2][1], state_tmp[3][1] = self.quarter_round(state_tmp[0][1], state_tmp[1][1], state_tmp[2][1], state_tmp[3][1])
            state_tmp[0][2], state_tmp[1][2], state_tmp[2][2], state_tmp[3][2] = self.quarter_round(state_tmp[0][2], state_tmp[1][2], state_tmp[2][2], state_tmp[3][2])
            state_tmp[0][3], state_tmp[1][3], state_tmp[2][3], state_tmp[3][3] = self.quarter_round(state_tmp[0][3], state_tmp[1][3], state_tmp[2][3], state_tmp[3][3])
             
            # Even round
            state_tmp[0][0], state_tmp[1][1], state_tmp[2][2], state_tmp[3][3] = self.quarter_round(state_tmp[0][0], state_tmp[1][1], state_tmp[2][2], state_tmp[3][3])
            state_tmp[0][1], state_tmp[1][2], state_tmp[2][3], state_tmp[3][0] = self.quarter_round(state_tmp[0][1], state_tmp[1][2], state_tmp[2][3], state_tmp[3][0])
            state_tmp[0][2], state_tmp[1][3], state_tmp[2][0], state_tmp[3][1] = self.quarter_round(state_tmp[0][2], state_tmp[1][3], state_tmp[2][0], state_tmp[3][1])
            state_tmp[3][0], state_tmp[1][0], state_tmp[1][2], state_tmp[3][2] = self.quarter_round(state_tmp[3][0], state_tmp[1][0], state_tmp[1][2], state_tmp[3][2])

        for i in range(4):
            for j in range(4):
                state_tmp[i][j] ^= self.state[i][j]

        self.state = state_tmp


    def quarter_round(self, a, b, c, d):
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
        return a, b, c, d

    def encrypt(self, key, nonce, counter, plain):
        assert(len(key) == 2 * 32)
        
        # We iterate on 8 key blocks
        for i in range(0, len(key), 8):
            self.s.add( int(key[i:i+8],16) == self.key[i//32][(i//8)%4] )

        plain_len = len(plain) // 2

        assert(plain_len <= 32)

        plaintext = BitVecs(["plain_%02d" %(i) for i in range(plain_len)], 8)

        ciphertext = BitVecs(["cipher_%02d" %(i) for i in range(plain_len)], 8)
        
        for i in range(0, plain_len, 4):
            word_plain = Concat(plaintext[i:i+4])
            for j in range(0, 4):
                self.s.add((plaintext[i+j]) == int(plain[2*(i+j):2*(i+j+1)]))
            word_cipher = word_plain ^ self.state[i//16][i//4]
            self.s.add(word_cipher == Concat(ciphertext[i:i+4]))
       
        print(self.s)
        if (self.s.check() == sat):
            print("Encryption")
            print(self.s.model())
        

            

a = Chacha20()
a.encrypt("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F", "0102030405060708")
