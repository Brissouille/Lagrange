from z3 import *
from .aes import Aes
from .model import Model

class Aes_Cbc():
    def __init__(self, keylength, size_message): 
        # Init the solver
        self.s = Solver()

        # The message must be a mutliple of 16 bytes
        assert((size_message!=0)%16)
        self.blocks = size_message // 16
        
        # Init message in CBC
        self.message = [0] * self.blocks

        # Aes list
        self.aes = [0] * self.blocks
              
        # Init iv and first message
        self.iv = [0] * 4
        self.message[0] = [0] * 4
        for i in range(4):
            self.iv[i] = [0] * 4
            for j in range(4):
                self.iv[i][j] = BitVec("iv_%02d_%02d" %(i, j), 8)

        # Init message
        for b in range(0, self.blocks):
            # Init message of the Aes_Cbc class
            self.message[b] = [0] * 4

            # Init each Aes with a different plaintext name
            self.aes[b] = Aes(keylength, "m"+str(b))

            # We init mi in the Aes class by the Mi ^ Ci-1 in the Aes_Cbc class
            for i in range(4):
                self.message[b][i] = [0] * 4
                for j in range(4):
                    self.message[b][i][j] = BitVec("M%02d_%02d_%02d" %(b, i, j), 8)
       
        self.reset()

    def check(self):
        self.s.check()
        for b in range(self.blocks):
            for i in range(4):
                for j in range(4):
                    print("{:02x}".format(int(str(self.s.model().evaluate(self.aes[b].cipher[i][j])))), end='')
        print()

    def addIv(self, iv):
        for i in range(4):
            for j in range(4):
                self.s.add(self.iv[i][j]==int(iv[2*(4*i+j):2*(4*i+j+1)], 16))
    
    def addMessage(self, value):
        for b in range(self.blocks):
            for i in range(4):
                for j in range(4):
                    self.s.add(self.message[b][i][j]==int(value[2*(i*4+j):2*(i*4+j+1)],16))

    def encrypt(self, key, plaintext, iv):
        plain_len = len(plaintext)

        # We padd with zeroes bytes
        padding = "0"*(32 - (plain_len % 32) % 32)
        plaintext = plaintext + padding

        # Init iv in solver
        self.addIv(iv)

        # Add message in the solver
        self.addMessage(plaintext)

        # Add the key in one aes -> all aes are impacted
        for i in range(0, self.aes[0].Nk):
            for j in range(0, 4):
                self.aes[0].addPartialKey(i//4, i, j, int(key[2*(i*4+j):2*(i*4+j+1)], 16))

        self.check()

    def decrypt(self, cipher):
        pass

    def resetSolver(self):
        s = Solver()
        s.reset()
        
        # Init only Sbox 
        s.add(self.aes[0].s.assertions())

        for i in range(4):
            for j in range(4):
                s.add(self.aes[0].message[i][j] == self.message[0][i][j] ^ self.iv[i][j])

        # We add all the assertions of the other system of equation
        for b in range(1, self.blocks):
            self.aes[b].s.reset()
            for i in range(4):
                for j in range(4):
                    s.add(self.aes[b].message[i][j] == self.message[b][i][j] ^ self.aes[b-1].cipher[i][j])
        return s
            
    def reset(self):
        self.s = Aes_Cbc.resetSolver(self)
