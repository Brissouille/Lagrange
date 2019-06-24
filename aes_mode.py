from z3 import *
from .aes import Aes
from .model import Model

class Aes_Mode():
    def __init__(self, keylength, size_message): 
        # Init the solver
        self.s = Solver()

        # The message must be a mutliple of 16 bytes
        assert((size_message!=0)%16)
        self.blocks = size_message // 16
        
        # Init message and cipher
        self.message = [0] * self.blocks
        self.cipher = [0] * self.blocks

        # Aes list
        self.aes = [0] * self.blocks
              
        # Init iv and first message
        self.iv = [0] * 4
        for i in range(4):
            self.iv[i] = [0] * 4
            for j in range(4):
                self.iv[i][j] = BitVec("iv_%02d_%02d" %(i, j), 8)

        self.message[0] = [0] * 4
        self.cipher[0] = [0] * 4
        # Init message
        for b in range(0, self.blocks):
            # Init message and cipher of the Aes_Cbc class
            self.message[b] = [0] * 4
            self.cipher[b] = [0] * 4

            # Init each Aes with a different plaintext name
            self.aes[b] = Aes(keylength, "m"+str(b))

            # We init mi in the Aes class by the Mi ^ Ci-1 in the Aes_Cbc class
            for i in range(4):
                self.message[b][i] = [0] * 4
                self.cipher[b][i] = [0] * 4
                for j in range(4):
                    self.message[b][i][j] = BitVec("M%02d_%02d_%02d" %(b, i, j), 8)
                    self.cipher[b][i][j] = BitVec("C%02d_%02d_%02d" %(b, i, j), 8)
       
        self.reset()

    def check(self):
        sat_resp = self.s.check()
        for b in range(self.blocks):
            for i in range(4):
                for j in range(4):
                    print("{:02x}".format(int(str(self.s.model().evaluate(self.cipher[b][i][j])))), end='')
            print('', end=' ')
        print()

    def addIv(self, iv):
        for i in range(4):
            for j in range(4):
                self.s.add(self.iv[i][j]==int(iv[2*(4*i+j):2*(4*i+j+1)], 16))
    
    def addMessage(self, value):
        for b in range(self.blocks):
            for i in range(4):
                for j in range(4):
                    self.s.add(self.message[b][i][j]==int(value[2*(b*16+i*4+j):2*(b*16+i*4+j+1)],16))

    def encrypt(self, key, plaintext, iv):
        self.reset()
        plain_len = len(plaintext)

        padding = "0" * (self.blocks * 32 - plain_len)

        # We padd with zeroes bytes
        plaintext = plaintext + padding

        # Init iv in solver
        self.addIv(iv)

        # Add message in the solver
        self.addMessage(plaintext)

        # Add the key in one aes -> all aes are impacted
        for i in range(0, self.aes[0].Nk):
            for j in range(0, 4):
                self.aes[0].addPartialKey(i//4, i%4, j, int(key[2*(i*4+j):2*(i*4+j+1)], 16))

        # Before to check, we agregate the solver of the Aes class and the solver of the Aes_Cbc class
        for b in range(self.blocks):
            self.s.add(self.aes[b].s.assertions())
        self.check()

    def addCipher(self, value):
        for b in range(self.blocks):
            for i in range(4):
                for j in range(4):
                    self.s.add(self.cipher[b][i][j] == int(value[2*(b*16+i*4+j):2*(b*16+i*4+j+1)],16))

    def decrypt(self, key, ciphertext, iv):
        pass

    def resetSolver(self):
        s = Solver()
        s.reset()
       
        # reset aes blocks
        for b in range(self.blocks):
            self.aes[b].reset()

        # Init only Sbox 
        s.add(self.aes[0].s.assertions())

        # Init the mode for the Aes
        self.init_mode(s)

        return s
            
    def reset(self):
        self.s = Aes_Mode.resetSolver(self)

    def init_mode(self, s):
        raise Excpetion('Abstract method init_mode called')
