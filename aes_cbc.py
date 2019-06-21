from z3 import *
from .aes import Aes
from .model import Model

class Aes_Cbc():
    def __init__(self, keylength, size_message): 
        # The message must be a mutliple of 32 bytes
        assert((size_message!=0)%32)
        self.blocks = size_message // 32
        
        # Init message in CBC
        self.message = [0] * self.blocks

        # Init iv and first message
        self.iv = [0] * 4
        self.message[0] = [0] * 4
        for i in range(4):
            self.iv[i] = [0] * 4
            self.message[0][i] = [0] * 4
            for j in range(4):
                self.iv[i][j] = BitVec("iv_%02d_%02d" %(i, j), 8)
                self.message[0][i][j] = BitVec("M0_%02d_%02d" %(i, j), 8)

        # Init the solver
        self.s = Solver()

        # Aes list
        self.aes = [0] * self.blocks
        self.aes[0] = Aes(keylength, "m0")
              
        # We init m0 in the Aes class by M0^iv in the Aes_Cbc class
        for i in range(4):
            for j in range(4):
                self.s.add(self.aes[0].message[i][j] == self.message[0][i][j] ^ self.iv[i][j])
        
        # We add the equations of Aes solver into Aes_cbc solver
        #self.s.add(self.aes[0].s.assertions())

        for b in range(1, self.blocks):
            # Init message of the Aes_Cbc class
            self.message[b] = [0] * 4

            # Init each Aes with a different plaintext name
            self.aes[b] = Aes(keylength, "m"+str(b))

            # We init mi in the Aes class by the Mi ^ Ci-1 in the Aes_Cbc class
            for i in range(4):
                self.message[b][i] = [0] * 4
                for j in range(4):
                    self.message[b][i][j] = BitVec("M%02d_%02d_%02d" %(b, i, j), 8)
                    self.s.add(self.aes[b].message[i][j] == self.message[b][i][j] ^ self.aes[b-1].message[i][j])
            
            # We add the equations of the ith Aes solver into Aes_cbc solver
            #self.s.add(self.aes[b].s.assertions())

    def check(self):
        pass

    def encrypt(self, key, plaintext, iv):
        plain_len = len(plaintext)

        # We padd with zeroes bytes
        padding = "0"+(32 - (plain_len % 32) % 32)
        plaintext = plaintext + padding

        self.addIv(iv)

        Aes.masterkey = 

        self.addMessage(plaintext)
        # self.addMessage(b, j, i, plaintext[2*(i*4+j):2*(i*4+j+1)])

    def decrypt(self, cipher):
        pass

    def resetSolver(self):
        self.s.reset()
        
        # Init only Sbox 
        self.s.add(self.aes[0].s.assertions())

        for i in range(4):
            for j in range(4):
                # We init the message with iv in the sovler
                self.s.add(self.aes[0].message[i][j] == self.message[0][i][j] ^ self.iv[i][j])
        
                # We add all the assertions of the other system of equation
                for b in range(1, self.blocks):
                    self.aes[b].s.reset()
                    self.s.add(self.aes[b].message[i][j] == self.aes[b].message[i][j] ^ self.message[b][i][j])
            
    def reset(self):
        self.s = Aes_Cbc.resetSolver(self)
