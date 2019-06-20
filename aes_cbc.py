from z3 import *
from .aes import Aes
from .model import Model

class Aes_Cbc():
    def __init__(self, keylength, size_message):
        
        # The message must be a mutliple of 32 bytes
        assert((size_message!=0)%32)
        self.blocks = size_message // 32
        
        # Init the solver
        self.s = Solver()

        # Aes list
        self.aes = [0] * self.blocks
        self.aes[0] = Aes(keylength, "m0")
        self.s.add(self.aes[0].assertions())

        for i in range(1, self.blocks)
            # Init each Aes with a different plaintext name
            self.aes[i] = Aes(keylength, "m"+str(i))
            for j in range(16):
                self.s.add(self.aes[i].message[j]==self.aes[i-1].message[j] ^ )
            self.s.add(self.aes[i].assertions())


