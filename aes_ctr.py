from .aes_mode import Aes_Mode
from z3 import *

class Aes_Ctr(Aes_Mode):
    def __init__(self, keylength, size_message):
        super().__init__(keylength, size_message)

    def init_mode(self, s):
        # We concatenate the initial vector for the addition. Concatenation is column order
        iv_int = Concat([self.iv[i][j] for i in range(4) for j in range(4)])
        print(iv_int)
        for b in range(0, self.blocks):
            # Init the block aes
            self.aes[b].s.reset()
            
            # Increment the iv in fonction of the block number
            tmp = iv_int + 0
            
            # Init the solver for CTR 
            for i in range(4):
                for j in range(4):
                    indice_hi = ( ((3-i)*4 + (3-j) + 1) * 8 -1 )
                    indice_low = ( ((3-i)*4 + (3-j)) * 8 )

                    # Adding the equation
                    s.add(self.aes[b].message[i][j] == Extract(indice_hi, indice_low, tmp))
                    s.add(self.cipher[b][i][j] == self.aes[b].cipher[i][j] ^ self.message[b][i][j])

