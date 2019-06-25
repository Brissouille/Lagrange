from .aes_mode import Aes_Mode
from z3 import *

class Aes_Ctr(Aes_Mode):
    def __init__(self, keylength, size_message):
        super().__init__(keylength, size_message)

    def init_mode(self, s):
        # We transform initial vector to an integer
        iv_int = BV2Int(Concat([self.iv[i][j] for i in range(4) for j in range(4)]))
        for b in range(0, self.blocks):
            # Init the block aes
            self.aes[b].s.reset()
            
            # Increment the iv in fonction of the block number
            tmp = iv_int + b
           
            # Init the solver for CTR 
            i = 3
            j = 3
            while(i>=0):
                # Adding the equation
                s.add(self.cipher[b][i][j] == self.aes[b].cipher[i][j] ^ self.message[b][i][j])
                
                # We add the Less Significant byte in the equation of the solver
                a = tmp % 256
                s.add(self.aes[b].message[i][j] == )

                # For the next iteration
                tmp = tmp / 256
                j = (j - 1)%4
                if(j==3):
                    i = i - 1
