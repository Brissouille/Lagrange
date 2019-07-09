from .Cipher.aes import Aes
from z3 import *

class DFA():
    def __init__(self):
        self.aes1 = Aes(128, "m1")
        self.aes2 = Aes(128, "m2")
        self.s = Solver()
       
    def insert_fault(self, lap, byte_attacked, byte_value):
        state1 = self.aes1.cipher[lap]
        state2 = self.aes2.cipher[lap]
        
        # Insert fault on byte 11
        self.fault = BitVec("fault", 8)
        state2[byte_attacked//4][(byte_attacked)%4] = state2[byte_attacked//4][byte_attacked%4] ^ fault
        self.aes2.cipher[lap] = state2
        
        # perform the rounds with the fault
        for l in range(lap+1, self.aes2.Nr):
            self.aes2.subByte(l)
            self.aes2.mixColumn(l)
            self.aes2.addRoundKey(l)
        
        # Last Round with fault
        self.aes2.subByte(self.aes2.Nr)
        self.aes2.addRoundKey(self.aes2.Nr)
        
        # Init the fault
        self.aes2.s.add(self.fault == byte_value)

    def perform_fault(self, safe_m, faulted_m):
        for i in range(4):
            for j in range(4):
                self.s.add(self.aes1.cipher[-1][i][j] ^ self.aes2.cipher[-1][i][j] == 
                        int(safe_m[2*(i*4+j):2*(i*4+j+1)], 16) ^ int(faulted_m[2*(i*4+j):2*(i*4+j+1)], 16))
        

