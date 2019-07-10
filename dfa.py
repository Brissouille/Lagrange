from .Cipher.aes import Aes
from z3 import *

class DFA():
    def __init__(self):
        self.aes1 = Aes(128)
        self.aes2 = Aes(128)
        self.s = Solver()
    
    def resetSolver(self):
        s = Solver()
        self.aes1.reset()
        self.aes2.reset()
        return s

    def reset(self):
        self.s = DFA.resetSolver(self)

    def insert(self, lap, byte_attacked, byte_value):
        state1 = self.aes1.cipher[lap]
        state2 = self.aes2.cipher[lap]
        
        self.aes2.subByte(lap+1)

        # Insert fault on byte
        self.fault = BitVec("fault", 8)
        #state2[byte_attacked//4][(byte_attacked)%4] = state2[byte_attacked//4][byte_attacked%4] ^ self.fault
        state2[byte_attacked//4][(byte_attacked)%4] = self.fault
        self.aes2.cipher[lap+1] = state2
        
        # perform the rounds with the fault
        for l in range(lap+1, self.aes2.Nr):
            self.aes2.mixColumn(l)
            self.aes2.addRoundKey(l)
        
        # Last Round with fault
        self.aes2.subByte(self.aes2.Nr)
        self.aes2.addRoundKey(self.aes2.Nr)
        
        # Init the fault
        self.aes2.s.add(self.fault == byte_value)

    def exploit(self, safe_m, faulted_m):
        self.aes1.addCipher(safe_m)
        self.aes2.addCipher(faulted_m)
        for i in range(4):
            for j in range(4):
                self.s.add(self.aes1.cipher[-1][i][j] ^ self.aes2.cipher[-1][i][j] == 
                  int(safe_m[2*(i*4+j):2*(i*4+j+1)], 16) ^ int(faulted_m[2*(i*4+j):2*(i*4+j+1)], 16))
        
        sat_status = self.s.check()
        while(sat_status == sat):
            if(sat_status == sat):
                print(self.s.model().evaluate(self.aes1.keyRounds[10][0][0]))
            else:
                print("No Solution")

            self.s.add()
            sat_status = self.s.check()
