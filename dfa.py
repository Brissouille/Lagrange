from .Cipher.aes import Aes
from z3 import *
from copy import deepcopy

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

        # We take the previous state
        self.aes2.cipher[lap] = deepcopy(self.aes2.cipher[lap-1])

        # Perform subByte 
        self.aes2.subByte(lap)

        # Insert fault on byte previous MixColumn
        state2 = self.aes2.cipher[lap]
        self.fault = BitVec("fault", 8)
        state2[byte_attacked//4][(byte_attacked)%4] = self.fault
        #state2[byte_attacked//4][(byte_attacked)%4] = state2[byte_attacked//4][byte_attacked%4] ^ self.fault 
        
        # Perform the rounds 9  with the fault
        for l in range(lap+1, self.aes2.Nr):
            self.aes2.mixColumn(l)
            self.aes2.addRoundKey(l)
        
        # Last Round with fault
        self.aes2.cipher[self.aes2.Nr] = deepcopy(self.aes2.cipher[self.aes2.Nr-1])
        self.aes2.subByte(self.aes2.Nr)
        self.aes2.addRoundKey(self.aes2.Nr)
        
        # Init the fault
        self.s.add(self.fault == byte_value)

    def exploit(self, safe_m, faulted_m):
        self.aes1.addCipher(safe_m)
        self.aes2.addCipher(faulted_m)
      
        self.s.add(self.aes1.s.assertions())
        self.s.add(self.aes2.s.assertions())
        
        sat_status = self.s.check()
        if(sat_status == sat):
            pass
            print("Solution")
            #print(self.s.model().evaluate(self.aes1.keyRounds[10][0][0]))
        else:
            print("No Solution")

