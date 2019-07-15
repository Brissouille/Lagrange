from .Cipher.aes import Aes
from z3 import *
from copy import deepcopy

class DFA():
    def __init__(self):
        self.aes = []
        self.s = Solver()
    
    def resetSolver(self):
        s = Solver()
        aes1.reset()
        aes2.reset()
        return s

    def reset(self):
        self.s = DFA.resetSolver(self)

    def insert(self, lap, byte_attacked, byte_value):
        aes1 = Aes(128, "m_%02d_1" %(len(self.aes)))
        aes2 = Aes(128, "m_%02d_2" %(len(self.aes)))
        self.aes.append([aes1, aes2])

        A = [[BitVec("A_%02d_%02d" % (j,i), 8) for i in range(4)] for j in range(4)] 
        K9 = [[BitVec("K9_%02d_%02d" % (j,i), 8) for i in range(4)] for j in range(4)] 
        K10 = [[BitVec("K10_%02d_%02d" % (j,i), 8) for i in range(4)] for j in range(4)] 

        # We take the previous state
        #aes2.cipher[lap] = deepcopy(aes2.cipher[lap-1])
        aes2.cipher[lap] = deepcopy(A)
        
        aes2.keyRounds[9] = deepcopy(K9)
        aes2.keyRounds[10] = deepcopy(K10)

        # Perform subByte 
        aes2.subByte(lap)

        # Insert fault on byte previous MixColumn
        state2 = aes2.cipher[lap]
        self.fault = BitVec("fault", 8)
        #state2[byte_attacked//4][(byte_attacked)%4] = self.fault
        state2[byte_attacked//4][(byte_attacked)%4] = state2[byte_attacked//4][byte_attacked%4] ^ self.fault 
       
        # Perform the rounds 9 with the fault
        for l in range(lap, aes2.Nr):
            aes2.mixColumn(l)
            aes2.addRoundKey(l)
       
        # Last Round with fault
        aes2.cipher[aes2.Nr] = deepcopy(aes2.cipher[aes2.Nr-1])
        aes2.subByte(aes2.Nr)
        aes2.addRoundKey(aes2.Nr)

        # Init the fault
        self.s.add(self.fault == byte_value)

    def exploit(self, safe_m, faulted_m):
        aes1, aes2 = self.aes[0]
        aes1.addCipher(safe_m)
        aes2.addCipher(faulted_m)
        print(aes2.cipher[-1][0][0])
        input()
        self.s.add(aes1.s.assertions())
        self.s.add(aes2.s.assertions())
        
        sat_status = self.s.check()
        if(sat_status == sat):
            print("Solution")
            #print(self.s.model().evaluate(aes1.keyRounds[10][0][0]))
        else:
            print("No Solution")

