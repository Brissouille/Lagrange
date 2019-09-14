from .Cipher.aes import Aes
from z3 import *
from copy import deepcopy

class DFA():
    """ DFA class which performed a Differential Fault Analysis """
    def __init__(self):
        """ Initialise the attribute """
        self.aes = []
        self.s = Solver()
    
    def resetSolver(self):
        """ Reset Solver and clean list of aes """
        self.s = Solver()
        self.aes = []
        return self.s

    def reset(self):
        """ Reset the solver of the DFA """
        self.s = DFA.resetSolver(self)

    def simulate(self, lap, byte_attacked, aes1, aes2):
        # Fault depend on the aes list
        self.fault = BitVec("fault_%02d" %(len(self.aes)), 8)
       
        # Round Aes with a fault
        aes2.subByte(lap)
        # Adding the last fault of the list
        aes2.insert_fault(lap, byte_attacked, self.fault) 
        aes2.mixColumn(lap)
        aes2.addRoundKey(lap)

        # Aes1 clean
        aes1.subByte(lap)
        aes1.mixColumn(lap)
        aes1.addRoundKey(lap)
        
        # Finish the rounds of Aes
        for l in range(lap+1, aes2.Nr):
            # Aes2 with fault
            aes2.subByte(l)
            aes2.mixColumn(l)
            aes2.addRoundKey(l)

            # Aes1 clean
            aes1.subByte(l)
            aes1.mixColumn(l)
            aes1.addRoundKey(l)
       
        # Last Round with fault
        aes2.cipher[aes2.Nr] = deepcopy(aes2.cipher[aes2.Nr-1])
        aes2.subByte(aes2.Nr)
        aes2.addRoundKey(aes2.Nr)
        
        # Last Round with Aes1 clean
        aes1.cipher[aes1.Nr] = deepcopy(aes1.cipher[aes1.Nr-1])
        aes1.subByte(aes1.Nr)
        aes1.addRoundKey(aes1.Nr)
        
        return [aes1, aes2]

    def insert(self, lap, byte_attacked):
        """ Modelisation of a fault on 1 byte after the subbyte of the round 9"""
        lap = 9
        self.target_byte = byte_attacked
        aes1 = Aes(128, "m_%02d_s" %(len(self.aes)))
        aes2 = Aes(128, "m_%02d_f" %(len(self.aes)))

        A = []
        K9 = []
        K10 = []
        for i in range(4):
            A_tmp = []
            K9_tmp = []
            K10_tmp = []
            for j in range(4):
                A_tmp.append(BitVec("A_%02d_%02d" % (j,i), 8))
                K9_tmp.append(BitVec("K9_%02d_%02d" % (j,i), 8)) 
                K10_tmp.append(BitVec("K10_%02d_%02d" % (j,i), 8))
            A.append(A_tmp)
            K9.append(K9_tmp)
            K10.append(K10_tmp)
            
        aes1.cipher[lap] = deepcopy(A)
        aes2.cipher[lap] = deepcopy(A)
        
        aes2.keyRounds[9] = deepcopy(K9)
        aes2.keyRounds[10] = deepcopy(K10)
        
        aes1.keyRounds[9] = deepcopy(K9)
        aes1.keyRounds[10] = deepcopy(K10)

        aes1, aes2 = self.simulate(lap, byte_attacked, aes1, aes2)

        # Save the cipher and the faulted cipher
        self.aes.append([aes1, aes2])
    
    def exploit(self, list_exploit):
        """ Add the couple of cipher and faulted cipher in the solver and check the solutions """
        # We agregate the solver into one solver
        for aes, output in zip(self.aes, list_exploit):
            aes1, aes2 = aes
            faulted_m, safe_m = output
            aes1.addCipher(safe_m)
            aes2.addCipher(faulted_m)
            self.s.add(aes1.s.assertions())
            self.s.add(aes2.s.assertions())
        
        sat_status = sat
        # Resolution of the equation
        sat_status = self.s.check()
        if(sat_status == sat):
            print("Solution")
            # We retrieve 4 key bytes
            # loop column order
            for i in range(4):
                solution = int(str(self.s.model().evaluate(aes1.keyRounds[10][i][(self.target_byte-i)%4])))
                print("{:02x}".format(solution), end=" ")
            print()
            
        else:
            print("No Solution")

    def test(self, key, message, lap, byte_attacked, fault_list):
        """ Create a cipher and faulted cipher in function of the fault value """
        # For each faults 
        l = []
        aes1 = Aes(128)
        aes2 = Aes(128)
        aes1.reset()
        aes2.reset()
        [aes1, aes2] = self.simulate(lap, byte_attacked, aes1, aes2) 
        for fault_value in fault_list:
            # Performs encryption with fault
            aes2.s.add(self.fault == fault_value)
            faulted_cipher = aes2.encrypt(key, message)

            # Performs safe encryption
            cipher = aes1.encrypt(key, message)
            l.append((faulted_cipher, cipher))

        return l
