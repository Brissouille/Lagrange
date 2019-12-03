from Hash.sha import Sha
from z3 import *
from copy import deepcopy

class Collision():
    def __init__(self, sha_type):
        ## Init to perform a collision betwee 2 hash function
        self.collisions_number = 2
        self.sha = [Sha(sha_type, "message"+str(i)+"_") for i in range(self.collisions_number)]
        self.s  = Solver()

    def resetSolver(self):
        """ Reset Solver and clean sha list"""
        for i in range(self.collisions_number):
            self.sha[i].reset()
        self.s = Solver()
        return self.s

    def reset(self):
        """ Reset the solver of the Collision """
        self.s = Collision.resetSolver(self)

    def exploit(self, round_attacked):
        sha_m0 = self.sha[0]
        sha_m1 = self.sha[1]

        # From 2 different messages
        tmp_or = False
        for i, j in zip(sha_m0.message, sha_m1.message):
            # Different messages -> one bit different between 2 messages
            tmp_or = Or(tmp_or, i!=j)
        self.s.add(simplify(tmp_or))
       
        # Find the same hash for a given round 
        for key1, key2 in zip(sha_m0.state[round_attacked].items(), sha_m1.state[round_attacked].items()):
            self.s.add(key1[1] == key2[1])

        print(self.s.check())
        
        for i in range(len(sha_m0.message)):
            print( (i, self.s.model().evaluate(sha_m0.message[i]) == self.s.model().evaluate(sha_m1.message[i])))
            
