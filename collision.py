from Hash.sha import Sha
from z3 import *
from copy import deepcopy

class Collision():
    def __init__(self, sha_type):
        ## Init to perform a collision betwee 2 hash function
        self.collisions_number = 2
        self.sha = [Sha(sha_type, "m"+str(i)) for i in range(self.collisions_number)]
        self.s  = Solver()

    def resetSolver(self):
        """ Reset Solver and clean list of aes """
        for i in range(self.collisions_number):
            self.sha[i].reset()
        self.s = Solver()
        return self.s

    def reset(self):
        """ Reset the solver of the DFA """
        self.s = Collision.resetSolver(self)

    def exploit(self, round_attacked):

