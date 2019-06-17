from z3 import *

class Hw():
    
    Hw = Function("Hw", BitVecSort(8), BitVecSort(8))
    
    def __init__(self):
        self.s = Solver()
        Hw.resetSolver(self)

    def reset(self):
        self.s.reset()
        self.s = Hw.resetSolver(self)

    def resetSolver(self):
        #Reset sovler of Hw and reinit with algo solver
        s = Solver() 
        for x in range(256):
            s.add(self.Hw(x)== self.Hw_func(x))
        return s

    def Hw_func(self, x):
        return bin(x)[2:].count("1")

