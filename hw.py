from z3 import *

class Hw():
    """ Class for the Hamming Weight """
    Hw = Function("Hw", BitVecSort(8), BitVecSort(8))
    
    def __init__(self):
        """ Init the Solver """
        self.s = Solver()
        Hw.resetSolver(self)

    def reset(self):
        """" Reset the Solver """
        self.s.reset()
        self.s = Hw.resetSolver(self)

    def resetSolver(self):
        """ Create a new sovler and reinit it with 256 elements """
        s = Solver() 
        for x in range(256):
            s.add(self.Hw(x)== self.Hw_func(x))
        return s

    def Hw_func(self, x):
        """ Compute the number of ones (= Hamming Weigth) """ 
        return bin(x)[2:].count("1")

