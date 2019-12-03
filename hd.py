from z3 import *
from hw import *
from model import Model

class Hd(Hw, metaclass = Model):
    """ Class for the Hamming distance """
    Hd = Function("Hd", BitVecSort(8), BitVecSort(8), BitVecSort(8))

    def __init__(self):
        """ Init the Solver """
        self.s = Solver()
        # reset is defined thanks to metaclass Model
        Hd.reset(self)

    def Hd_func(self, x, y):
        """ Compute the Hamming distance thanks to Hamming Weight """
        return self.Hw_func(x^y)
