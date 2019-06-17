from z3 import *
from aes import Aes
from hw import Hw
from model import Model


class Aes_Hw(Aes, Hw, metaclass = Model):
    def __init__(self, keylength):
        Aes.__init__(self, keylength)
        Hw.__init__(self)
        self.reset()

#    def resetSolver(self):
#        AES.resetSolver(self)
#        tmp_s = self.s
#        Hw.resetSolver(self)
#        self.s.add(tmp_s.assertions())

if __name__=="__main__":

    aes = Aes_Hw(128)

    cipher = aes.encrypt("2b7e151628aed2a6abf7158809cf4f3c", "3243f6a8885a308d313198a2e0370734")

    print(cipher)
