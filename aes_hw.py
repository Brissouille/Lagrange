from z3 import *
from .aes import Aes
from .hw import Hw
from .model import Model


class Aes_Hw(Aes, Hw, metaclass = Model):
    def __init__(self, keylength):
        Aes.__init__(self, keylength)
        Hw.__init__(self)
        self.reset()

