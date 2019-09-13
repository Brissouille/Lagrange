from z3 import Solver

class Model(type):
    """ Meta class which allows to agregate the solvers of parent class """
    def __new__(cls, name, bases, dct):
        def _agregateSolver(self):
            self.s = Solver()
            for base in bases:
                s1 = base.resetSolver(self)
                self.s.add(s1.assertions())
        dct["reset"] = _agregateSolver
        return type.__new__(cls, name, bases, dct)
