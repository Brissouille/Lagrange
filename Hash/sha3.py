from z3 import *
from math import log

class Sha3():
    dx = [3, 4, 0, 1, 2]
    dy = [3, 4, 0, 1, 2]

    def __init__(self, b):
        self.b = b
        assert(b%25==0)
        self.w = b // 25
        self.l = log(self.w, 2)
        assert(self.l < 7)

        #self.A = BitVecs(["A_%d_%d_%d" % (x, y, z) for x in range(5) for y in range(5) for z in range(self.w)], 1)
        self.A = [0] * 5
        for i in self.dx:
            self.A[i] = [0] * 5
            for j in self.dy:
                self.A[i][j] = BitVecs(["A_%d_%d_%d" %(i, j, k) for k in range(self.w)], 1)

    def teta(self):
        c = [0] * 5
        for x in self.dx:
            c[x] = [0] * self.w
            for z in range(self.w):
                c[x][z] = self.A[x][0][z] ^ self.A[x][1][z] ^ self.A[x][2][z] ^ self.A[x][3][z] ^ self.A[x][4][z]

        d = [0] * 5
        for x in self.dx:
            d[x] = [0] * self.w
            for z in range(self.w):
                d[x][z] = c[(x-1)%5][z] ^ c[(x+1)%5][(z-1)%self.w]

        for i in self.dx:
            for j in self.dy:
                for k in range(self.w):
                    self.A[i][j][k] = self.A[i][j][k] ^ d[i][k]
                

sha3 = Sha3(50)
sha3.teta()
print(sha3.A[0][0][0])
