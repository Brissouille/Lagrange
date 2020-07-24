from z3 import *
from math import log
from copy import deepcopy

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
                

    def rho(self):
        A = [0] * 5 
        for i in range(5):
            A[i] = [0] * 5
            for j in range(5):
                A[i][j] = [0] * self.w
                for k in range(self.w):
                    A[i][j][k] = 0 

        for z in range(self.w):
            A[self.dx[0]][self.dy[0]][z] = self.A[self.dx[0]][self.dy[0]][z]

        x = 1
        y = 0
        for t in range(24):
            for z in range(self.w):
                A[self.dx[x]][self.dy[y]][z] = self.A[self.dx[x]][self.dy[y]][(z-(t+1)*(t+2)//2)%self.w]
            x, y = (y, (2 * self.dx[x] + 3 * self.dy[y]) % 5)
        self.A = A

    def pi(self):
        A = [0] * 5
        for i in range(5):
            A[i] = [0] * 5
            for j in range(5):
                A[i][j] = [0] * self.w
                for k in range(self.w):
                    A[i][j][k] = 0
        for i in range(5):
            for j in range(5):
                for k in range(self.w):
                    A[self.dx[i]][self.dy[j]][k] = self.A[self.dx[i]][self.dy[j]][k] 
        self.A = A

sha3 = Sha3(50)
print(sha3.A)
#sha3.teta()
#sha3.rho()
sha3.pi()
print(sha3.A)
