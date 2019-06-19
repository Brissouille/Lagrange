from z3 import *
from .constant import Ksha, Hsha, sha_param

class Sha():
    message = 0
    def __init__(self, sha_type):
       
        sha_type = sha_type
        self.hash_param = sha_param[sha_type]

        self.message = BitVecs(["message%02d" %i for i in range(self.hash_param['Mblock'])], 1)
       
        # Init Solver
        self.s = Solver()

        # Concatenation in 32 bits words
        self.w = [0] * self.hash_param['nb_rounds']
        size_word = self.hash_param['Mblock']//16 
        nb_rounds = self.hash_param['nb_rounds']
        
        for i  in range(0, self.hash_param['Mblock'], size_word):
            self.w[i//size_word] = Concat(self.message[i:i+size_word])
       
        # Transformation W
        for i in range(16, nb_rounds):
            self.w[i] = self.sigma_1(self.w[i-2]) + self.w[i-7] + self.sigma_0(self.w[i-15]) + self.w[i-16]

        Hconstante = Hsha[sha_type]

        self.K = Ksha[sha_type]

        self.state = [0] * (nb_rounds + 1)

# We suppose there is only 1 block to hash 
        self.state[0] = Hconstante

        for i in range(0, nb_rounds):
            self.state[i+1] = self.compression(i, **self.state[i])

        for key, value in self.state[nb_rounds].items():
            self.state[nb_rounds][key] = self.state[0][key] + value

    def compression(self, i, A, B, C, D, E, F, G, H):
        T1 = H  + self.Sigma_1(E) 
        T1 = T1 + self.Ch(E,F,G) 
        T1 = T1 + self.K[i]
        T1 = T1 + self.w[i]
        T2 = self.Sigma_0(A) + self.Maj(A,B,C)
        H = G
        G = F
        F = E
        E = D + T1
        D = C
        C = B
        B = A
        A = T1 + T2
        dct = {'A':A, 'B':B, 'C':C, 'D':D, 'E':E, 'F':F, 'G':G, 'H':H}
        return dct 

    def digest(self, message):
        self.s.reset()
        # template which keeps the zeros on the left and transforms message in binary
        forme = "{:0"+str(len(message)*4)+"b}"
        m = forme.format(int(message, 16))
        l = len(m)

        # Padding 
        k = (self.hash_param['Mblock']*7//8 - l - 1) % self.hash_param['Mblock'] 
        zpadding = "1" + "0" * k
        forme = "{:0"+str(self.hash_param['maxlength'])+"b}"
        m = m + zpadding + forme.format(l)
        
        # Prepare equation
        for i in range(0,len(m)):
            self.s.add(self.message[i] == int(m[i],2))

        # Resolve system
        sat_sha = self.s.check()

        if sat_sha == sat:
            [print(hex(int(str(self.s.model().evaluate(self.state[64][i]))))[2:], end='') for i in ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H']]
            #[print(hex(int(str(self.s.model().evaluate(self.state[1][i]))))[2:], end=' ') for i in ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H']]
            print()

    def Ch(self, x, y, z):
        # Compute the value to perform a completion on 32 or 64 bits
        size_ff = (2**32) ** (self.hash_param['Mblock'] // 512) - 1
        return ((x & y) ^ (( x ^ size_ff) & z))

    def Maj(self, x, y, z):
        return ((x & y) ^ (x & z) ^ (y & z))

    def Sigma_0(self, x):
        f = self.hash_param['Sigma_0']
        return f(self,x)

    def Sigma_1(self, x):
        f = self.hash_param['Sigma_1']
        return f(self,x)

    def sigma_0(self, x):
        f = self.hash_param['sigma_0']
        return f(self,x)

    def sigma_1(self, x):
        f = self.hash_param['sigma_1']
        return f(self, x)

    def reset(self):
        self.s = Sha.resetSolver(self)

    def resetSolver(self):
        self.s = Solver()
        return self.s

