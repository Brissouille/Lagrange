from z3 import *
from constant import Ksha, Hsha, sha_param

class Sha():
    message = 0
    def __init__(self, sha_type):
       
        self.sha_type = sha_type
        self.hash_param = sha_param[sha_type]

        self.message = BitVecs(["message%02d" %i for i in range(self.hash_param['Mblock'])], 1)
       
        # Init Solver
        self.s = Solver()

        # Concatenation in 32 bits words
        self.w = [0] * 64 
        for i  in range(0, 512, 32):
            self.w[i//32] = Concat(self.message[i:i+32])
       
        # Transformation W
        for i in range(16, 64):
            self.w[i] = self.sigma_1(self.w[i-2]) + self.w[i-7] + self.sigma_0(self.w[i-15]) + self.w[i-16]

        Hconstante = Hsha[sha_type]

        self.K = Ksha[sha_type]

        nb_rounds = self.hash_param['nb_rounds']
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
        k = (448 - l - 1) % 512
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
            if():
                print()

    def Ch(self, x, y, z):
        return ((x & y) ^ (( x ^ 0xFFFFFFFF) & z))

    def Maj(self, x, y, z):
        return ((x & y) ^ (x & z) ^ (y & z))

    def Sigma_0(self, x):
        return RotateRight(x, 2) ^ RotateRight(x, 13) ^ RotateRight(x, 22)

    def Sigma_1(self, x):
        return RotateRight(x, 6) ^ RotateRight(x, 11) ^ RotateRight(x, 25)

    def sigma_0(self, x):
        return RotateRight(x, 7) ^ RotateRight(x, 18) ^ LShR(x, 3)

    def sigma_1(self, x):
        return RotateRight(x, 17) ^ RotateRight(x, 19) ^ LShR(x, 10)

    def reset(self):
        self.s = Sha.resetSolver(self)

    def resetSolver(self):
        self.s = Solver()
        return self.s

if __name__=="__main__":
    sha = Sha(224)
    sha.digest("616263")
