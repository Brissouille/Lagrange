from z3 import *

class Sha():
    message = 0
    def __init__(self):
        self.message = BitVecs(["message%02d" %i for i in range(512)], 1)
       
        # Init Solver
        self.s = Solver()

        # Concatenation in 32 bits words
        self.w = [0]*64
        for i  in range(0, 512, 32):
            self.w[i//32] = Concat(self.message[i:i+32])
       
        # Transformation w
        for i in range(16, 64):
            #self.w[i] = self.sigma_1(self.w[i-2]) + self.w[i-7] + self.sigma_0(self.w[i-15]) + self.w[i-16]
            self.w[i] = 0 


        Hconstante = {'A':BitVecVal(0x6a09e667, 32),
                      'B':BitVecVal(0xbb67ae85, 32),
                      'C':BitVecVal(0x3c6ef372, 32),
                      'D':BitVecVal(0xa54ff53a, 32),
                      'E':BitVecVal(0x510e527f, 32),
                      'F':BitVecVal(0x9b05688c, 32),
                      'G':BitVecVal(0x1f83d9ab, 32),
                      'H':BitVecVal(0x5be0cd19, 32)
                    }

        self.K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
             0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 
             0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 
             0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 
             0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 
             0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 
             0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 
             0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

        self.state = [0] * 65

# on suppose qu un bloc a hacher
        self.state[0] = Hconstante

        for i in range(0,1):
            self.state[i+1] = self.compression(i, **self.state[i])

        Hconstante = self.state[64]

    def compression(self, i, A, B, C, D, E, F, G, H):
        T1 = H + self.Sigma_1(E) + self.Ch(E,F,G) + self.K[i]
        T1 = T1 + A + self.w[i]
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
        # On cree une forme qui garde les zeros de poids forts
        forme = "{:0"+str(len(message)*4)+"b}"
        m = forme.format(int(message, 16))
        l = len(m)

        # Padding 
        k = (448 - l - 1) % 512
        zpadding = "1" + "0" * k
        m = m + zpadding + "{:064b}".format(l)
        
        # Prepare equation
        for i in range(0,len(m)):
            self.s.add(self.message[i] == int(m[i],2))

        # Resolve system
        sat_sha = self.s.check()

        if sat_sha == sat:
            print(hex(int(str(self.s.model().evaluate(self.state[1]['H'])))))

    def Ch(self, x, y, z):
        return ((x & y) ^ (( x ^ 0xFF) & z))

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
    sha256 = Sha()
    sha256.digest("616263")

