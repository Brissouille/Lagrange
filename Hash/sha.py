from z3 import *
from Hash.constant import Ksha, Hsha, sha_param

class Sha():
    """ Class which implements Hash function compliance with the FIPS 180 """
    message = 0
    def __init__(self, sha_type, prefix='message_'):
        """ Init the type of Hash function and its symbolic variables """
        self.sha_type = sha_type
        self.hash_param = sha_param[sha_type]
        self.message = BitVecs([prefix+"%02d" %i for i in range(self.hash_param['Mblock'])], 1)
       
        # Init Solver
        self.s = Solver()

        size_word = self.hash_param['Mblock']//16 
        nb_rounds = self.hash_param['nb_rounds']
        
        self.w = [0] * nb_rounds 
        # Concatenation in 32 or 64 bits words
        for i  in range(0, self.hash_param['Mblock'], size_word):
            self.w[i//size_word] = Concat(self.message[i:i+size_word])
       
        # Transformation W
        for i in range(16, nb_rounds):
            self.w[i] = self.sigma_1(self.w[i-2]) + self.w[i-7] + self.sigma_0(self.w[i-15]) + self.w[i-16]

        # Initialisation of the constants
        Hconstante = Hsha[sha_type]
        self.K = Ksha[sha_type]

        self.state = [0] * (nb_rounds + 1)

# We suppose there is only 1 block to hash 
        self.state[0] = Hconstante

        # for each round, we perform a comppression function
        for t in range(0, nb_rounds):
            self.state[t+1] = self.compression(t, **self.state[t])

        # Last operation for the sha
        # Be careful the order is not A, B, ..., H
        for key, value in self.state[nb_rounds].items():
            self.state[nb_rounds][key] = self.state[0][key] + value

    def compression(self, i, A, B, C, D, E, F, G, H):
        """ Performs the compression function of the FIPS 180 """
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

    def preimage(self, round_attacked, hash_value):
        """ Performs a preimage attack in function of reduced hash and the number of reduced round """
        Sha.reset(self)
        i = 0
        size_word = self.hash_param['Mblock']//(64) 
        for key, value in sorted(self.state[round_attacked].items()):
            self.s.add(self.state[round_attacked][key] == int(hash_value[i*size_word:(i+1)*size_word], 16))
            i = i + 1
            
        if(self.s.check()==sat):
            message = str([self.s.model().evaluate(self.message[i]) for i in range(512)])
        else:
            print("No Solution")
            message = ""
        return  message

    def digest(self, message, round_attack=-1):
        """ Performs a hash """
        self.s.reset()
        # A format string which keeps the zeros on the left and transforms message in binary
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
            # to print in hex on 8 caracteres or 16 caracteres
            forme = "{:0"+str(self.hash_param['Mblock']//64)+"x}"
            size_hash = self.sha_type // (self.hash_param['Mblock'] // 16)
            hash_result = [forme.format(int(str(self.s.model().evaluate(self.state[round_attack][chr(i+0x41)])))) for i in range(size_hash)] 
            return "".join(hash_result)

    def Ch(self, x, y, z):
        """ Internal Function for the hash """
        # size_ff is used to perform a completion on 32 or 64 bits
        size_ff = (2**32) ** (self.hash_param['Mblock'] // 512) - 1
        return ((x & y) ^ (( x ^ size_ff) & z))

    def Maj(self, x, y, z):
        """ Internal Function for the hash """
        return ((x & y) ^ (x & z) ^ (y & z))

    def Sigma_0(self, x):
        """ Internal Function for the hash """
        f = self.hash_param['Sigma_0']
        return f(self,x)

    def Sigma_1(self, x):
        """ Internal Function for the hash """
        f = self.hash_param['Sigma_1']
        return f(self,x)

    def sigma_0(self, x):
        """ Internal Function for the hash """
        f = self.hash_param['sigma_0']
        return f(self,x)

    def sigma_1(self, x):
        """ Internal Function for the hash """
        f = self.hash_param['sigma_1']
        return f(self, x)

    def reset(self):
        """ reset the solver of the class """
        self.s = Sha.resetSolver(self)

    def resetSolver(self):
        """ Create a solver """
        self.s = Solver()
        return self.s

