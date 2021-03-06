from z3 import *

class Rsa():
    def __init__(self, size_module, prefix="message"):
        """ Class which implements an RSA """ 
        # private exponent
        self.d = []
        
        #public exponent
        self.e = []

        # modulus 
        self.n = []
        
        # phi
        self.phi_n = []

        # message to encrypt
        self.message = Int("message")
        
        # message to decrypt
        self.encrypted_message = Int("ecnrypted_message")
        
        for i in range(size_module):
            self.d.append(BitVec("d_%x" %(i), 1))
            self.e.append(BitVec("e_%x" %(i), 1))
       
        # Init variable
        self.p, self.q = Ints("p q")
        self.n = Int("n")
        self.phi_n = (self.p-1) * (self.q-1)
        self.size_module = size_module

        ## symbolic exponentiation with the previous variables

        # Init cipher (= encryption of message variable)
        self.encryption()

        # Init plain (= decryption of encrypted message variable)
        self.decryption()

        self.s = Solver()

        self.reset()

    def encryption(self):
        """ encrypt with an exponentiation and public exponent """
        self.cipher = self.exponentiation(self.e, self.n, self.message)
    
    def decryption(self):
        """ decrypt with an exponentiation and private exponent """
        self.plain = self.exponentiation(self.d, self.n, self.encrypted_message)

    def exponentiation(self, exponent, n, message):
        """ Performs an exponentiation """
        result = 1
        for i in range(self.size_module):
            result = (result * result) % n
            multiply = If(exponent[i]==0x01, message, 1)
            result = (result * multiply) % n
        return result

    def encrypt(self, exponent, modulus, message):
        """ Computes the cipher in resolving the solver """
        self.addPublicExponent(exponent)
        self.addMessage(message)
        self.addModulus(modulus)
        self.s.check()
        forme = "{:x}"
        return forme.format(int(str(self.s.model().evaluate(self.cipher))))
   
    def decrypt(self, exponent, modulus, cipher):
        """ Computes the plain in resolving the solver """
        self.addPrivateExponent(exponent)
        self.addEncryptedMessage(cipher)
        self.addModulus(modulus)
        self.s.check()
        forme = "{:x}"
        return forme.format(int(str(self.s.model().evaluate(self.plain))))

    def crt_init(self, dest_number):
        ai = []
        ni = []
        Ni = []
        Mi = []
        N = Int("N")
        # Init Crt theorem with dest_number components
        for i in range(dest_number):
            ni.append(Int("n"+str(i)))
            ai.append(Int("a"+str(i)))
            Ni.append(N/ni[-1])
            Mi.append(Int("m"+str(i)))

        self.crt = Crt()
        self.crt.ni = ni
        self.crt.ai = ai
        self.crt.Ni = Ni
        self.crt.Mi = Mi
        self.crt.N = N

    def crt_exploit(self, dest_list, exponent):
        assert(len(dest_list) == len(self.crt.ni))
        ni = self.crt.ni
        ai = self.crt.ai
        Ni = self.crt.Ni
        Mi = self.crt.Mi
        N = self.crt.N
        
        N_temp = 1
        for i in range(len(dest_list)):
            N_temp = N_temp * ni[i]
            self.s.add(ai[i]==int(dest_list[i][0], 16))
            self.s.add(ni[i]==int(dest_list[i][1], 16))
            self.s.add((Ni[i]*Mi[i])%ni[i]==1, 0<Mi[i], Mi[i]<ni[i])
        self.s.add(N==N_temp)

        me = sum([ai[i]*Ni[i]*Mi[i] for i in range(len(ni))])%N
        
        message = Int("message")
        e = Int("e")
        self.s.add(message**e == me)
        self.s.add(e == int(exponent))
        self.s.add(0<message)
        self.s.check()
        return self.s.model().evaluate(message)

        

    def coppersmith(self, n_4):
        # length of n_4 must be one quater of size module in bits
        assert(len(n_4) == self.size_module//16)
        """ Attack with key exposure """
        e = BV2Int(Concat(self.e))
        d0 = BV2Int(Concat(self.d[self.size_module - self.size_module//4:]))
        partial_n = 2**(4*len(n_4))
        k = Int("k")
        self.s.add(k<e, 0<k)
        self.s.add(self.p<self.n, 0<self.p)
        self.s.add(self.q<self.n, 0<self.q)
        self.s.add(self.n == self.p * self.q)
        #self.s.add(self.p == (e * d0 * self.p - k * self.p * (self.n - self.p + 1) + k * self.n) % partial_n)
        self.s.add(d0 == int(n_4, 16)) 
        self.s.add((e * d0)% partial_n == (1 + k * (self.n -(self.p+self.q) + 1))% partial_n)
        #self.s.add((self.p*self.p -(self.p+self.q)*self.p + self.p*self.q) % partial_n == 0)
        
        print(self.s.check())
        print(self.s.model())
        print(hex(int(str(self.s.model().evaluate(self.p)))))

    def addPublicExponent(self, public_exponent):
        """ Addding the public exponent to solver """
        self.addExponent(public_exponent, 'e')

    def addPrivateExponent(self, private_exponent, offset=0):
        """ Addding the private exponent to solver """
        self.addExponent(private_exponent, 'd', offset)

    def addExponent(self, exponent, attribute, offset=0):
        """ Addding the exponent to solver """
        # e is in hexadecimal format but not zero complemented
        forme = "{:0"+str(self.size_module)+"b}"
        # zero completion
        exponent = forme.format(int(exponent,16))
        # Get the bitvector of the exponent
        exp_value = self.__getattribute__(attribute)
        
        # We find only the used bit
        exponent = exponent[offset:]
        exp_value = exp_value[offset:]

        # equal bit to bit
        for i,j in zip(exponent, exp_value):
            self.s.add(i == j)

    def addModulus(self, module):
        """ Addding the modulus to solver """
        # modulus is in hexadecimal format
        self.s.add(self.n == int(module, 16))
    
    def addMessage(self, message):
        """ Addding the plain to solver """
        # message is in hexadecimal format
        self.s.add(self.message == int(message, 16))
    
    def addEncryptedMessage(self, cipher):
        """ Addding the cipher to solver """
        # message is in hexadecimal format
        self.s.add(self.encrypted_message == int(cipher, 16))
    
    def resetSolver(self):
        """ Create a Solver and init with the sbox value """
        self.s.reset()
        return self.s
    
    def reset(self):
        """ reset the solver for this class """
        self.s = Rsa.resetSolver(self)

class Crt():
    def __init__(self):
        pass

