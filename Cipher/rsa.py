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

        # message
        self.message = []
        
        for i in range(size_module):
            self.d.append(BitVec("d_%x" %(i), 1))
            self.e.append(BitVec("e_%x" %(i), 1))
       
        # Init variable
        self.message = Int("message")
        self.p, self.q = Ints("p, q")
        self.n = self.p * self.q
        self.phi_n = (self.p-1) * (self.q-1)
        self.size_module = size_module

        # symbolic exponentiation with the previous variables
        self.exponentiation()

        self.s = Solver()

        self.reset()


    def exponentiation(self):
        """ Performs an exponentiation """
        self.cipher = 1
        for i in range(0, self.size_module):
            self.cipher = self.cipher * self.cipher
            multiply = If(self.e[i]==0x01, self.message, 1)
            self.cipher = (self.cipher * multiply) % self.n

    def encrypt(self, public_exponent, modulus, message):
        """ Computes the cipher in resolving the solver """
        self.addPublicExponent(public_exponent)
        self.addMessage(message)
        self.addModulus(modulus)
        print(self.s.assertions()[0])
        input()
        self.s.check()
        forme = "{:0"+str(self.size_module//8)+"x}"
        print(forme.format(int(str(self.s.model().evaluate(self.cipher)))))
   
    def decrypt(self, private_exponent, modulus, message):
        """ Computes the plain in resolving the solver """
        self.addPrivateExponent(private_exponent)
        self.addCipher(message)
        self.addModulus(modulus)
        print(self.s.assertions()[0])
        input()
        self.s.check()
        forme = "{:0"+str(self.size_module//8)+"x}"
        print(forme.format(int(str(self.s.model().evaluate(self.cipher)))))
    
    def addPrivateExponent(self, d):
        """ Addding the private exponent to solver """
        self.addExponent(d, 'd')

    def addPublicExponent(self, e):
        """ Addding the public exponent to solver """
        self.addExponent(e, 'e')

    def addExponent(self, exponent, exp_attrib):
        """ Addding the exponent to solver """
        # e is in hexadecimal format but not zero complemented
        forme = "{:0"+str(self.size_module)+"b}"
        exponent = forme.format(int(exponent,16))
        for i in range(len(exponent)):
            exp_value = self.__getattribute__(exp_attrib)
            self.s.add(exp_value[i] == exponent[i])

    def addModulus(self, module):
        """ Addding the modulus to solver """
        # modulus is in hexadecimal format
        self.s.add(self.n == int(module, 16))
    
    def addMessage(self, message):
        """ Addding the plaint to solver """
        # message is in hexadecimal format
        self.s.add(self.message == int(message, 16))
    
    def addCipher(self, cipher):
        """ Addding the cipher to solver """
        # message is in hexadecimal format
        self.s.add(self.cipher == int(cipher, 16))

    def resetSolver(self):
        """ Create a Solver and init with the sbox value """
        self.s.reset()
        e_int = BV2Int(Concat(self.e))
        d_int = BV2Int(Concat(self.d))
        self.s.add( e_int * d_int == 1 % (self.phi_n))
        return self.s
    
    def reset(self):
        """ reset the solver for this class """
        self.s = Rsa.resetSolver(self)

