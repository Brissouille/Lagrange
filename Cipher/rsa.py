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
        self.n = self.p * self.q
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
        self.cipher = self.exponentiation(self.e, self.n, self.message)
    
    def decryption(self):
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
        """ Computes the plain in resolving the solver """
        self.addPublicExponent(exponent)
        self.addMessage(message)
        self.addModulus(modulus)
        print(self.s.check())
        forme = "{:0"+str(self.size_module//8)+"x}"
        print(str(self.s.model().evaluate(self.cipher)))
   
    def decrypt(self, exponent, modulus, cipher):
        """ Computes the plain in resolving the solver """
        self.addPrivateExponent(exponent)
        self.addEncryptedMessage(cipher)
        self.addModulus(modulus)
        print(self.s.check())
        forme = "{:0"+str(self.size_module//8)+"x}"
        print(str(self.s.model().evaluate(self.plain)))
   
    def addPublicExponent(self, public_exponent):
        self.addExponent(public_exponent, 'e')

    def addPrivateExponent(self, private_exponent):
        self.addExponent(private_exponent, 'd')

    def addExponent(self, exponent, attribute):
        """ Addding the exponent to solver """
        # e is in hexadecimal format but not zero complemented
        forme = "{:0"+str(self.size_module)+"b}"
        # zero completion
        exponent = forme.format(int(exponent,16))
        # Get the bitvector of the exponent
        exp_value = self.__getattribute__(attribute)
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

