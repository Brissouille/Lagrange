from z3 import *

class Rsa():
    def __init__(self, size_module, prefix="message"):
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
        self.phi_n = Int("phi_n")
        self.n = Int("n")
        self.size_module = size_module

        # symbolic exponentiation with the previous variables
        self.exponentiation()

        self.s = Solver()

    def exponentiation(self):
        self.cipher = 1
        for i in range(0, self.size_module):
            self.cipher = self.cipher * self.cipher
            multiply = If(self.e[i]==0x01, self.message, 1)
            self.cipher = (self.cipher * multiply) % self.n

    def encrypt(self, public_exponent, modulus, message):
        self.addPublicExponent(public_exponent)
        self.addMessage(message)
        self.addModulus(modulus)
        self.s.check()
        forme = "{:0"+str(self.size_module//8)+"x}"
        print(forme.format(int(str(self.s.model().evaluate(self.cipher)))))
   
    def decrypt(self, private_exponent, modulus, message):
        self.addPrivateExponent(private_exponent)
        self.addCipher(message)
        self.addModulus(modulus)
        self.s.check()
        forme = "{:0"+str(self.size_module//8)+"x}"
        print(forme.format(int(str(self.s.model().evaluate(self.cipher)))))
    
    def addPrivateExponent(self, d):
        self.addExponent(d, 'd')

    def addPublicExponent(self, e):
        self.addExponent(e, 'e')

    def addExponent(self, exponent, exp_attrib):
        # e is in hexadecimal format
        for i in range(0, self.size_module//8, 2):
            # for each byte of the exponent
            byte_exp = exponent[i:i+2]

            # transform in bits
            bin_exp = "{:08b}".format(int(byte_exp, 16))
            for j in range(8):
                exp_value = self.__getattribute__(exp_attrib)
                self.s.add(exp_value[i*8+j] == bin_exp[j])

    def addModulus(self, module):
        # modulus is in hexadecimal format
        self.s.add(self.n == int(module, 16))
    
    def addMessage(self, message):
        # message is in hexadecimal format
        self.s.add(self.message == int(message, 16))
    
    def addCipher(self, message):
        # message is in hexadecimal format
        self.s.add(self.cipher == int(cipher, 16))

    def resetSolver(self):
        self.s.reset()
    
    def reset(self):
        self.s.reset()
        self.s = Rsa.resetSolver(self)
