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
        
        self.message = Int("message")
        self.phi_n = Int("phi_n")
        self.n = Int("n")
        self.size_module = size_module

        self.exponentiation()

        self.s = Solver()

    def exponentiation(self):
        self.cipher = 1
        for i in range(0, self.size_module):
            self.cipher = self.cipher * self.cipher
            multiply = If(self.d[i]==0x01, self.message, 1)
            self.cipher = (self.cipher * multiply) % self.n

    def encrypt(self, public_exponent, modulus, message):
        self.addPublicExponent(public_exponent)
        self.addMessage(message)
        self.addModulus(modulus)
        self.s.check()
        print(self.s.model().evaluate(self.cipher))
   
    def addPrivateExponent(self, d):
        # d is in hexadecimal format
        for i in range(0, self.size_module, 2):
            self.s.add(self.d[i]== d[i:i+2])

    def addPublicExponent(self, e):
        # e is in hexadecimal format
        for i in range(0, self.size_module, 2):
            self.s.add(self.e[i]==e[i:i+2])
    
    def addModulus(self, module):
        # modulus is in hexadecimal format
        self.s.add(self.n== int(module, 16))
    
    def addMessage(self, message):
        # message is in hexadecimal format
        self.s.add(self.message== int(message, 16))
    
    def decrypt(self, message):
        pass
