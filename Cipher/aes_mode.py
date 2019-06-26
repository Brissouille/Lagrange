from z3 import *
from .aes import Aes

class Aes_Mode():
    def __init__(self, keylength, size_message): 
        # Init the solver
        self.s = Solver()

        # The message must be a mutliple of 16 bytes
        assert((size_message!=0)%16)
        self.blocks = size_message // 16
        
        # Init message and cipher
        self.message = [0] * self.blocks
        self.cipher = [0] * self.blocks

        # Aes list
        self.aes = [0] * self.blocks
              
        # Init iv and first message
        self.iv = [0] * 4
        for i in range(4):
            self.iv[i] = [0] * 4
            for j in range(4):
                self.iv[i][j] = BitVec("iv_%02d_%02d" %(i, j), 8)

        self.message[0] = [0] * 4
        self.cipher[0] = [0] * 4
        # Init message
        for b in range(0, self.blocks):
            # Init message and cipher of the Aes_Cbc class
            self.message[b] = [0] * 4
            self.cipher[b] = [0] * 4

            # Init each Aes with a different plaintext name
            self.aes[b] = Aes(keylength, "m"+str(b))

            # We init mi in the Aes class by the Mi ^ Ci-1 in the Aes_Cbc class
            for i in range(4):
                self.message[b][i] = [0] * 4
                self.cipher[b][i] = [0] * 4
                for j in range(4):
                    self.message[b][i][j] = BitVec("M%02d_%02d_%02d" %(b, i, j), 8)
                    self.cipher[b][i][j] = BitVec("C%02d_%02d_%02d" %(b, i, j), 8)
       
        self.reset()

    def toString(self, attribut_key):
        for b in range(self.blocks):
            for i in range(4):
                for j in range(4):
                    print("{:02x}".format(int(str(self.s.model().evaluate(self.__dict__[attribut_key][b][i][j])))), end='')
            print('', end=' ')
        print()

    def check(self):
        return self.s.check()
        
        
    def addIv(self, iv):
        for i in range(4):
            for j in range(4):
                self.s.add(self.iv[i][j]==int(iv[2*(4*i+j):2*(4*i+j+1)], 16))
    
    def addMessage(self, value):
        for b in range(self.blocks):
            for i in range(4):
                for j in range(4):
                    self.s.add(self.message[b][i][j] == int(value[2*(b*16+i*4+j):2*(b*16+i*4+j+1)],16))

    def encrypt(self, key, plaintext, iv):
        self.reset()
        plain_len = len(plaintext)

        padding = "0" * (self.blocks * 32 - plain_len)

        # We padd with zeroes bytes
        plaintext = plaintext + padding

        # Init iv in solver
        self.addIv(iv)

        # Add message in the solver
        self.addMessage(plaintext)

        # Add the key in one aes -> all aes are impacted
        for i in range(0, self.aes[0].Nk):
            for j in range(0, 4):
                self.aes[0].addPartialKey(i//4, i%4, j, int(key[2*(i*4+j):2*(i*4+j+1)], 16))

        # Before to check, we agregate the solver of the Aes class and the solver of the Aes_Cbc class
        for b in range(self.blocks):
            self.s.add(self.aes[b].s.assertions())
       
        # We resolve the system of equation and return the cipher
        if(self.check() == sat):
            cipher = self.toString("cipher")

        return cipher

    def addCipher(self, value):
        for b in range(self.blocks):
            for i in range(4):
                for j in range(4):
                    self.s.add(self.cipher[b][i][j] == int(value[2*(b*16+i*4+j):2*(b*16+i*4+j+1)],16))

    def decrypt(self, key, ciphertext, iv):
        self.reset()
        cipher_len = len(ciphertext)

        # Init iv in solver
        self.addIv(iv)

        # Add message in the solver
        self.addCipher(ciphertext)

        # Add the key in one aes -> all aes are impacted
        for i in range(0, self.aes[0].Nk):
            for j in range(0, 4):
                self.aes[0].addPartialKey(i//4, i%4, j, int(key[2*(i*4+j):2*(i*4+j+1)], 16))

        # Before to check, we agregate the solver of the Aes class and the solver of the Aes_Cbc class
        for b in range(self.blocks):
            self.s.add(self.aes[b].s.assertions())
        
        if(self.check() == sat):
            message = self.toString("message")

        return message

    def resetSolver(self):
        s = Solver()
        s.reset()
       
        # reset aes blocks
        for b in range(self.blocks):
            self.aes[b].reset()

        # Init the mode for the Aes
        self.init_mode(s)
        
        # Init only Sbox 
        s.add(self.aes[0].s.assertions())

        return s
            
    def reset(self):
        self.s = Aes_Mode.resetSolver(self)

    def init_mode(self, s):
        raise NotImplementedError("AES_Mode.init_mode() is an abstract function")

class Aes_Cbc(Aes_Mode):
    def __init__(self, keylength, size_message):
        super().__init__(keylength, size_message)

    def init_mode(self, s):
        for i in range(4):
            for j in range(4):
                s.add(self.aes[0].message[i][j] == self.message[0][i][j] ^ self.iv[i][j])
                s.add(self.aes[0].cipher[i][j] == self.cipher[0][i][j])

        # We add all the assertions of the other system of equation
        for b in range(1, self.blocks):
            self.aes[b].s.reset()
            for i in range(4):
                for j in range(4):
                    s.add(self.aes[b].message[i][j] == self.message[b][i][j] ^ self.aes[b-1].cipher[i][j])
                    s.add(self.aes[b].cipher[i][j] == self.cipher[b][i][j])

class Aes_Cfb(Aes_Mode):
    def __init__(self, keylength, size_message):
        super().__init__(keylength, size_message)

    def init_mode(self, s):
        for i in range(4):
            for j in range(4):
                s.add(self.aes[0].message[i][j] == self.iv[i][j])
                s.add(self.cipher[0][i][j] == self.aes[0].cipher[i][j] ^ self.message[0][i][j])

        # We add all the assertions of the other system of equation
        for b in range(1, self.blocks):
            self.aes[b].s.reset()
            for i in range(4):
                for j in range(4):
                    s.add(self.cipher[b][i][j] == self.aes[b].cipher[i][j] ^ self.message[b][i][j])
                    s.add(self.aes[b].message[i][j] == self.cipher[b-1][i][j])

class Aes_Ctr(Aes_Mode):
    def __init__(self, keylength, size_message):
        super().__init__(keylength, size_message)

    def init_mode(self, s):
        # We concatenate the initial vector for the addition. Concatenation is column order
        iv_int = Concat([self.iv[i][j] for i in range(4) for j in range(4)])
        
        for b in range(0, self.blocks):
            # Init the block aes ->  init causes the fail
            #self.aes[b].s.reset()
            
            # Increment the iv in fonction of the block number
            iv_tmp = iv_int + b
            
            # Init the solver for CTR 
            for i in range(4):
                for j in range(4):
                    indice_hi = ( ((3-i)*4 + (3-j) + 1) * 8 -1 )
                    indice_low = ( ((3-i)*4 + (3-j)) * 8 )

                    # Adding the iv in the solver
                    s.add(self.aes[b].message[i][j] == simplify(Extract(indice_hi, indice_low, iv_tmp)))

                    # Adding the xor between plain and encrypted iv in the solver
                    s.add(self.cipher[b][i][j] == self.aes[b].cipher[i][j] ^ self.message[b][i][j])

class Aes_Ofb(Aes_Mode):
    def __init__(self, keylength, size_message):
        super().__init__(keylength, size_message)

    def init_mode(self, s):
        for i in range(4):
            for j in range(4):
                s.add(self.aes[0].message[i][j] == self.iv[i][j])
                s.add(self.cipher[0][i][j] == self.aes[0].cipher[i][j] ^ self.message[0][i][j])

        # We add all the assertions of the other system of equation
        for b in range(1, self.blocks):
            self.aes[b].s.reset()
            for i in range(4):
                for j in range(4):
                    s.add(self.aes[b].message[i][j] == self.aes[b-1].cipher[i][j])
                    s.add(self.cipher[b][i][j] == self.aes[b].cipher[i][j] ^ self.message[b][i][j])

