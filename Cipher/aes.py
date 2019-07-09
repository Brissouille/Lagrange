from z3 import *

class Aes():
   
    masterkey = [0] * 8 

    def __init__(self, keylength, prefix="message"):
        self.keylength = keylength
  
        # Number of column  (Aes128->4, AES192->6, AES256->8)
        self.Nk = keylength//32

        # Nomber of rounds
        self.Nr = self.Nk+6
        
        self.keyRounds = [0] * (self.Nr + 1)

        # Init with column order
        for j in range(self.Nk):
            self.masterkey[j] = BitVecs(["masterkey_%02d_%02d" %(j, i) for i in range(4)], 8)
       
        self.message = [0] * 4
        for j in range(4):
            self.message[j] = BitVecs([prefix+"_%02d_%02d" %(j, i) for i in range(4)], 8)
        
        self.cipher = [0] * (self.Nr + 1)
        for i in range(self.Nr+1):
            self.cipher[i] = [0] * 4
            for j in range(4):
                self.cipher[i][j] = [0] * 4
                for k in range(4):
                    if(i==0):
                        self.cipher[i][j][k] = self.message[j][k]
                    else:
                        self.cipher[i][j][k] = 0

        self.s = Aes.resetSolver(self)
      
        # Init keyRounds
        self.keyRounds = self.expandKey()

        # Init encryption algorithm
        self.encryption()

    def expandKey(self):
        rc = [ 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF]

        tmp_key = [0] * (self.Nr+1)*4

        # loop for all rounds, all columns 
        for i in range(0, (self.Nr+1)*4):
            tmp_key[i] = [0] * 4
            if(i <self.Nk):
                # we initialize with the masterKey
                for j in range(4):
                    tmp_key[i][j] = self.masterkey[i][j]    
            else:
                # To choose the correct index of rc
                l = i // self.Nk - 1
                # we prepare xor
                tmp_rc = [rc[l], 0, 0, 0]

                for j in range(4):
                    tmp_key[i][j] = 0 
                    # the first column is treated differently
                    if (i%self.Nk) == 0:
                        tmp_key[i][j] = tmp_key[i-self.Nk][j] ^ self.subByte_f(tmp_key[i-1][(j+1)%4]) ^ tmp_rc[j]
                    # for Aes256
                    elif self.Nk>6 and (i%self.Nk)==4:
                        tmp_key[i][j] = tmp_key[i-self.Nk][j] ^ self.subByte_f(tmp_key[(i-1)][j]) 
                    else:
                        tmp_key[i][j] = tmp_key[i-self.Nk][j] ^ tmp_key[i-1][j]
       
        keyRounds = [0] * (self.Nr+1)
        for i in range(0, self.Nr+1):
            keyRounds[i] = [0] * 4
            for j in range(0, 4):
                keyRounds[i][j] = [0] * 4
                for k in range(0, 4):
                    keyRounds[i][j][k] = tmp_key[i*4+j][k]
       
        return keyRounds
   
    def mult1(self, x):
        #Just for coherence
        return x

    def mult2(self, x):
        #  mult in GF(2^8)
        # %256 beacause BitVecVal(128, 8) == -1
        return ((x<<1)%256) ^ (0x1b * ((x>>7) & 1))
    
    def mult3(self, x):
        # 3 = 2 ^ 1 so x*3 = x*2 ^ x
        return self.mult2(x) ^ x

    def subByte(self, lap):
        for i in range(4):
            tmp = [self.subByte_f(self.cipher[lap-1][k][i]) for k in range(4)]
            for j in range(4):
                self.cipher[lap][j][i] = tmp[(j+i)%4]

    def mixColumn(self, l):
        matrix = [[self.mult2, self.mult3, self.mult1, self.mult1], 
                  [self.mult1, self.mult2, self.mult3, self.mult1], 
                  [self.mult1, self.mult1, self.mult2, self.mult3], 
                  [self.mult3, self.mult1, self.mult1, self.mult2]]
        
        for c in range(4):
            column = self.cipher[l][c]
            a = [0] * len(column)
            for i in range(4):
                for j in range(4):
                    a[i] = a[i] ^ matrix[i][j](column[j])
            self.cipher[l][c] = a

    def addRoundKey(self, lap):
        key = self.keyRounds[lap]
        # column order
        for i in range(4):
            for j in range(4):
                self.cipher[lap][i][j] = self.cipher[lap][i][j] ^ key[i][j]
    
    def encryption(self):
        self.addRoundKey(0)
        for l in range(1, self.Nr):
            # SubByte and shiftRow line order
            self.subByte(l)

            # MixColumn column order
            self.mixColumn(l)
            
            # Adding the key
            self.addRoundKey(l)
        
        # SubByte and shiftRow of last roudns - line order 
        for i in range(4):
            tmp = [self.subByte_f(self.cipher[self.Nr-1][k][i]) for k in range(4)]
            for j in range(4):
                self.cipher[self.Nr][j][i] = tmp[(j+i)%4]

        self.addRoundKey(self.Nr)
    
    def encrypt(self, key, plain):
        Aes.reset(self)
        #Column order 
        for i in range(0, self.Nk):
            for j in range(0,4):
                self.addPartialKey(i//4, i%4, j, int(key[2*(i*4+j):2*(i*4+j+1)], 16))
        self.addMessage(plain)
        sat_resp = self.s.check()
        solution = []
        if (sat_resp==sat):
            test = type(BitVecVal(0xcafe, 8))
            for i in range(4):
                for j in range(4):
                    toto = self.s.model().evaluate(self.cipher[self.Nr][i][j])
                    solution.append(int(str(toto)))

        elif(sat_resp==unknown):
            print("#"*25)
        else:
            print("No Solution")
        return solution
    
    def decrypt(self, key, cipher):
        Aes.resetSolver(self)
        #Column order 
        for i in range(0, self.Nk):
            for j in range(0, 4):
                self.addPartialKey(i//4, i%4, j, int(key[2*(i*4+j):2*(i*4+j+1)], 16))
        self.addCipher(cipher)
        sat_resp = self.s.check()
        solution = []
        if (sat_resp==sat):
            for i in range(4):
                for j in range(4):
                    toto = self.s.model().evaluate(self.message[i][j])
                    solution.append(int(str(toto)))
        
        elif(sat_resp==unknown):
            print("#"*25)

        else:
            print("No Solution")
        return solution

    def addCipher(self, value):
        # Column order to insert
        for i in range(4):
            for j in range(4):
                # *2 to find the indice of the byte
                self.s.add(self.cipher[self.Nr][i][j]==int(value[2*(i*4+j):2*(i*4+j+1)],16))

    def addMessage(self, value):
        # Column order to insert
        for i in range(4):
            for j in range(4):
                # *2 to find the indice of the byte
                self.s.add(self.message[i][j]==int(value[2*(i*4+j):2*(i*4+j+1)],16))

    def addPartialKey(self, lap, column, line, value):
        self.s.add(self.keyRounds[lap][column][line]==value)

    def reset(self):
        self.s.reset()
        self.s = Aes.resetSolver(self)

    def resetSolver(self):
        s = Solver()
        # Init solver with Sboxes
        for i in range(256):
            s.add(self.subByte_f(i)==self.sbox_tab[i])
        return s

    def check(self):
        sat_resp = self.s.check()
        if (sat_resp==sat):
            #print("Solution found")
            l=0
            a=[]
            print(self.getKeyRound(0)) 
        elif(sat_resp==unknown):
            print("#"*25)
        else:
            print("No Solution")
            l=1
            for i in range(4):
                for j in range(4):
                    print(self.keyRounds[l][i][j])
  
    def getKeyRound(self, lap):
        string = ""
        sat_aes = self.s.check()
        for i in range(self.Nk):
            for j in range(4):
                value = self.s.model().evaluate(self.keyRounds[lap][i][j])
                test = type(BitVecVal(0xcafe, 8))
                # if printable
                if(type(value) == test):
                    value = int(str(value))
                    if(value < 16):
                        value = "0"+hex(value)[2:]
                    else:
                        value  = hex(value)[2:]
                    string = string + value
                else:
                    string = string + "\n" + str(value)  + "\n"

        return string

    subByte_f = Function('subByte_f', BitVecSort(8), BitVecSort(8))

    sbox_tab =  \
   [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67,
    0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59,
    0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7,
    0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1,
    0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05,
    0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83,
    0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29,
    0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa,
    0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c,
    0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc,
    0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
    0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
    0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
    0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4,
    0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
    0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70,
    0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9,
    0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e,
    0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1,
    0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0,
    0x54, 0xbb, 0x16]

    
