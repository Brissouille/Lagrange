from Cipher.aes import Aes
from z3 import *
from copy import deepcopy

def init_aes_components(message_num):
    A = [0] * 4
    K3 = [0] * 4
    K4 = [0] * 4
    for j in range(4):
        A[j] = BitVecs(["A_"+str(message_num)+"_%02d_%02d" %(j, i) for i in range(4)], 8)
        K3[j] = BitVecs(["K3_%02d_%02d" %(j, i) for i in range(4)], 8)
        K4[j] = BitVecs(["K4_%02d_%02d" %(j, i) for i in range(4)], 8)
    return A, K3, K4

key = ["000102030405060708090a0b0c0d0e0f",
       "d6aa74fdd2af72fadaa678f1d6ab76fe",
       "b692cf0b643dbdf1be9bc5006830b3fe",
       "b6ff744ed2c2c9bf6c590cbf0469bf41",
       "47f7f7bc95353e03f96c32bcfd058dfd",
       "3caaa3e8a99f9deb50f3af57adf622aa",
       "5e390f7df7a69296a7553dc10aa31f6b",
       "14f9701ae35fe28c440adf4d4ea9c026",
       "47438735a41c65b9e016baf4aebf7ad2",
       "549932d1f08557681093ed9cbe2c974e",
       "13111d7fe3944a17f307a78b4d2b30c5"
       ]
message = ""
test1 = 0
test2 = 0
s = Solver()
x = BitVec("x", 8)
y1 = BitVecs(["y1_%02x" % i for i in range(256)], 8)
y2 = BitVecs(["y2_%02x" % i for i in range(256)], 8)
a = 0x0
aes_tmp = Aes(128, "m")
s.add(aes_tmp.s.assertions())
for i in range(0, 1):
    for j in range(256):
        message1 = "00" * i + "{:02X}".format(j) + "00" * (15-i)
        message2 = "00" * ((i+1)%16) + "{:02X}".format(j) + "00" * ((15-i-1)%16)
        
        # Encryption
        aes_tmp.reset()
        cipher1  = aes_tmp.encrypt(key[0], message1)

        aes_tmp.reset()
        cipher2  = aes_tmp.encrypt(key[0], message2)
   
        # Active index
        s.add(aes_tmp.subByte_f1(int(cipher1[i*2:(i+1)*2], 16) ^ x ) == y1[j])

        # Passive index = Active + 1 
        s.add(aes_tmp.subByte_f1(int(cipher2[(i*2):(i+1)*2], 16) ^ x ) == y2[j])
        
        test1 = test1 ^ y1[j]
        test2 = test2 ^ y2[j]

    s.add(test1 == 0)
    s.add(test2 == 0)
    print("Checking")

    while(s.check() == sat):
        a = str((s.model().evaluate(x)))
        print("{:02X}".format(int(a)))
        s.add(x!= a)

    print("End checking")
