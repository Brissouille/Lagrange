from Cipher.aes import Aes
from z3 import *
from copy import deepcopy

def create_delta_set(i, key):
    aes_tmp = Aes(128, "m")
    cipher1 = []
    cipher2 = []
    for j in range(256):
        message1 = "00" * i + "{:02X}".format(j) + "00" * (15-i)
        message2 = "00" * ((i+1)%16) + "{:02X}".format(j) + "00" * ((15-i-1)%16)
        
        # Encryption
        aes_tmp.reset()
        cipher1.append(aes_tmp.encrypt(key, message1))

        aes_tmp.reset()
        cipher2.append(aes_tmp.encrypt(key, message2))

    return cipher1, cipher2

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
s = Solver()
x = BitVec("x", 8)
y1 = BitVecs(["y1_%02x" % i for i in range(256)], 8)
y2 = BitVecs(["y2_%02x" % i for i in range(256)], 8)
aes_tmp = Aes(128, "m")
key4 = []

for i in range(0, 16):
    s.reset()
    s.add(aes_tmp.s.assertions())
    cipher1, cipher2 = create_delta_set(i, key[0])
    test1 = 0
    test2 = 0
    for j in range(256):
        # Active index
        s.add(aes_tmp.subByte_f1(int(cipher1[j][i*2:(i+1)*2], 16) ^ x) == y1[j])

        # Passive index = Active + 1 
        s.add(aes_tmp.subByte_f1(int(cipher2[j][i*2:(i+1)*2], 16) ^ x) == y2[j])
        
        test1 = test1 ^ y1[j]
        test2 = test2 ^ y2[j]

    s.add(test1 == 0)
    s.add(test2 == 0)
    print("Checking for key[%d][%d]" %(i//4, i%4) )

    while(s.check() == sat):
        a = str((s.model().evaluate(x)))
        print("{:02X}".format(int(a)))
        s.add(x!= a)
    key4.append(a)

    print("End checking")

aes_tmp.reset()
[aes_tmp.addPartialKey(4, i//4, i%4, key4[i]) for i in range(16)]
print("Key Found")
print(aes_tmp.check())


