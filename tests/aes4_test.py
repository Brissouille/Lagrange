from Cipher.aes import Aes
from z3 import *

aes_tmp = Aes(128, "m")
key = "2B7E151628AED2A6ABF7158809CF4F3C"
message = ""
test = 0
s = Solver()

for j in range(16):
    print("Fin des chiffrements pour la case %d" %j)
    test = 0
    for i in range(0, 256):
        aes_tmp.reset()
        aes_tmp = Aes(128, "m"+"{:02d}".format(j*256+i))
        message = "00" * j + "{:02X}".format(i) + "00" * (15-j)
        cipher = aes_tmp.encrypt(key, message)
        aes_tmp.reset()
        aes_tmp.addMessage(message)
        aes_tmp.addCipher(cipher)
        print("Ajout dans le systeme (%d, %d)" %(j, i))
        s.add(aes_tmp.s.assertions())
        test = test ^ aes_tmp.cipher[-2][j//4][j%4]
    s.add(test == 0)

print(s.check())
print(s.model().evaluate(aes_tmp[0][0].getKeyRound(0)))

