from Cipher.rsa import Rsa

size_module = 16
rsa = Rsa(size_module)

p = 61
q = 251

e = "3"
d = "3"
modulus = "3bcf" # p * q

message = "5f"

cipher = rsa.encrypt(e, modulus, message)
print(cipher)

rsa.reset()

plain = rsa.decrypt(d, modulus, cipher)
print(plain)
