from Cipher.rsa import Rsa

size_module = 16
rsa = Rsa(size_module)

p = 61
q = 251

e = "3"
d = "3"
modulus = "3bcf" # p * q

message = "5f"

rsa.encrypt(e, modulus, message)
rsa.reset()
rsa.decrypt(d, modulus, "3ba6")
