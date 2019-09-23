from Cipher.rsa import Rsa

size_module = 8
rsa = Rsa(size_module)

exponent = "03"
modulus = "ff"
message = "89"

rsa.encrypt(exponent, modulus, message)
