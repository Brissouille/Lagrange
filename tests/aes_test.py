from Cipher.aes import Aes

aes = Aes(128, "m")
key = "2B7E151628AED2A6ABF7158809CF4F3C"
message = "3243F6A8885A308D313198A2E0370734"
iv = "00"*16

aes.reset()

cipher = aes.encrypt(key, message)

print(cipher)

aes.reset()

message = aes.decrypt(key, cipher)
print(message)


