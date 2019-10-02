from Cipher.aes_mode import Aes_Cbc, Aes_Cfb, Aes_Ofb, Aes_Ctr 

aes = [Aes_Cbc(128, 32), Aes_Cfb(128, 32), Aes_Ofb(128, 32), Aes_Ctr(128, 32)]
key = "61"*16
message = "000102030405060708090a0b0c0d0e0f"+"01"*16
iv = "00"*16

c_message=[
        "9bc9a67b992e085b8c0cf0dd6f6e4c56d721f105d34c298f6adc941b5507c63f",
        "dc3b2e4aae3d5d0b6f4bd3c827151c1aa9f10d6e31bd5127d90dbdd7d2e5b3d7",
        "dc3b2e4aae3d5d0b6f4bd3c827151c1a425d7d9d1233c479fedd854b9d96c5aa",
        "dc3b2e4aae3d5d0b6f4bd3c827151c1a4115a3766227beaca4087d91d2b74e93"]

for i in range(len(aes)):
    aes[i].reset()
    a = aes[i].encrypt(key, message, iv)
    print(a)

    aes[i].reset()
    a = aes[i].decrypt(key, c_message[i], iv)
    print(a)
