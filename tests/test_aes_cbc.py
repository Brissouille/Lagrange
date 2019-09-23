from Cipher.aes_mode import Aes_Cbc

aes = Aes_Cbc(128, 32)
key = "61"*16
message = "62" * 32
iv = "63"*16

aes.reset()

aes.encrypt(key, message, iv)

aes.decrypt(key, "c27a9f26824c53ce9891804569b0e62b20b2a172c9f22bf493b851c7a94addb9", iv)

