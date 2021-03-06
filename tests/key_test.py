from Cipher.aes import Aes

key_test = ["000102030405060708090a0b0c0d0e0f",
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
            

s = 128
aes = Aes(s, "message")

aes.reset()

for l in range(10,11):
    for i in range(0,4):
        for j in range(0,2):
            aes.addPartialKey(l, j, i, int(key_test[l][2*(j*4+i):2*(j*4+i+1)], 16)) 
        for j in range(2,4):
            aes.addPartialKey(l-1, j, i, int(key_test[l-1][2*(j*4+i):2*(j*4+i+1)], 16)) 
	
solution = aes.check()
print(solution)
