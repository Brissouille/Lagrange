from Cipher.aes_hw import Aes_Hw

key_test = ["C0A6B0A6636D3AC7D7D3065BA70827D3",
             "F16AD6FA9207EC3D45D4EA66E2DCCDB5",
             "75D70362E7D0EF5FA204053940D8C88C",
             "103F676BF7EF883455EB8D0D15334581",
             "DB516B322CBEE30679556E0B6C662B8A",
             "F8A01562D41EF664AD4B986FC12DB3E5",
             "00CDCC1AD4D33A7E7998A211B8B511F4",
             "954F7376419C49083804EB1980B1FAED",
             "DD6226BB9CFE6FB3A4FA84AA244B7E47",
             "7591868DE96FE93E4D956D9469DE13D3",
             "5EECE074B783094AFA1664DE93C8770D"
         ]

s = 128
aes = Aes_Hw(s)

aes.reset()

#list_Hw = [aes.Hw(aes.keyRounds[j // 16][(j // 4) % 4][j % 4]) == aes.Hw_func(int(key_test[j // 16][(j%16)*2:((j%16)+1)*2], 16)) for j in range(176)]

lap = 0
list_key = [aes.keyRounds[lap][(j // 4)][j % 4] == int(key_test[lap][(j%16)*2:((j%16)+1)*2], 16) for j in range(16)]

c = 0
l = 1
list_key[c*4+l] = aes.keyRounds[lap][c][l] == 0x9B

key_guess = aes.check(list_key)

print("Key guess")
print(key_guess)
