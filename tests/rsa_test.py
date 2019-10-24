from Cipher.rsa import Rsa

size_module = 32
rsa = Rsa(size_module)

#e = 511*"0"+"3"
#d="77ef1bf1a71602b007c311a55f7b5f1f1154c0f869d79fcd23b3272758ce17be256878da268b689a2eb7f5add0b0a1d760647261338c9063d17480c895134078e2c1a10d2f97db76fcbc5ca055da200932e0feb101b90fb4186570e7cda10e4d6999698594f66c96517b5abe2779684c51f606e9337756c360269e0e7df7be14f9c8da6230167f9d56516b1d63939100a17431ef4c0d132605f139dca671faf26e02bf1d565ef250718efd3fdc20bd022660fafb52a5cdacb04db1484dedb2c524e7e0ec0258460e98e38966f2e36eb5795adc00144ef43e4742ce69d403fe1ba183426c4675a5fbb7924a6b9a195b32c0b53b84c7f17813ec1714599f1935cb"

#modulus = "00b3e6a9ea7aa104080ba49a780f390eae99ff21749ec36fb3b58cbabb0535239d381cb54739d11ce74613f084b908f2c31096ab91cd52d895ba2ec12cdf9ce0b554227193c763c9327b1a8af080c7300dcc517e098295978e2498295bb47195741e661e485f71a2e17a39081d3b361c727af10a5dcd3302251039ed15bcf39d21249525a638ff9a7ee617c318ae61cfbaf5d011401361e1ea985f30e62148e799ef3140e8ef0fb30ca725b811ca9e6a52ec9fb80af96f2ffaa580222b8292bba3d2387ad0e40c673cc3acc66f99bb092af3e393dd7481eef9852bf5fc603bed12115078d5d7bd595128ecc9940b49b0f0c7874bf153b7c1c444ec8aafd83ad47f"

#message = "0"*255+"8"+"0"*256+"5f"

#rsa.coppersmith("24e7e0ec0258460e98e38966f2e36eb5795adc00144ef43e4742ce69d403fe1ba183426c4675a5fbb7924a6b9a195b32c0b53b84c7f17813ec1714599f1935cb")

# 512
#modulus = "00bd79e614800471cb8bfc1e9700a9a51cf56d7d9d2efe0519a0114921f5e1d9266fed389d1006b869c378627391d52cb68bac0105111367691e3d6df613bfc7b9"

#e = "3"

#d = "7e51440daaada1325d52bf0f55c66e134e48fe68c9feae111560db6bf9413b6dcf3088b82ac99b22fba71bd8c4e182357ecdcd175b79d091713cbc94f137b1a3"

#message = "0"*63+"8"+"0"*63+"5f"

# 32
p = 57899
q = 55487

modulus = "bf7d0615"
e = "00000003"
d = "7fa78773"

message = "0000d000"

cipher = rsa.encrypt(e, modulus, message)
print(cipher)

rsa.reset()

plain = rsa.decrypt(d, modulus, cipher)
print(plain)

rsa.reset()

#rsa.addModulus(modulus)
#rsa.addPublicExponent(e)
#d_len = len(d)
#rsa.coppersmith(d[d_len*3//4:])

rsa.crt_init(2)
l = [["3","5"], ["8","B"]]
x = rsa.crt_exploit(l, "3")
print(x)
