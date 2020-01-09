from Cipher.rsa import Rsa

size_module = 512
rsa = Rsa(size_module)

dest_number = 2

rsa.crt_init(dest_number)

n1 = "00d138fba552a1b2d84d2b1395f271f5feb7431ed0dea639c133dd5d58adf0e60f"
m1 = 

n2 = "00c40a8177833d82e7841849eefb9d87cd3154b6181f2ce067efdf79e82dbbee95"
m2 = 

l = [[m1,n1], [m2,n2]]
x = rsa.crt_exploit(l, "3")
print(x)
