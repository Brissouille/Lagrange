from Hash.sha2 import Sha2

sha2 = Sha2(256)
hash_result = sha2.digest("616263", 5)
print(hash_result)

#message = sha2.preimage(1, "5D6AEBCD6A09E667BB67AE853C6EF372FA2A4622510E527F9B05688C1F83D9AB")
#print(message)

message = sha2.preimage(5, "04409a6ad550f666c8c347a75a6ad9ad43ada24524e00850f92939eb78ce7989")
print(message)

#sha2.preimage(6, "2b4209f504409a6ad550f666c8c347a7714260ad43ada24524e00850f92939eb")
