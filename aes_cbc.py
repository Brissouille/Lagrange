from .aes_mode import Aes_Mode

class Aes_Cbc(Aes_Mode):
    def __init__(self, keylength, size_message):
        super().__init__(keylength, size_message)

    def init_mode(self, s):
        for i in range(4):
            for j in range(4):
                s.add(self.aes[0].message[i][j] == self.message[0][i][j] ^ self.iv[i][j])
                s.add(self.aes[0].cipher[i][j] == self.cipher[0][i][j] )

        # We add all the assertions of the other system of equation
        for b in range(1, self.blocks):
            self.aes[b].s.reset()
            for i in range(4):
                for j in range(4):
                    s.add(self.aes[b].message[i][j] == self.message[b][i][j] ^ self.aes[b-1].cipher[i][j])
                    s.add(self.aes[b].cipher[i][j] == self.cipher[b][i][j])

