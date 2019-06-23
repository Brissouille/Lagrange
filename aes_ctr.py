from .aes_mode import Aes_Mode

class Aes_Ctr(Aes_Mode):
    def __init__(self, keylength, size_message):
        super().__init__(keylength, size_message)

    def init_mode(self, s):
        for b in range(0, self.blocks):
            self.aes[b].s.reset()
            for i in range(4):
                for j in range(4):
                    s.add(self.aes[b].message[i][j] == self.iv[i][j] + b)
                    s.add(self.cipher[b][i][j] == self.aes[b].cipher[i][j] ^ self.message[b][i][j])

