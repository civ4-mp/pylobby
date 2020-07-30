# Based on code copied or translated from works: GsOpenSDK, ALuigi's projects, dwc_network_server_emulator, possibly other sources

from typing import Optional, Tuple

# 6 functions related to SB Crypting
SCHALLCONST = b"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"


class GOACryptState:
    cards: bytearray
    rotor: int
    ratchet: int
    avalanche: int
    last_plain: int
    last_cipher: int

    def __init__(self):
        self.cards = bytearray([i for i in range(256)])

    # 1/5
    def keyrand(
        self,
        limit: int,
        mask: int,
        user_key: bytes,
        keysize: int,
        rsum: int,
        keypos: int,
    ) -> Tuple[int, int, int]:
        if limit == 0:
            return 0, rsum, keypos
        retry_limiter = 0
        while True:
            rsum = (self.cards[rsum] + user_key[keypos]) % 256
            keypos += 1
            keypos %= 256
            if keypos >= keysize:
                keypos = 0
                rsum = (rsum + keysize) % 256
            u = mask & rsum
            if retry_limiter > 11:
                u %= limit
            retry_limiter += 1
            if u <= limit:
                break
        return u, rsum, keypos

    # 2/5
    def GOACryptPreStart(self, key: bytes) -> None:
        rsum = 0
        keypos = 0
        mask = 255
        for i2c in range(255, 0, -1):  # 255-1
            toswap, rsum, keypos = self.keyrand(i2c, mask, key, 8, rsum, keypos)
            self.cards[i2c], self.cards[toswap] = self.cards[toswap], self.cards[i2c]
            if (i2c & (i2c - 1)) == 0:
                mask >>= 1
        self.rotor = self.cards[1]
        self.ratchet = self.cards[3]
        self.avalanche = self.cards[5]
        self.last_plain = self.cards[7]
        self.last_cipher = self.cards[rsum]
        rsum = 0
        keypos = 0

    # 3/5
    def SBCryptStart(self, qfromkey: bytes, cchal: bytes, schal: bytes) -> bytes:
        sklen = len(qfromkey)
        thekey = bytearray(cchal)
        for i in range(0, len(schal)):
            thekey[(i * qfromkey[i % sklen]) % 8] ^= (
                (thekey[i % 8] ^ schal[i]) & 255
            ) % 256
        self.GOACryptPreStart(thekey)
        return thekey

    # 4/5
    def GOAEncrypt(self, bp: bytes) -> bytes:
        ret = bytearray(bp)
        rotor = self.rotor
        ratchet = self.ratchet
        avalanche = self.avalanche
        last_plain = self.last_plain
        last_cipher = self.last_cipher
        for i in range(0, len(ret)):
            ratchet += self.cards[rotor]
            ratchet %= 256
            rotor += 1
            rotor %= 256
            swaptemp = self.cards[last_cipher]
            self.cards[last_cipher] = self.cards[ratchet]
            self.cards[ratchet] = self.cards[last_plain]
            self.cards[last_plain] = self.cards[rotor]
            self.cards[rotor] = swaptemp
            avalanche += self.cards[swaptemp]
            avalanche %= 256
            last_cipher = (
                ret[i]
                ^ self.cards[(self.cards[avalanche] + swaptemp) & 255]
                ^ self.cards[
                    self.cards[
                        (
                            self.cards[last_plain]
                            + self.cards[last_cipher]
                            + self.cards[ratchet]
                        )
                        & 255
                    ]
                ]
            ) % 256
            last_plain = ret[i]
            ret[i] = last_cipher
        self.rotor = rotor
        self.ratchet = ratchet
        self.avalanche = avalanche
        self.last_plain = last_plain
        self.last_cipher = last_cipher
        return ret

    # 5/5
    def GOADecrypt(self, bp: bytes) -> bytes:
        ret = bytearray(bp)
        rotor = self.rotor
        ratchet = self.ratchet
        avalanche = self.avalanche
        last_plain = self.last_plain
        last_cipher = self.last_cipher
        for i in range(0, len(ret)):
            ratchet += self.cards[rotor]
            ratchet %= 256
            rotor += 1
            rotor %= 256
            swaptemp = self.cards[last_cipher]
            self.cards[last_cipher] = self.cards[ratchet]
            self.cards[ratchet] = self.cards[last_plain]
            self.cards[last_plain] = self.cards[rotor]
            self.cards[rotor] = swaptemp
            avalanche += self.cards[swaptemp]
            avalanche %= 256
            last_plain = (
                ret[i]
                ^ self.cards[(self.cards[avalanche] + self.cards[rotor]) & 255]
                ^ self.cards[
                    self.cards[
                        (
                            self.cards[last_plain]
                            + self.cards[last_cipher]
                            + self.cards[ratchet]
                        )
                        & 255
                    ]
                ]
            ) % 256
            last_cipher = bp[i]
            ret[i] = last_plain
        self.rotor = rotor
        self.ratchet = ratchet
        self.avalanche = avalanche
        self.last_plain = last_plain
        self.last_cipher = last_cipher
        return ret


# 0/5
def SBpreCryptHeader() -> bytes:
    data = b""
    data += bytes([2 ^ 236])  # number of random bytes to follow xor \xEC
    data += b"\x01"
    data += b"\x01"
    data += bytes([15 ^ 234])  # challenge len(15) xor \xEA
    data += SCHALLCONST
    return data


# f = GOACryptState()
# f1 = GOACryptState()

# f.SBCryptStart(bytearray('\x20'+'\x21'*4+'\x22'),bytearray('\x2b'+'\x2c'*6+'\x2d'),bytearray('\x36'+'\x37'*6+'\x38'))
# f1.SBCryptStart(bytearray('\x20'+'\x21'*4+'\x22'),bytearray('\x2b'+'\x2c'*6+'\x2d'),bytearray('\x36'+'\x37'*6+'\x38'))

# enc1 = f.GOAEncrypt(bytearray('soplykita'))
# print enc1
# dec1 = f1.GOADecrypt(enc1)
# print dec1
