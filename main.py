import hashlib
import math
import struct

# word_a = bytearray(b'\x67\x45\x23\x01')
# word_b = bytearray(b'\xEF\xCD\xAB\x89')
# word_c = bytearray(b'\x98\xBA\xDC\xFE')
# word_d = bytearray(b'\x10\x32\x54\x76')


# word_a = bytearray(b'\x01\x23\x45\x67')
# word_b = bytearray(b'\x89\xab\xcd\xef')
# word_c = bytearray(b'\xfe\xdc\xba\x98')
# word_d = bytearray(b'\x76\x54\x32\x10')

s_vals = {"round1": [3, 7, 11, 19],
          "round2": [3, 5, 9, 13],
          "round3": [3, 9, 11, 15]}


class MD4:
    def __init__(self, bytes_mess: bytes) -> None:

        self.word_a = 0x67452301
        self.word_b = 0xEFCDAB89
        self.word_c = 0x98BADCFE
        self.word_d = 0x10325476

        self.len_msg: int = len(bytes_mess)  # len in bytes

        # len = 448 mod 512 / Заполнение сообщения
        self.msg = bytes_mess + b"\x80" + (b"\x00" * ((56 - self.len_msg - 1) % 64))
        self.msg += struct.pack("<Q", self.len_msg * 8)


    def hash(self):
        for msg_bl in [self.msg[x: x + 64] for x in range(0, len(self.msg), 64)]:
            msg_blocks = list(struct.unpack("<16I", msg_bl))

            word_aa = self.word_a
            word_bb = self.word_b
            word_cc = self.word_c
            word_dd = self.word_d

            for k in range(16):
                if k % 4 == 0:
                    value = word_aa + self.func_f(word_bb, word_cc, word_dd) + msg_blocks[k]
                    value %= pow(2, 32)
                    word_aa = self.shift_rotate_to_left(value, s_vals['round1'][0])
                elif k % 4 == 1:
                    value = word_dd + self.func_f(word_aa, word_bb, word_cc) + msg_blocks[k]
                    value %= pow(2, 32)
                    word_dd = self.shift_rotate_to_left(value, s_vals['round1'][1])
                elif k % 4 == 2:
                    value = word_cc + self.func_f(word_dd, word_aa, word_bb) + msg_blocks[k]
                    value %= pow(2, 32)
                    word_cc = self.shift_rotate_to_left(value, s_vals['round1'][2])
                else:
                    value = word_bb + self.func_f(word_cc, word_dd, word_aa) + msg_blocks[k]
                    value %= pow(2, 32)
                    word_bb = self.shift_rotate_to_left(value, s_vals['round1'][3])
            const_vector = 0x5A827999
            for k in [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]:

                if 0 <= k <= 3:
                    value = word_aa + self.func_g(word_bb, word_cc, word_dd) + msg_blocks[k] + const_vector
                    value %= pow(2, 32)
                    word_aa = self.shift_rotate_to_left(value, s_vals["round2"][0])
                elif 4 <= k <= 7:
                    value = word_dd + self.func_g(word_aa, word_bb, word_cc) + msg_blocks[k] + const_vector
                    value %= pow(2, 32)
                    word_dd = self.shift_rotate_to_left(value, s_vals["round2"][1])
                elif 8 <= k <= 11:
                    value = word_cc + self.func_g(word_dd, word_aa, word_bb) + msg_blocks[k] + const_vector
                    value %= pow(2, 32)
                    word_cc = self.shift_rotate_to_left(value, s_vals["round2"][2])
                else:
                    value = word_bb + self.func_g(word_cc, word_dd, word_aa) + msg_blocks[k] + const_vector
                    value %= pow(2, 32)
                    word_bb = self.shift_rotate_to_left(value, s_vals["round2"][3])

            const_vector = 0x6ED9EBA1
            for k in [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]:
                if 0 <= k <= 3:
                    value = word_aa + self.func_h(word_bb, word_cc, word_dd) + msg_blocks[k] + const_vector
                    value %= pow(2, 32)
                    word_aa = self.shift_rotate_to_left(value, s_vals["round3"][0])
                elif 4 <= k <= 7:
                    value = word_cc + self.func_h(word_dd, word_aa, word_bb) + msg_blocks[k] + const_vector
                    value %= pow(2, 32)
                    word_cc = self.shift_rotate_to_left(value, s_vals["round3"][2])
                elif 8 <= k <= 11:
                    value = word_dd + self.func_h(word_aa, word_bb, word_cc) + msg_blocks[k] + const_vector
                    value %= pow(2, 32)
                    word_dd = self.shift_rotate_to_left(value, s_vals["round3"][1])
                else:
                    value = word_bb + self.func_h(word_cc, word_dd, word_aa) + msg_blocks[k] + const_vector
                    value %= pow(2, 32)
                    word_bb = self.shift_rotate_to_left(value, s_vals["round3"][3])

            self.word_a = (self.word_a + word_aa) % pow(2, 32)
            self.word_b = (self.word_b + word_bb) % pow(2, 32)
            self.word_c = (self.word_c + word_cc) % pow(2, 32)
            self.word_d = (self.word_d + word_dd) % pow(2, 32)

        hash_ = struct.pack("<4L", *[self.word_a, self.word_b, self.word_c, self.word_d])
        return hash_

    @staticmethod
    def func_f(x_word: int, y_word: int, z_word: int) -> int:
        return (x_word & y_word) | (~x_word & z_word)

    @staticmethod
    def func_g(x_word: int, y_word: int, z_word: int) -> int:
        return (x_word & y_word) | (x_word & z_word) | (y_word & z_word)

    @staticmethod
    def func_h(x_word: int, y_word: int, z_word: int) -> int:
        return x_word ^ y_word ^ z_word

    @staticmethod
    def shift_rotate_to_left(vector: int, rotation_value: int) -> int:
        left_bits = (vector << rotation_value) & 0xFFFFFFFF
        right_bits = vector >> (32 - rotation_value)
        return left_bits | right_bits

    @staticmethod
    def sum_mod2pow32(vector_1: int, vector_2: int):
        return (vector_1 + vector_2) % pow(2, 32)


text = ''
msg = text.encode('utf-8')

hashObject = hashlib.new('md4', msg).hexdigest()
print(f"Hashlib -- {hashObject}")
print(f'My hash -- {MD4(msg).hash().hex()}')
