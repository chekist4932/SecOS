import hashlib
import math
import struct

s_vals = {"round1": [3, 7, 11, 19],
          "round2": [3, 5, 9, 13],
          "round3": [3, 9, 11, 15]}


class MD4:
    def __init__(self, bytes_mess: bytes) -> None:

        self.constants = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]

        self.len_msg: int = len(bytes_mess)  # len in bytes

        # len = 448 mod 512 / Заполнение сообщения
        padding_len = (56 - self.len_msg - 1) % 64
        self.msg = bytes_mess + b"\x80" + (b"\x00" * padding_len)
        self.msg += struct.pack("<Q", self.len_msg * 8)

    def hash(self):
        const = self.constants.copy()
        for msg_blocks in [self.msg[x: x + 64] for x in range(0, len(self.msg), 64)]:

            word_blocks = list(struct.unpack("<16I", msg_blocks))

            A = const[0]
            B = const[1]
            C = const[2]
            D = const[3]

            for k in range(16):
                if k % 4 == 0:
                    value = A + self.func_f(B, C, D) + word_blocks[k]
                    value %= pow(2, 32)
                    A = self.shift_rotate_to_left(value, s_vals['round1'][k % 4])
                elif k % 4 == 1:
                    value = D + self.func_f(A, B, C) + word_blocks[k]
                    value %= pow(2, 32)
                    D = self.shift_rotate_to_left(value, s_vals['round1'][k % 4])
                elif k % 4 == 2:
                    value = C + self.func_f(D, A, B) + word_blocks[k]
                    value %= pow(2, 32)
                    C = self.shift_rotate_to_left(value, s_vals['round1'][k % 4])
                else:
                    value = B + self.func_f(C, D, A) + word_blocks[k]
                    value %= pow(2, 32)
                    B = self.shift_rotate_to_left(value, s_vals['round1'][k % 4])

            const_vector = 0x5A827999
            for k in [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]:

                if 0 <= k <= 3:
                    value = A + self.func_g(B, C, D) + word_blocks[k] + const_vector
                    value %= pow(2, 32)
                    A = self.shift_rotate_to_left(value, s_vals["round2"][0])
                elif 4 <= k <= 7:
                    value = D + self.func_g(A, B, C) + word_blocks[k] + const_vector
                    value %= pow(2, 32)
                    D = self.shift_rotate_to_left(value, s_vals["round2"][1])
                elif 8 <= k <= 11:
                    value = C + self.func_g(D, A, B) + word_blocks[k] + const_vector
                    value %= pow(2, 32)
                    C = self.shift_rotate_to_left(value, s_vals["round2"][2])
                else:
                    value = B + self.func_g(C, D, A) + word_blocks[k] + const_vector
                    value %= pow(2, 32)
                    B = self.shift_rotate_to_left(value, s_vals["round2"][3])

            const_vector = 0x6ED9EBA1
            for k in [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]:
                if 0 <= k <= 3:
                    value = A + self.func_h(B, C, D) + word_blocks[k] + const_vector
                    value %= pow(2, 32)
                    A = self.shift_rotate_to_left(value, s_vals["round3"][0])
                elif 4 <= k <= 7:
                    value = C + self.func_h(D, A, B) + word_blocks[k] + const_vector
                    value %= pow(2, 32)
                    C = self.shift_rotate_to_left(value, s_vals["round3"][2])
                elif 8 <= k <= 11:
                    value = D + self.func_h(A, B, C) + word_blocks[k] + const_vector
                    value %= pow(2, 32)
                    D = self.shift_rotate_to_left(value, s_vals["round3"][1])
                else:
                    value = B + self.func_h(C, D, A) + word_blocks[k] + const_vector
                    value %= pow(2, 32)
                    B = self.shift_rotate_to_left(value, s_vals["round3"][3])

            const[0] = (const[0] + A) % pow(2, 32)
            const[1] = (const[1] + B) % pow(2, 32)
            const[2] = (const[2] + C) % pow(2, 32)
            const[3] = (const[3] + D) % pow(2, 32)

        hash_ = struct.pack("<4L", *const)
        return hash_

    @staticmethod
    def round_one(A: int, B: int, C: int, D: int):
        return None

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

hasher = MD4(msg)

hashObject = hashlib.new('md4', msg).hexdigest()
print(f"Hashlib -- {hashObject}")
print(f'My hash -- {hasher.hash().hex()}')
