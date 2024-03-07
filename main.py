import random


class AES:
    def __init__(self, key_len: int = 256):
        self.key_len = key_len

        self.aes_sbox = [
            [
                0x63,
                0x7C,
                0x77,
                0x7B,
                0xF2,
                0x6B,
                0x6F,
                0xC5,
                0x30,
                0x01,
                0x67,
                0x2B,
                0xFE,
                0xD7,
                0xAB,
                0x76,
            ],
            [
                0xCA,
                0x82,
                0xC9,
                0x7D,
                0xFA,
                0x59,
                0x47,
                0xF0,
                0xAD,
                0xD4,
                0xA2,
                0xAF,
                0x9C,
                0xA4,
                0x72,
                0xC0,
            ],
            [
                0xB7,
                0xFD,
                0x93,
                0x26,
                0x36,
                0x3F,
                0xF7,
                0xCC,
                0x34,
                0xA5,
                0xE5,
                0xF1,
                0x71,
                0xD8,
                0x31,
                0x15,
            ],
            [
                0x04,
                0xC7,
                0x23,
                0xC3,
                0x18,
                0x96,
                0x05,
                0x9A,
                0x07,
                0x12,
                0x80,
                0xE2,
                0xEB,
                0x27,
                0xB2,
                0x75,
            ],
            [
                0x09,
                0x83,
                0x2C,
                0x1A,
                0x1B,
                0x6E,
                0x5A,
                0xA0,
                0x52,
                0x3B,
                0xD6,
                0xB3,
                0x29,
                0xE3,
                0x2F,
                0x84,
            ],
            [
                0x53,
                0xD1,
                0x00,
                0xED,
                0x20,
                0xFC,
                0xB1,
                0x5B,
                0x6A,
                0xCB,
                0xBE,
                0x39,
                0x4A,
                0x4C,
                0x58,
                0xCF,
            ],
            [
                0xD0,
                0xEF,
                0xAA,
                0xFB,
                0x43,
                0x4D,
                0x33,
                0x85,
                0x45,
                0xF9,
                0x02,
                0x7F,
                0x50,
                0x3C,
                0x9F,
                0xA8,
            ],
            [
                0x51,
                0xA3,
                0x40,
                0x8F,
                0x92,
                0x9D,
                0x38,
                0xF5,
                0xBC,
                0xB6,
                0xDA,
                0x21,
                0x10,
                0xFF,
                0xF3,
                0xD2,
            ],
            [
                0xCD,
                0x0C,
                0x13,
                0xEC,
                0x5F,
                0x97,
                0x44,
                0x17,
                0xC4,
                0xA7,
                0x7E,
                0x3D,
                0x64,
                0x5D,
                0x19,
                0x73,
            ],
            [
                0x60,
                0x81,
                0x4F,
                0xDC,
                0x22,
                0x2A,
                0x90,
                0x88,
                0x46,
                0xEE,
                0xB8,
                0x14,
                0xDE,
                0x5E,
                0x0B,
                0xDB,
            ],
            [
                0xE0,
                0x32,
                0x3A,
                0x0A,
                0x49,
                0x06,
                0x24,
                0x5C,
                0xC2,
                0xD3,
                0xAC,
                0x62,
                0x91,
                0x95,
                0xE4,
                0x79,
            ],
            [
                0xE7,
                0xC8,
                0x37,
                0x6D,
                0x8D,
                0xD5,
                0x4E,
                0xA9,
                0x6C,
                0x56,
                0xF4,
                0xEA,
                0x65,
                0x7A,
                0xAE,
                0x08,
            ],
            [
                0xBA,
                0x78,
                0x25,
                0x2E,
                0x1C,
                0xA6,
                0xB4,
                0xC6,
                0xE8,
                0xDD,
                0x74,
                0x1F,
                0x4B,
                0xBD,
                0x8B,
                0x8A,
            ],
            [
                0x70,
                0x3E,
                0xB5,
                0x66,
                0x48,
                0x03,
                0xF6,
                0x0E,
                0x61,
                0x35,
                0x57,
                0xB9,
                0x86,
                0xC1,
                0x1D,
                0x9E,
            ],
            [
                0xE1,
                0xF8,
                0x98,
                0x11,
                0x69,
                0xD9,
                0x8E,
                0x94,
                0x9B,
                0x1E,
                0x87,
                0xE9,
                0xCE,
                0x55,
                0x28,
                0xDF,
            ],
            [
                0x8C,
                0xA1,
                0x89,
                0x0D,
                0xBF,
                0xE6,
                0x42,
                0x68,
                0x41,
                0x99,
                0x2D,
                0x0F,
                0xB0,
                0x54,
                0xBB,
                0x16,
            ],
        ]

        self.reverse_aes_sbox = [
            [
                0x52,
                0x09,
                0x6A,
                0xD5,
                0x30,
                0x36,
                0xA5,
                0x38,
                0xBF,
                0x40,
                0xA3,
                0x9E,
                0x81,
                0xF3,
                0xD7,
                0xFB,
            ],
            [
                0x7C,
                0xE3,
                0x39,
                0x82,
                0x9B,
                0x2F,
                0xFF,
                0x87,
                0x34,
                0x8E,
                0x43,
                0x44,
                0xC4,
                0xDE,
                0xE9,
                0xCB,
            ],
            [
                0x54,
                0x7B,
                0x94,
                0x32,
                0xA6,
                0xC2,
                0x23,
                0x3D,
                0xEE,
                0x4C,
                0x95,
                0x0B,
                0x42,
                0xFA,
                0xC3,
                0x4E,
            ],
            [
                0x08,
                0x2E,
                0xA1,
                0x66,
                0x28,
                0xD9,
                0x24,
                0xB2,
                0x76,
                0x5B,
                0xA2,
                0x49,
                0x6D,
                0x8B,
                0xD1,
                0x25,
            ],
            [
                0x72,
                0xF8,
                0xF6,
                0x64,
                0x86,
                0x68,
                0x98,
                0x16,
                0xD4,
                0xA4,
                0x5C,
                0xCC,
                0x5D,
                0x65,
                0xB6,
                0x92,
            ],
            [
                0x6C,
                0x70,
                0x48,
                0x50,
                0xFD,
                0xED,
                0xB9,
                0xDA,
                0x5E,
                0x15,
                0x46,
                0x57,
                0xA7,
                0x8D,
                0x9D,
                0x84,
            ],
            [
                0x90,
                0xD8,
                0xAB,
                0x00,
                0x8C,
                0xBC,
                0xD3,
                0x0A,
                0xF7,
                0xE4,
                0x58,
                0x05,
                0xB8,
                0xB3,
                0x45,
                0x06,
            ],
            [
                0xD0,
                0x2C,
                0x1E,
                0x8F,
                0xCA,
                0x3F,
                0x0F,
                0x02,
                0xC1,
                0xAF,
                0xBD,
                0x03,
                0x01,
                0x13,
                0x8A,
                0x6B,
            ],
            [
                0x3A,
                0x91,
                0x11,
                0x41,
                0x4F,
                0x67,
                0xDC,
                0xEA,
                0x97,
                0xF2,
                0xCF,
                0xCE,
                0xF0,
                0xB4,
                0xE6,
                0x73,
            ],
            [
                0x96,
                0xAC,
                0x74,
                0x22,
                0xE7,
                0xAD,
                0x35,
                0x85,
                0xE2,
                0xF9,
                0x37,
                0xE8,
                0x1C,
                0x75,
                0xDF,
                0x6E,
            ],
            [
                0x47,
                0xF1,
                0x1A,
                0x71,
                0x1D,
                0x29,
                0xC5,
                0x89,
                0x6F,
                0xB7,
                0x62,
                0x0E,
                0xAA,
                0x18,
                0xBE,
                0x1B,
            ],
            [
                0xFC,
                0x56,
                0x3E,
                0x4B,
                0xC6,
                0xD2,
                0x79,
                0x20,
                0x9A,
                0xDB,
                0xC0,
                0xFE,
                0x78,
                0xCD,
                0x5A,
                0xF4,
            ],
            [
                0x1F,
                0xDD,
                0xA8,
                0x33,
                0x88,
                0x07,
                0xC7,
                0x31,
                0xB1,
                0x12,
                0x10,
                0x59,
                0x27,
                0x80,
                0xEC,
                0x5F,
            ],
            [
                0x60,
                0x51,
                0x7F,
                0xA9,
                0x19,
                0xB5,
                0x4A,
                0x0D,
                0x2D,
                0xE5,
                0x7A,
                0x9F,
                0x93,
                0xC9,
                0x9C,
                0xEF,
            ],
            [
                0xA0,
                0xE0,
                0x3B,
                0x4D,
                0xAE,
                0x2A,
                0xF5,
                0xB0,
                0xC8,
                0xEB,
                0xBB,
                0x3C,
                0x83,
                0x53,
                0x99,
                0x61,
            ],
            [
                0x17,
                0x2B,
                0x04,
                0x7E,
                0xBA,
                0x77,
                0xD6,
                0x26,
                0xE1,
                0x69,
                0x14,
                0x63,
                0x55,
                0x21,
                0x0C,
                0x7D,
            ],
        ]

        self.mul_2 = [
            0x00,
            0x02,
            0x04,
            0x06,
            0x08,
            0x0A,
            0x0C,
            0x0E,
            0x10,
            0x12,
            0x14,
            0x16,
            0x18,
            0x1A,
            0x1C,
            0x1E,
            0x20,
            0x22,
            0x24,
            0x26,
            0x28,
            0x2A,
            0x2C,
            0x2E,
            0x30,
            0x32,
            0x34,
            0x36,
            0x38,
            0x3A,
            0x3C,
            0x3E,
            0x40,
            0x42,
            0x44,
            0x46,
            0x48,
            0x4A,
            0x4C,
            0x4E,
            0x50,
            0x52,
            0x54,
            0x56,
            0x58,
            0x5A,
            0x5C,
            0x5E,
            0x60,
            0x62,
            0x64,
            0x66,
            0x68,
            0x6A,
            0x6C,
            0x6E,
            0x70,
            0x72,
            0x74,
            0x76,
            0x78,
            0x7A,
            0x7C,
            0x7E,
            0x80,
            0x82,
            0x84,
            0x86,
            0x88,
            0x8A,
            0x8C,
            0x8E,
            0x90,
            0x92,
            0x94,
            0x96,
            0x98,
            0x9A,
            0x9C,
            0x9E,
            0xA0,
            0xA2,
            0xA4,
            0xA6,
            0xA8,
            0xAA,
            0xAC,
            0xAE,
            0xB0,
            0xB2,
            0xB4,
            0xB6,
            0xB8,
            0xBA,
            0xBC,
            0xBE,
            0xC0,
            0xC2,
            0xC4,
            0xC6,
            0xC8,
            0xCA,
            0xCC,
            0xCE,
            0xD0,
            0xD2,
            0xD4,
            0xD6,
            0xD8,
            0xDA,
            0xDC,
            0xDE,
            0xE0,
            0xE2,
            0xE4,
            0xE6,
            0xE8,
            0xEA,
            0xEC,
            0xEE,
            0xF0,
            0xF2,
            0xF4,
            0xF6,
            0xF8,
            0xFA,
            0xFC,
            0xFE,
            0x1B,
            0x19,
            0x1F,
            0x1D,
            0x13,
            0x11,
            0x17,
            0x15,
            0x0B,
            0x09,
            0x0F,
            0x0D,
            0x03,
            0x01,
            0x07,
            0x05,
            0x3B,
            0x39,
            0x3F,
            0x3D,
            0x33,
            0x31,
            0x37,
            0x35,
            0x2B,
            0x29,
            0x2F,
            0x2D,
            0x23,
            0x21,
            0x27,
            0x25,
            0x5B,
            0x59,
            0x5F,
            0x5D,
            0x53,
            0x51,
            0x57,
            0x55,
            0x4B,
            0x49,
            0x4F,
            0x4D,
            0x43,
            0x41,
            0x47,
            0x45,
            0x7B,
            0x79,
            0x7F,
            0x7D,
            0x73,
            0x71,
            0x77,
            0x75,
            0x6B,
            0x69,
            0x6F,
            0x6D,
            0x63,
            0x61,
            0x67,
            0x65,
            0x9B,
            0x99,
            0x9F,
            0x9D,
            0x93,
            0x91,
            0x97,
            0x95,
            0x8B,
            0x89,
            0x8F,
            0x8D,
            0x83,
            0x81,
            0x87,
            0x85,
            0xBB,
            0xB9,
            0xBF,
            0xBD,
            0xB3,
            0xB1,
            0xB7,
            0xB5,
            0xAB,
            0xA9,
            0xAF,
            0xAD,
            0xA3,
            0xA1,
            0xA7,
            0xA5,
            0xDB,
            0xD9,
            0xDF,
            0xDD,
            0xD3,
            0xD1,
            0xD7,
            0xD5,
            0xCB,
            0xC9,
            0xCF,
            0xCD,
            0xC3,
            0xC1,
            0xC7,
            0xC5,
            0xFB,
            0xF9,
            0xFF,
            0xFD,
            0xF3,
            0xF1,
            0xF7,
            0xF5,
            0xEB,
            0xE9,
            0xEF,
            0xED,
            0xE3,
            0xE1,
            0xE7,
            0xE5,
        ]

        self.mul_3 = [
            0x00,
            0x03,
            0x06,
            0x05,
            0x0C,
            0x0F,
            0x0A,
            0x09,
            0x18,
            0x1B,
            0x1E,
            0x1D,
            0x14,
            0x17,
            0x12,
            0x11,
            0x30,
            0x33,
            0x36,
            0x35,
            0x3C,
            0x3F,
            0x3A,
            0x39,
            0x28,
            0x2B,
            0x2E,
            0x2D,
            0x24,
            0x27,
            0x22,
            0x21,
            0x60,
            0x63,
            0x66,
            0x65,
            0x6C,
            0x6F,
            0x6A,
            0x69,
            0x78,
            0x7B,
            0x7E,
            0x7D,
            0x74,
            0x77,
            0x72,
            0x71,
            0x50,
            0x53,
            0x56,
            0x55,
            0x5C,
            0x5F,
            0x5A,
            0x59,
            0x48,
            0x4B,
            0x4E,
            0x4D,
            0x44,
            0x47,
            0x42,
            0x41,
            0xC0,
            0xC3,
            0xC6,
            0xC5,
            0xCC,
            0xCF,
            0xCA,
            0xC9,
            0xD8,
            0xDB,
            0xDE,
            0xDD,
            0xD4,
            0xD7,
            0xD2,
            0xD1,
            0xF0,
            0xF3,
            0xF6,
            0xF5,
            0xFC,
            0xFF,
            0xFA,
            0xF9,
            0xE8,
            0xEB,
            0xEE,
            0xED,
            0xE4,
            0xE7,
            0xE2,
            0xE1,
            0xA0,
            0xA3,
            0xA6,
            0xA5,
            0xAC,
            0xAF,
            0xAA,
            0xA9,
            0xB8,
            0xBB,
            0xBE,
            0xBD,
            0xB4,
            0xB7,
            0xB2,
            0xB1,
            0x90,
            0x93,
            0x96,
            0x95,
            0x9C,
            0x9F,
            0x9A,
            0x99,
            0x88,
            0x8B,
            0x8E,
            0x8D,
            0x84,
            0x87,
            0x82,
            0x81,
            0x9B,
            0x98,
            0x9D,
            0x9E,
            0x97,
            0x94,
            0x91,
            0x92,
            0x83,
            0x80,
            0x85,
            0x86,
            0x8F,
            0x8C,
            0x89,
            0x8A,
            0xAB,
            0xA8,
            0xAD,
            0xAE,
            0xA7,
            0xA4,
            0xA1,
            0xA2,
            0xB3,
            0xB0,
            0xB5,
            0xB6,
            0xBF,
            0xBC,
            0xB9,
            0xBA,
            0xFB,
            0xF8,
            0xFD,
            0xFE,
            0xF7,
            0xF4,
            0xF1,
            0xF2,
            0xE3,
            0xE0,
            0xE5,
            0xE6,
            0xEF,
            0xEC,
            0xE9,
            0xEA,
            0xCB,
            0xC8,
            0xCD,
            0xCE,
            0xC7,
            0xC4,
            0xC1,
            0xC2,
            0xD3,
            0xD0,
            0xD5,
            0xD6,
            0xDF,
            0xDC,
            0xD9,
            0xDA,
            0x5B,
            0x58,
            0x5D,
            0x5E,
            0x57,
            0x54,
            0x51,
            0x52,
            0x43,
            0x40,
            0x45,
            0x46,
            0x4F,
            0x4C,
            0x49,
            0x4A,
            0x6B,
            0x68,
            0x6D,
            0x6E,
            0x67,
            0x64,
            0x61,
            0x62,
            0x73,
            0x70,
            0x75,
            0x76,
            0x7F,
            0x7C,
            0x79,
            0x7A,
            0x3B,
            0x38,
            0x3D,
            0x3E,
            0x37,
            0x34,
            0x31,
            0x32,
            0x23,
            0x20,
            0x25,
            0x26,
            0x2F,
            0x2C,
            0x29,
            0x2A,
            0x0B,
            0x08,
            0x0D,
            0x0E,
            0x07,
            0x04,
            0x01,
            0x02,
            0x13,
            0x10,
            0x15,
            0x16,
            0x1F,
            0x1C,
            0x19,
            0x1A,
        ]

        # iteration correspond to differing differing key lengths 14 -> 256, 12 -> 192, 10 -> 128
        self.iterations = {16: 10, 24: 12, 32: 14}

        self.rcon = {
            16: [[x, 0, 0, 0] for x in [1, 2, 4, 8, 16, 32, 64, 128, 27, 53]],
            24: [[x, 0, 0, 0] for x in [1, 2, 4, 8, 16, 32, 64, 128, 27, 53][:8]],
            32: [[x, 0, 0, 0] for x in [1, 2, 4, 8, 16, 32, 64, 128, 27, 53][:7]],
        }

    def Lookup(self, byte: int) -> int:
        return self.aes_sbox[byte >> 4][byte & 15]

    def ReverseLookup(self, byte: int) -> int:
        return self.reverse_aes_sbox[byte >> 4][byte & 15]

    def Block(self, s: bytes) -> list[list[int]]:
        grids = []
        for i in range(0, len(s), 16):
            block = s[i : i + 16]
            grid = [[0] * 4 for _ in range(4)]
            for row in range(4):
                for col in range(4):
                    grid[row][col] = block[row + col * 4]
            grids.append(grid)
        return grids

    def ExpandKey(self, key: bytes) -> list[list[bytes]]:
        rounds = self.iterations[len(key)] + 1

        key_grid = self.Block(key)[0]

        for round in range(rounds):
            last_column = [row[-1] for row in key_grid]
            last_column_rotate_step = self.RotateRowLeft(last_column)
            last_column_sbox_step = [self.Lookup(b) for b in last_column_rotate_step]
            last_column_rcon_step = [
                last_column_sbox_step[i]
                ^ self.rcon[len(key)][round % len(self.rcon)][i]
                for i in range(len(last_column_rotate_step))
            ]

            for r in range(4):
                key_grid[r].append(last_column_rcon_step[r] ^ key_grid[r][round * 4])

            for i in range(len(key_grid)):
                for j in range(1, 4):
                    new_byte = (
                        key_grid[i][round * 4 + j] ^ key_grid[i][round * 4 + j + 3]
                    ) & 0xFF
                    key_grid[i] += bytes([new_byte])

        return key_grid

    def MixColumn(self, column: list[int]) -> list[int]:
        return [
            self.mul_2[column[0]] ^ self.mul_3[column[1]] ^ column[2] ^ column[3],
            column[0] ^ self.mul_2[column[1]] ^ self.mul_3[column[2]] ^ column[3],
            column[0] ^ column[1] ^ self.mul_2[column[2]] ^ self.mul_3[column[3]],
            self.mul_3[column[0]] ^ column[1] ^ column[2] ^ self.mul_2[column[3]],
        ]

    def MixColumns(self, grid: list[list[int]]) -> list[list[int]]:
        new_grid = [[0] * 4 for _ in range(4)]
        for i in range(4):
            col = [grid[j][i] for j in range(4)]
            new_col = self.MixColumn(col)
            for j in range(4):
                new_grid[j][i] = new_col[j]
        return new_grid

    def AddSubKey(
        self, block_grid: list[list[int]], key_grid: list[list[int]]
    ) -> list[list[int]]:
        result_grid = []
        for i in range(4):
            result_grid.append([])
            for j in range(4):
                result_grid[i].append(block_grid[i][j] ^ key_grid[i][j])
        return result_grid

    def RotateRowLeft(self, row: list[int], n: int = 1) -> list[int]:
        return row[n:] + row[:n]

    def Encrypt(self, key: bytes, data: bytes) -> bytes:
        padding = bytes(16 - len(data) % 16)
        if len(padding) != 16:
            data += padding
        grids = self.Block(data)

        expanded_key = self.ExpandKey(key)

        temp_grids = []
        round_key = self.ExtractKeyForRound(expanded_key, 0)
        for grid in grids:
            temp_grids.append(self.AddSubKey(grid, round_key))
        grids = temp_grids

        for round in range(1, 10):
            temp_grids = []
            for grid in grids:
                sub_bytes_step = [[self.Lookup(val) for val in row] for row in grid]
                shift_rows_step = [
                    self.RotateRowLeft(sub_bytes_step[i], i) for i in range(4)
                ]
                MixColumn_step = self.MixColumns(shift_rows_step)
                round_key = self.ExtractKeyForRound(expanded_key, round)
                AddSubKey_step = self.AddSubKey(MixColumn_step, round_key)
                temp_grids.append(AddSubKey_step)
            grids = temp_grids

        temp_grids = []
        round_key = self.ExtractKeyForRound(expanded_key, 10)
        for grid in grids:
            sub_bytes_step = [[self.Lookup(val) for val in row] for row in grid]
            shift_rows_step = [
                self.RotateRowLeft(sub_bytes_step[i], i) for i in range(4)
            ]
            AddSubKey_step = self.AddSubKey(shift_rows_step, round_key)
            temp_grids.append(AddSubKey_step)
        grids = temp_grids

        int_stream = []
        for grid in grids:
            for column in range(4):
                for row in range(4):
                    int_stream.append(grid[row][column])

        return bytes(int_stream)

    def Decrypt(self, key: bytes, data: bytes) -> bytes:
        grids = self.Block(data)
        expanded_key = self.ExpandKey(key)
        temp_grids = []
        round_key = self.ExtractKeyForRound(expanded_key, 10)

        temp_grids = []

        for grid in grids:

            AddSubKey_step = self.AddSubKey(grid, round_key)
            shift_rows_step = [
                self.RotateRowLeft(AddSubKey_step[i], -1 * i) for i in range(4)
            ]
            sub_bytes_step = [
                [self.ReverseLookup(val) for val in row] for row in shift_rows_step
            ]
            temp_grids.append(sub_bytes_step)

        grids = temp_grids

        for round in range(9, 0, -1):
            temp_grids = []

            for grid in grids:
                round_key = self.ExtractKeyForRound(expanded_key, round)
                AddSubKey_step = self.AddSubKey(grid, round_key)

                MixColumn_step = self.MixColumns(AddSubKey_step)
                MixColumn_step = self.MixColumns(MixColumn_step)
                MixColumn_step = self.MixColumns(MixColumn_step)
                shift_rows_step = [
                    self.RotateRowLeft(MixColumn_step[i], -1 * i) for i in range(4)
                ]
                sub_bytes_step = [
                    [self.ReverseLookup(val) for val in row] for row in shift_rows_step
                ]
                temp_grids.append(sub_bytes_step)

            grids = temp_grids
            temp_grids = []

        round_key = self.ExtractKeyForRound(expanded_key, 0)

        for grid in grids:
            temp_grids.append(self.AddSubKey(grid, round_key))

        grids = temp_grids

        int_stream = []
        for grid in grids:
            for column in range(4):
                for row in range(4):
                    int_stream.append(grid[row][column])

        return self.RemovePadding(bytes(int_stream))

    def ExtractKeyForRound(
        self, expanded_key: list[list[bytes]], round: int
    ) -> list[list[bytes]]:
        return [row[round * 4 : round * 4 + 4] for row in expanded_key]

    def RemovePadding(self, data: bytes) -> bytes:
        last_zero_index = len(data) - 1
        while last_zero_index >= 0 and data[last_zero_index] == 0:
            last_zero_index -= 1

        return data[: last_zero_index + 1]

    def GenerateRandomKey(self) -> bytes:
        return bytes([random.randint(0, 255) for _ in range(self.key_len // 8)])


import base64

# Usage example
aes = AES(key_len=256)
random_key = aes.GenerateRandomKey()
encrypted_data = aes.Encrypt(
    random_key, b"The quick brown fox jumped over the lazy dogs."
)
print(f"Encrypted data: {encrypted_data}")
print([base64.b64encode(encrypted_data).decode("ascii")])

decrypted_data = aes.Decrypt(random_key, encrypted_data)

print(f"Decrypted data: {decrypted_data.decode()}")


# https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
# https://en.wikipedia.org/wiki/AES_key_schedule
# https://crypto.stackexchange.com/questions/2402/how-to-solve-MixColumns
# https://en.wikipedia.org/wiki/Rijndael_S-box
# https://en.wikipedia.org/wiki/Diehard_tests
# https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
# https://en.wikipedia.org/wiki/Nothing-up-my-sleeve_number
# https://en.wikipedia.org/wiki/Grover%27s_algorithm
# https://en.wikipedia.org/wiki/Shor%27s_algorithm
# https://en.wikipedia.org/wiki/Post-quantum_cryptography
# https://www.youtube.com/watch?v=O4xNJsjtN6E
# https://en.wikipedia.org/wiki/Key_stretching
