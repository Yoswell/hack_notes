comments = """
   Reverse Engineering Solution for Mickey Mouse Binary
   Analysis of machine_decoding_sequence() function
   
   Binary Analysis:
       * Algorithm: XOR + bit rotations
"""

tags = """
   #xor #shift #bit #rotation #decryption #encoding
"""

encode_hex = """
   ; _QWORD enc[23]
   enc dq 0FFFEh, 0FF8Eh, 0FFD6h, 0FF32h, 0FF12h, 0FF72h, 0FE1Ah
       dq 0FF1Eh, 0FF9Eh, 0FE1Ah, 0FF66h, 0FFC2h, 0FE6Ah, 0FFD2h
       dq 0FE0Eh, 2 dup(0FF6Eh), 0FE4Eh, 2 dup(0FE5Ah), 0FE1Ah
       dq 0FE5Ah, 0FF2Ah
"""

disassembled_code = """
   2 dup(0FF6Eh) meaning => 0FF6Eh, 0FF6Eh
   2 dup(0FE5Ah) meaning => 0FE5Ah, 0FE5Ah
   
   enc[i] = __ROR8__(x) meaning => enc[i] = (enc[i] >> 1) | ((enc[i] & 1) << 15)
   enc[i] = __ROL8__(x) meaning => enc[i] = (enc[i] << 1) | ((enc[i] >> 15) & 1)
"""

class Py_testing:
    def main():
        print('/*== Project to test ==*/')

        enc = [
            0xFFFE, 0xFF8E, 0xFFD6, 0xFF32, 0xFF12, 0xFF72, 0xFE1A,
            0xFF1E, 0xFF9E, 0xFE1A, 0xFF66, 0xFFC2, 0xFE6A, 0xFFD2,
            0xFE0E, 0xFF6E, 0xFF6E, 0xFE4E, 0xFE5A, 0xFE5A, 0xFE1A,
            0xFE5A, 0xFF2A
        ]

        # Decryption function applied to each element of the array
        def decrypt(enc):
            enc = enc ^ 0x524E
            enc = (enc >> 1) | ((enc & 1) << 15)
            enc = enc ^ 0x5648
            enc = enc = ((enc << 7) | (enc >> 9)) & 0xFFFF
            enc = enc >> 8
            
            return enc

        dc = []
        for x in enc:
            dc.append(decrypt(x))

        print(''.join(chr(x) for x in dc))

if __name__ == '__main__':
    Py_testing.main()
