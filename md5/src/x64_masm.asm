;
; MD5 hash in x64 MASM
;
; Copyright (c) 2023 Chong Yeol Nah (MIT License)
;
; Permission is hereby granted, free of charge, to any person obtaining a copy of
; this software and associated documentation files (the "Software"), to deal in
; the Software without restriction, including without limitation the rights to
; use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
; the Software, and to permit persons to whom the Software is furnished to do so,
; subject to the following conditions:
; - The above copyright notice and this permission notice shall be included in
;   all copies or substantial portions of the Software.
; - The Software is provided "as is", without warranty of any kind, express or
;   implied, including but not limited to the warranties of merchantability,
;   fitness for a particular purpose and noninfringement. In no event shall the
;   authors or copyright holders be liable for any claim, damages or other
;   liability, whether in an action of contract, tort or otherwise, arising from,
;   out of or in connection with the Software or the use or other dealings in the
;   Software.
;
;
; Storage usage:
;   Bytes  Location  Volatile  Description
;       4  eax       yes       Temporary w-bit word used in the hash computation
;       8  rcx       yes       Base address of message block array argument (read-only)
;       8  rdx       yes       Base address of hash value array argument (read-only)
;       4  r8d       yes       MD5 working variable A
;       4  r9d       yes       MD5 working variable B
;       4  r10d      yes       MD5 working variable C
;       4  r11d      yes       MD5 working variable D

                option  casemap:none

                .const
ROUND           macro       i, a, b, c, d, k, s, t

if i LT 16

                ; eax = F(b,c,d) = (b & c) | (!b & d) = d ^ (b & (c ^ d))
                mov         eax, c
                xor         eax, d
                and         eax, b
                xor         eax, d

elseif i LT 32

                ; eax = G(b,c,d) = (b & d) | (c & !d) = c ^ (d & (b ^ c))
                mov         eax, c
                xor         eax, b
                and         eax, d
                xor         eax, c

elseif i LT 48

                ; eax = H(b,c,d) = b ^ c ^ d
                mov         eax, c
                xor         eax, d
                xor         eax, b

else

                ; eax = I(b,c,d) = c ^ (b | !d)
                mov         eax, d
                not         eax
                or          eax, b
                xor         eax, c

endif

                lea         a, [eax + a + t]
                add         a, [rcx + k*4]
                rol         a, s
                add         a, b
                endm

                .code
                ; void md5_compress(const uint8_t block[64], uint32_t state[4])
                public      md5_compress
md5_compress    proc
                ; Initialize working variables with previous hash value
                mov          r8d, [rdx]                     ; a
                mov          r9d, [rdx +  4]                ; b
                mov         r10d, [rdx +  8]                ; c
                mov         r11d, [rdx + 12]                ; d

                ; 64 rounds of hashing
                ROUND        0, r8d, r9d, r10d, r11d,  0,  7, -28955B88h
                ROUND        1, r11d, r8d, r9d, r10d,  1, 12, -173848AAh
                ROUND        2, r10d, r11d, r8d, r9d,  2, 17,  242070DBh
                ROUND        3, r9d, r10d, r11d, r8d,  3, 22, -3E423112h
                ROUND        4, r8d, r9d, r10d, r11d,  4,  7, -0A83F051h
                ROUND        5, r11d, r8d, r9d, r10d,  5, 12,  4787C62Ah
                ROUND        6, r10d, r11d, r8d, r9d,  6, 17, -57CFB9EDh
                ROUND        7, r9d, r10d, r11d, r8d,  7, 22, -02B96AFFh
                ROUND        8, r8d, r9d, r10d, r11d,  8,  7,  698098D8h
                ROUND        9, r11d, r8d, r9d, r10d,  9, 12, -74BB0851h
                ROUND       10, r10d, r11d, r8d, r9d, 10, 17, -0000A44Fh
                ROUND       11, r9d, r10d, r11d, r8d, 11, 22, -76A32842h
                ROUND       12, r8d, r9d, r10d, r11d, 12,  7,  6B901122h
                ROUND       13, r11d, r8d, r9d, r10d, 13, 12, -02678E6Dh
                ROUND       14, r10d, r11d, r8d, r9d, 14, 17, -5986BC72h
                ROUND       15, r9d, r10d, r11d, r8d, 15, 22,  49B40821h
                ROUND       16, r8d, r9d, r10d, r11d,  1,  5, -09E1DA9Eh
                ROUND       17, r11d, r8d, r9d, r10d,  6,  9, -3FBF4CC0h
                ROUND       18, r10d, r11d, r8d, r9d, 11, 14,  265E5A51h
                ROUND       19, r9d, r10d, r11d, r8d,  0, 20, -16493856h
                ROUND       20, r8d, r9d, r10d, r11d,  5,  5, -29D0EFA3h
                ROUND       21, r11d, r8d, r9d, r10d, 10,  9,  02441453h
                ROUND       22, r10d, r11d, r8d, r9d, 15, 14, -275E197Fh
                ROUND       23, r9d, r10d, r11d, r8d,  4, 20, -182C0438h
                ROUND       24, r8d, r9d, r10d, r11d,  9,  5,  21E1CDE6h
                ROUND       25, r11d, r8d, r9d, r10d, 14,  9, -3CC8F82Ah
                ROUND       26, r10d, r11d, r8d, r9d,  3, 14, -0B2AF279h
                ROUND       27, r9d, r10d, r11d, r8d,  8, 20,  455A14EDh
                ROUND       28, r8d, r9d, r10d, r11d, 13,  5, -561C16FBh
                ROUND       29, r11d, r8d, r9d, r10d,  2,  9, -03105C08h
                ROUND       30, r10d, r11d, r8d, r9d,  7, 14,  676F02D9h
                ROUND       31, r9d, r10d, r11d, r8d, 12, 20, -72D5B376h
                ROUND       32, r8d, r9d, r10d, r11d,  5,  4, -0005C6BEh
                ROUND       33, r11d, r8d, r9d, r10d,  8, 11, -788E097Fh
                ROUND       34, r10d, r11d, r8d, r9d, 11, 16,  6D9D6122h
                ROUND       35, r9d, r10d, r11d, r8d, 14, 23, -021AC7F4h
                ROUND       36, r8d, r9d, r10d, r11d,  1,  4, -5B4115BCh
                ROUND       37, r11d, r8d, r9d, r10d,  4, 11,  4BDECFA9h
                ROUND       38, r10d, r11d, r8d, r9d,  7, 16, -0944B4A0h
                ROUND       39, r9d, r10d, r11d, r8d, 10, 23, -41404390h
                ROUND       40, r8d, r9d, r10d, r11d, 13,  4,  289B7EC6h
                ROUND       41, r11d, r8d, r9d, r10d,  0, 11, -155ED806h
                ROUND       42, r10d, r11d, r8d, r9d,  3, 16, -2B10CF7Bh
                ROUND       43, r9d, r10d, r11d, r8d,  6, 23,  04881D05h
                ROUND       44, r8d, r9d, r10d, r11d,  9,  4, -262B2FC7h
                ROUND       45, r11d, r8d, r9d, r10d, 12, 11, -1924661Bh
                ROUND       46, r10d, r11d, r8d, r9d, 15, 16,  1FA27CF8h
                ROUND       47, r9d, r10d, r11d, r8d,  2, 23, -3B53A99Bh
                ROUND       48, r8d, r9d, r10d, r11d,  0,  6, -0BD6DDBCh
                ROUND       49, r11d, r8d, r9d, r10d,  7, 10,  432AFF97h
                ROUND       50, r10d, r11d, r8d, r9d, 14, 15, -546BDC59h
                ROUND       51, r9d, r10d, r11d, r8d,  5, 21, -036C5FC7h
                ROUND       52, r8d, r9d, r10d, r11d, 12,  6,  655B59C3h
                ROUND       53, r11d, r8d, r9d, r10d,  3, 10, -70F3336Eh
                ROUND       54, r10d, r11d, r8d, r9d, 10, 15, -00100B83h
                ROUND       55, r9d, r10d, r11d, r8d,  1, 21, -7A7BA22Fh
                ROUND       56, r8d, r9d, r10d, r11d,  8,  6,  6FA87E4Fh
                ROUND       57, r11d, r8d, r9d, r10d, 15, 10, -01D31920h
                ROUND       58, r10d, r11d, r8d, r9d,  6, 15, -5CFEBCECh
                ROUND       59, r9d, r10d, r11d, r8d, 13, 21,  4E0811A1h
                ROUND       60, r8d, r9d, r10d, r11d,  4,  6, -08AC817Eh
                ROUND       61, r11d, r8d, r9d, r10d, 11, 10, -42C50DCBh
                ROUND       62, r10d, r11d, r8d, r9d,  2, 15,  2AD7D2BBh
                ROUND       63, r9d, r10d, r11d, r8d,  9, 21, -14792C6Fh

                ; Compute intermediate hash value
                add         [rdx]     ,  r8d
                add         [rdx +  4],  r9d
                add         [rdx +  8], r10d
                add         [rdx + 12], r11d
                ret
md5_compress    endp
                end
