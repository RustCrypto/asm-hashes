;
; SHA512 hash in x64 MASM
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
;       8  rax       yes       Temporary w-bit word used in the hash computation
;       8  rbx       no        Temporary w-bit word used in the hash computation
;       8  rcx       yes       Base address of message block array argument (read-only)
;       8  rdx       yes       Base address of hash value array argument (read-only)
;       8  rdi       no        Temporary w-bit word used in the hash computation
;       8  rsi       no        Temporary w-bit word used in the hash computation
;       8  rsp       no        x64 stack pointer
;       8  r8        yes       SHA512 working variable A
;       8  r9        yes       SHA512 working variable B
;       8  r10       yes       SHA512 working variable C
;       8  r11       yes       SHA512 working variable D
;       8  r12       no        SHA512 working variable E
;       8  r13       no        SHA512 working variable F
;       8  r14       no        SHA512 working variable G
;       8  r15       no        SHA512 working variable H
;     128  [rsp+0]   no        Circular buffer of most recent 16 message schedule items, 8 bytes each

                option  casemap:none

                .const
SCHED           macro       i
                index       textequ %i AND 0fh              ; i mod 16
                exitm       <[rsp + index*8]>
                endm

ROUNDTAIL       macro       a, b, c, d, e, f, g, h, k       ; rbx = w[i]
                ; temp1 = h + S1 + ch + k[i] + w[i]
                ; temp2 = S0 + maj
                ; (obj1) h -> temp1 + temp2 = h + S1 + ch + k[i] + w[i] + S0 + maj
                ; (obj2) d -> d + temp1
                ; Part 0
                mov         rax, e
                mov         rdi, e
                mov         rsi, e
                ror         rax, 14
                ror         rdi, 18
                ror         rsi, 41
                xor         rdi, rsi
                xor         rax, rdi                        ; rax = S1
                ; ch = (e & f) ^ (~e & g) = (g ^ (e & (f ^ g)))
                ; & and ^ form the Z/2Z ring (& is *, ^ is +)
                ; ~e is (1 + e)
                ; ef + (1 + e)g = ef + g + eg = g + ef + eg = g + e(f + g)
                mov         rdi, g
                xor         rdi, f
                and         rdi, e
                xor         rdi, g                          ; rdi = ch
                add         h, rax                          ; h -> h + S1
                add         h, rdi                          ; h -> h + S1 + ch
                mov         rax, k
                add         h, rax                          ; h -> h + S1 + ch + k[i]
                add         h, rbx                          ; h -> h + S1 + ch + k[i] + w[i] = temp1
                ; Part 1
                add         d, h                            ; d -> d + temp1 (obj2)
                ; Part 2
                mov         rax, a
                mov         rdi, a
                mov         rsi, a
                ror         rax, 28
                ror         rdi, 34
                ror         rsi, 39
                xor         rdi, rsi
                xor         rax, rdi                        ; rax = S0
                add         h, rax                          ; h -> temp1 + S0
                ; maj = (a and b) xor (a and c) xor (b and c) = (a and (b or c)) or (b and c)
                ; https://www.wolframalpha.com/input?i=simplify+%28A+%26%26+B%29+xor+%28A+%26%26+C%29+xor+%28B+%26%26+C%29
                mov         rdi, c
                mov         rax, c
                or          rax, b
                and         rdi, b
                and         rax, a
                or          rax, rdi                        ; rax = maj
                add         h, rax                          ; h -> temp1 + S0 + maj = temp1 + temp2 (obj1)
                endm

ROUND           macro       i, a, b, c, d, e, f, g, h, k

if i LT 16

                mov         rbx, [rcx + i*8]
                bswap       rbx
                mov         SCHED(i), rbx

else

                ; (obj) w[i] -> w[i-16] + s0 + w[i-7] + s1
                mov         rbx, SCHED(i - 16)              ; rbx = w[i-16]
                mov         rax, SCHED(i - 15)
                mov         rdi, rax
                mov         rsi, rax
                ror         rdi, 8
                shr         rsi, 7
                ror         rax, 1
                xor         rdi, rsi
                xor         rax, rdi                        ; s0 = rax
                add         rbx, rax                        ; rbx = w[i-16] + s0
                add         rbx, SCHED(i -  7)              ; rbx = w[i-16] + s0 + w[i-7]
                mov         rax, SCHED(i -  2)
                mov         rdi, rax
                mov         rsi, rax
                ror         rdi, 61
                shr         rsi, 6
                ror         rax, 19
                xor         rdi, rsi
                xor         rax, rdi                        ; rax = s1
                add         rbx, rax                        ; rbx = w[i-16] + s0 + w[i-7] + s1
                mov         SCHED(i), rbx                   ; w[i] -> w[i-16] + s0 + w[i-7] + s1 (obj)

endif

                ROUNDTAIL   a, b, c, d, e, f, g, h, k       ; rbx = w[i]
                endm

                .code
                ; void sha512_compress(const uint8_t block[128], uint64_t state[8])
                public      sha512_compress
sha512_compress proc
                ; Save nonvolatile registers, allocate scratch space
                push        rbx
                push        rdi
                push        rsi
                push        r12
                push        r13
                push        r14
                push        r15
                sub         rsp, 128

                ; Initialize working variables with previous hash value
                mov          r8, [rdx]                      ; a
                mov          r9, [rdx +  8]                 ; b
                mov         r10, [rdx + 16]                 ; c
                mov         r11, [rdx + 24]                 ; d
                mov         r12, [rdx + 32]                 ; e
                mov         r13, [rdx + 40]                 ; f
                mov         r14, [rdx + 48]                 ; g
                mov         r15, [rdx + 56]                 ; h

                ; 80 rounds of hashing
                ROUND        0, r8, r9, r10, r11, r12, r13, r14, r15, 0428A2F98D728AE22h
                ROUND        1, r15, r8, r9, r10, r11, r12, r13, r14, 07137449123EF65CDh
                ROUND        2, r14, r15, r8, r9, r10, r11, r12, r13, 0B5C0FBCFEC4D3B2Fh
                ROUND        3, r13, r14, r15, r8, r9, r10, r11, r12, 0E9B5DBA58189DBBCh
                ROUND        4, r12, r13, r14, r15, r8, r9, r10, r11, 03956C25BF348B538h
                ROUND        5, r11, r12, r13, r14, r15, r8, r9, r10, 059F111F1B605D019h
                ROUND        6, r10, r11, r12, r13, r14, r15, r8, r9, 0923F82A4AF194F9Bh
                ROUND        7, r9, r10, r11, r12, r13, r14, r15, r8, 0AB1C5ED5DA6D8118h
                ROUND        8, r8, r9, r10, r11, r12, r13, r14, r15, 0D807AA98A3030242h
                ROUND        9, r15, r8, r9, r10, r11, r12, r13, r14, 012835B0145706FBEh
                ROUND       10, r14, r15, r8, r9, r10, r11, r12, r13, 0243185BE4EE4B28Ch
                ROUND       11, r13, r14, r15, r8, r9, r10, r11, r12, 0550C7DC3D5FFB4E2h
                ROUND       12, r12, r13, r14, r15, r8, r9, r10, r11, 072BE5D74F27B896Fh
                ROUND       13, r11, r12, r13, r14, r15, r8, r9, r10, 080DEB1FE3B1696B1h
                ROUND       14, r10, r11, r12, r13, r14, r15, r8, r9, 09BDC06A725C71235h
                ROUND       15, r9, r10, r11, r12, r13, r14, r15, r8, 0C19BF174CF692694h
                ROUND       16, r8, r9, r10, r11, r12, r13, r14, r15, 0E49B69C19EF14AD2h
                ROUND       17, r15, r8, r9, r10, r11, r12, r13, r14, 0EFBE4786384F25E3h
                ROUND       18, r14, r15, r8, r9, r10, r11, r12, r13, 00FC19DC68B8CD5B5h
                ROUND       19, r13, r14, r15, r8, r9, r10, r11, r12, 0240CA1CC77AC9C65h
                ROUND       20, r12, r13, r14, r15, r8, r9, r10, r11, 02DE92C6F592B0275h
                ROUND       21, r11, r12, r13, r14, r15, r8, r9, r10, 04A7484AA6EA6E483h
                ROUND       22, r10, r11, r12, r13, r14, r15, r8, r9, 05CB0A9DCBD41FBD4h
                ROUND       23, r9, r10, r11, r12, r13, r14, r15, r8, 076F988DA831153B5h
                ROUND       24, r8, r9, r10, r11, r12, r13, r14, r15, 0983E5152EE66DFABh
                ROUND       25, r15, r8, r9, r10, r11, r12, r13, r14, 0A831C66D2DB43210h
                ROUND       26, r14, r15, r8, r9, r10, r11, r12, r13, 0B00327C898FB213Fh
                ROUND       27, r13, r14, r15, r8, r9, r10, r11, r12, 0BF597FC7BEEF0EE4h
                ROUND       28, r12, r13, r14, r15, r8, r9, r10, r11, 0C6E00BF33DA88FC2h
                ROUND       29, r11, r12, r13, r14, r15, r8, r9, r10, 0D5A79147930AA725h
                ROUND       30, r10, r11, r12, r13, r14, r15, r8, r9, 006CA6351E003826Fh
                ROUND       31, r9, r10, r11, r12, r13, r14, r15, r8, 0142929670A0E6E70h
                ROUND       32, r8, r9, r10, r11, r12, r13, r14, r15, 027B70A8546D22FFCh
                ROUND       33, r15, r8, r9, r10, r11, r12, r13, r14, 02E1B21385C26C926h
                ROUND       34, r14, r15, r8, r9, r10, r11, r12, r13, 04D2C6DFC5AC42AEDh
                ROUND       35, r13, r14, r15, r8, r9, r10, r11, r12, 053380D139D95B3DFh
                ROUND       36, r12, r13, r14, r15, r8, r9, r10, r11, 0650A73548BAF63DEh
                ROUND       37, r11, r12, r13, r14, r15, r8, r9, r10, 0766A0ABB3C77B2A8h
                ROUND       38, r10, r11, r12, r13, r14, r15, r8, r9, 081C2C92E47EDAEE6h
                ROUND       39, r9, r10, r11, r12, r13, r14, r15, r8, 092722C851482353Bh
                ROUND       40, r8, r9, r10, r11, r12, r13, r14, r15, 0A2BFE8A14CF10364h
                ROUND       41, r15, r8, r9, r10, r11, r12, r13, r14, 0A81A664BBC423001h
                ROUND       42, r14, r15, r8, r9, r10, r11, r12, r13, 0C24B8B70D0F89791h
                ROUND       43, r13, r14, r15, r8, r9, r10, r11, r12, 0C76C51A30654BE30h
                ROUND       44, r12, r13, r14, r15, r8, r9, r10, r11, 0D192E819D6EF5218h
                ROUND       45, r11, r12, r13, r14, r15, r8, r9, r10, 0D69906245565A910h
                ROUND       46, r10, r11, r12, r13, r14, r15, r8, r9, 0F40E35855771202Ah
                ROUND       47, r9, r10, r11, r12, r13, r14, r15, r8, 0106AA07032BBD1B8h
                ROUND       48, r8, r9, r10, r11, r12, r13, r14, r15, 019A4C116B8D2D0C8h
                ROUND       49, r15, r8, r9, r10, r11, r12, r13, r14, 01E376C085141AB53h
                ROUND       50, r14, r15, r8, r9, r10, r11, r12, r13, 02748774CDF8EEB99h
                ROUND       51, r13, r14, r15, r8, r9, r10, r11, r12, 034B0BCB5E19B48A8h
                ROUND       52, r12, r13, r14, r15, r8, r9, r10, r11, 0391C0CB3C5C95A63h
                ROUND       53, r11, r12, r13, r14, r15, r8, r9, r10, 04ED8AA4AE3418ACBh
                ROUND       54, r10, r11, r12, r13, r14, r15, r8, r9, 05B9CCA4F7763E373h
                ROUND       55, r9, r10, r11, r12, r13, r14, r15, r8, 0682E6FF3D6B2B8A3h
                ROUND       56, r8, r9, r10, r11, r12, r13, r14, r15, 0748F82EE5DEFB2FCh
                ROUND       57, r15, r8, r9, r10, r11, r12, r13, r14, 078A5636F43172F60h
                ROUND       58, r14, r15, r8, r9, r10, r11, r12, r13, 084C87814A1F0AB72h
                ROUND       59, r13, r14, r15, r8, r9, r10, r11, r12, 08CC702081A6439ECh
                ROUND       60, r12, r13, r14, r15, r8, r9, r10, r11, 090BEFFFA23631E28h
                ROUND       61, r11, r12, r13, r14, r15, r8, r9, r10, 0A4506CEBDE82BDE9h
                ROUND       62, r10, r11, r12, r13, r14, r15, r8, r9, 0BEF9A3F7B2C67915h
                ROUND       63, r9, r10, r11, r12, r13, r14, r15, r8, 0C67178F2E372532Bh
                ROUND       64, r8, r9, r10, r11, r12, r13, r14, r15, 0CA273ECEEA26619Ch
                ROUND       65, r15, r8, r9, r10, r11, r12, r13, r14, 0D186B8C721C0C207h
                ROUND       66, r14, r15, r8, r9, r10, r11, r12, r13, 0EADA7DD6CDE0EB1Eh
                ROUND       67, r13, r14, r15, r8, r9, r10, r11, r12, 0F57D4F7FEE6ED178h
                ROUND       68, r12, r13, r14, r15, r8, r9, r10, r11, 006F067AA72176FBAh
                ROUND       69, r11, r12, r13, r14, r15, r8, r9, r10, 00A637DC5A2C898A6h
                ROUND       70, r10, r11, r12, r13, r14, r15, r8, r9, 0113F9804BEF90DAEh
                ROUND       71, r9, r10, r11, r12, r13, r14, r15, r8, 01B710B35131C471Bh
                ROUND       72, r8, r9, r10, r11, r12, r13, r14, r15, 028DB77F523047D84h
                ROUND       73, r15, r8, r9, r10, r11, r12, r13, r14, 032CAAB7B40C72493h
                ROUND       74, r14, r15, r8, r9, r10, r11, r12, r13, 03C9EBE0A15C9BEBCh
                ROUND       75, r13, r14, r15, r8, r9, r10, r11, r12, 0431D67C49C100D4Ch
                ROUND       76, r12, r13, r14, r15, r8, r9, r10, r11, 04CC5D4BECB3E42B6h
                ROUND       77, r11, r12, r13, r14, r15, r8, r9, r10, 0597F299CFC657E2Ah
                ROUND       78, r10, r11, r12, r13, r14, r15, r8, r9, 05FCB6FAB3AD6FAECh
                ROUND       79, r9, r10, r11, r12, r13, r14, r15, r8, 06C44198C4A475817h

                ; Compute intermediate hash value
                add         [rdx]     ,  r8
                add         [rdx +  8],  r9
                add         [rdx + 16], r10
                add         [rdx + 24], r11
                add         [rdx + 32], r12
                add         [rdx + 40], r13
                add         [rdx + 48], r14
                add         [rdx + 56], r15

                ; Restore nonvolatile registers
                add         rsp, 128
                pop         r15
                pop         r14
                pop         r13
                pop         r12
                pop         rsi
                pop         rdi
                pop         rbx
                ret
sha512_compress endp
                end
