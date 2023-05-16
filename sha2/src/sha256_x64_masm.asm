;
; SHA256 hash in x64 MASM
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
;       4  ebx       no        Temporary w-bit word used in the hash computation
;       8  rcx       yes       Base address of message block array argument (read-only)
;       8  rdx       yes       Base address of hash value array argument (read-only)
;       4  edi       no        Temporary w-bit word used in the hash computation
;       4  esi       no        Temporary w-bit word used in the hash computation
;       8  rsp       no        x64 stack pointer
;       4  r8d       yes       SHA256 working variable A
;       4  r9d       yes       SHA256 working variable B
;       4  r10d      yes       SHA256 working variable C
;       4  r11d      yes       SHA256 working variable D
;       4  r12d      no        SHA256 working variable E
;       4  r13d      no        SHA256 working variable F
;       4  r14d      no        SHA256 working variable G
;       4  r15d      no        SHA256 working variable H
;      64  [rsp+0]   no        Circular buffer of most recent 16 message schedule items, 4 bytes each

                option  casemap:none

                .const
SCHED           macro       i
                index       textequ %i AND 0fh              ; i mod 16
                exitm       <[rsp + index*4]>
                endm

ROUNDTAIL       macro       a, b, c, d, e, f, g, h, k       ; ebx = w[i]
                ; temp1 = h + S1 + ch + k[i] + w[i]
                ; temp2 = S0 + maj
                ; (obj1) h -> temp1 + temp2 = h + S1 + ch + k[i] + w[i] + S0 + maj
                ; (obj2) d -> d + temp1
                ; Part 0
                mov         eax, e
                mov         edi, e
                mov         esi, e
                ror         eax, 6
                ror         edi, 11
                ror         esi, 25
                xor         edi, esi
                xor         eax, edi                        ; eax = S1
                ; ch = (e & f) ^ (~e & g) = (g ^ (e & (f ^ g)))
                ; & and ^ form the Z/2Z ring (& is *, ^ is +)
                ; ~e is (1 + e)
                ; ef + (1 + e)g = ef + g + eg = g + ef + eg = g + e(f + g)
                mov         edi, g
                xor         edi, f
                and         edi, e
                xor         edi, g                          ; edi = ch
                lea         eax, [eax + edi + k]            ; eax = S1 + ch + k[i]
                add         h, eax                          ; h -> h + S1 + ch + k[i]
                add         h, ebx                          ; h -> h + S1 + ch + k[i] + w[i] = temp1
                ; Part 1
                add         d, h                            ; d -> d + temp1 (obj2)
                ; Part 2
                mov         eax, a
                mov         edi, a
                mov         esi, a
                ror         eax, 2
                ror         edi, 13
                ror         esi, 22
                xor         edi, esi
                xor         eax, edi                        ; eax = S0
                add         h, eax                          ; h -> temp1 + S0
                ; maj = (a and b) xor (a and c) xor (b and c) = (a and (b or c)) or (b and c)
                ; https://www.wolframalpha.com/input?i=simplify+%28A+%26%26+B%29+xor+%28A+%26%26+C%29+xor+%28B+%26%26+C%29
                mov         edi, c
                mov         eax, c
                or          eax, b
                and         edi, b
                and         eax, a
                or          eax, edi                        ; eax = maj
                add         h, eax                          ; h -> temp1 + S0 + maj = temp1 + temp2 (obj1)
                endm

ROUND           macro       i, a, b, c, d, e, f, g, h, k

if i LT 16

                mov         ebx, [rcx + i*4]
                bswap       ebx
                mov         SCHED(i), ebx

else

                ; (obj) w[i] -> w[i-16] + s0 + w[i-7] + s1
                mov         ebx, SCHED(i - 16)              ; ebx = w[i-16]
                mov         eax, SCHED(i - 15)
                mov         edi, eax
                mov         esi, eax
                ror         edi, 18
                shr         esi, 3
                ror         eax, 7
                xor         edi, esi
                xor         eax, edi                        ; s0 = eax
                add         ebx, eax                        ; ebx = w[i-16] + s0
                add         ebx, SCHED(i -  7)              ; ebx = w[i-16] + s0 + w[i-7]
                mov         eax, SCHED(i -  2)
                mov         edi, eax
                mov         esi, eax
                ror         edi, 19
                shr         esi, 10
                ror         eax, 17
                xor         edi, esi
                xor         eax, edi                        ; eax = s1
                add         ebx, eax                        ; ebx = w[i-16] + s0 + w[i-7] + s1
                mov         SCHED(i), ebx                   ; w[i] -> w[i-16] + s0 + w[i-7] + s1 (obj)

endif

                ROUNDTAIL   a, b, c, d, e, f, g, h, k       ; ebx = w[i]
                endm

                .code
                ; void sha256_compress(const uint8_t block[64], uint32_t state[8])
                public      sha256_compress
sha256_compress proc
                ; Save nonvolatile registers, allocate scratch space
                push        rbx
                push        rdi
                push        rsi
                push        r12
                push        r13
                push        r14
                push        r15
                sub         rsp, 64

                ; Initialize working variables with previous hash value
                mov          r8d, [rdx]                     ; a
                mov          r9d, [rdx +  4]                ; b
                mov         r10d, [rdx +  8]                ; c
                mov         r11d, [rdx + 12]                ; d
                mov         r12d, [rdx + 16]                ; e
                mov         r13d, [rdx + 20]                ; f
                mov         r14d, [rdx + 24]                ; g
                mov         r15d, [rdx + 28]                ; h

                ; 64 rounds of hashing
                ROUND        0, r8d , r9d , r10d, r11d, r12d, r13d, r14d, r15d,  428A2F98h
                ROUND        1, r15d, r8d , r9d , r10d, r11d, r12d, r13d, r14d,  71374491h
                ROUND        2, r14d, r15d, r8d , r9d , r10d, r11d, r12d, r13d, -4A3F0431h
                ROUND        3, r13d, r14d, r15d, r8d , r9d , r10d, r11d, r12d, -164A245Bh
                ROUND        4, r12d, r13d, r14d, r15d, r8d , r9d , r10d, r11d,  3956C25Bh
                ROUND        5, r11d, r12d, r13d, r14d, r15d, r8d , r9d , r10d,  59F111F1h
                ROUND        6, r10d, r11d, r12d, r13d, r14d, r15d, r8d , r9d , -6DC07D5Ch
                ROUND        7, r9d , r10d, r11d, r12d, r13d, r14d, r15d, r8d , -54E3A12Bh
                ROUND        8, r8d , r9d , r10d, r11d, r12d, r13d, r14d, r15d, -27F85568h
                ROUND        9, r15d, r8d , r9d , r10d, r11d, r12d, r13d, r14d,  12835B01h
                ROUND       10, r14d, r15d, r8d , r9d , r10d, r11d, r12d, r13d,  243185BEh
                ROUND       11, r13d, r14d, r15d, r8d , r9d , r10d, r11d, r12d,  550C7DC3h
                ROUND       12, r12d, r13d, r14d, r15d, r8d , r9d , r10d, r11d,  72BE5D74h
                ROUND       13, r11d, r12d, r13d, r14d, r15d, r8d , r9d , r10d, -7F214E02h
                ROUND       14, r10d, r11d, r12d, r13d, r14d, r15d, r8d , r9d , -6423F959h
                ROUND       15, r9d , r10d, r11d, r12d, r13d, r14d, r15d, r8d , -3E640E8Ch
                ROUND       16, r8d , r9d , r10d, r11d, r12d, r13d, r14d, r15d, -1B64963Fh
                ROUND       17, r15d, r8d , r9d , r10d, r11d, r12d, r13d, r14d, -1041B87Ah
                ROUND       18, r14d, r15d, r8d , r9d , r10d, r11d, r12d, r13d,  0FC19DC6h
                ROUND       19, r13d, r14d, r15d, r8d , r9d , r10d, r11d, r12d,  240CA1CCh
                ROUND       20, r12d, r13d, r14d, r15d, r8d , r9d , r10d, r11d,  2DE92C6Fh
                ROUND       21, r11d, r12d, r13d, r14d, r15d, r8d , r9d , r10d,  4A7484AAh
                ROUND       22, r10d, r11d, r12d, r13d, r14d, r15d, r8d , r9d ,  5CB0A9DCh
                ROUND       23, r9d , r10d, r11d, r12d, r13d, r14d, r15d, r8d ,  76F988DAh
                ROUND       24, r8d , r9d , r10d, r11d, r12d, r13d, r14d, r15d, -67C1AEAEh
                ROUND       25, r15d, r8d , r9d , r10d, r11d, r12d, r13d, r14d, -57CE3993h
                ROUND       26, r14d, r15d, r8d , r9d , r10d, r11d, r12d, r13d, -4FFCD838h
                ROUND       27, r13d, r14d, r15d, r8d , r9d , r10d, r11d, r12d, -40A68039h
                ROUND       28, r12d, r13d, r14d, r15d, r8d , r9d , r10d, r11d, -391FF40Dh
                ROUND       29, r11d, r12d, r13d, r14d, r15d, r8d , r9d , r10d, -2A586EB9h
                ROUND       30, r10d, r11d, r12d, r13d, r14d, r15d, r8d , r9d ,  06CA6351h
                ROUND       31, r9d , r10d, r11d, r12d, r13d, r14d, r15d, r8d ,  14292967h
                ROUND       32, r8d , r9d , r10d, r11d, r12d, r13d, r14d, r15d,  27B70A85h
                ROUND       33, r15d, r8d , r9d , r10d, r11d, r12d, r13d, r14d,  2E1B2138h
                ROUND       34, r14d, r15d, r8d , r9d , r10d, r11d, r12d, r13d,  4D2C6DFCh
                ROUND       35, r13d, r14d, r15d, r8d , r9d , r10d, r11d, r12d,  53380D13h
                ROUND       36, r12d, r13d, r14d, r15d, r8d , r9d , r10d, r11d,  650A7354h
                ROUND       37, r11d, r12d, r13d, r14d, r15d, r8d , r9d , r10d,  766A0ABBh
                ROUND       38, r10d, r11d, r12d, r13d, r14d, r15d, r8d , r9d , -7E3D36D2h
                ROUND       39, r9d , r10d, r11d, r12d, r13d, r14d, r15d, r8d , -6D8DD37Bh
                ROUND       40, r8d , r9d , r10d, r11d, r12d, r13d, r14d, r15d, -5D40175Fh
                ROUND       41, r15d, r8d , r9d , r10d, r11d, r12d, r13d, r14d, -57E599B5h
                ROUND       42, r14d, r15d, r8d , r9d , r10d, r11d, r12d, r13d, -3DB47490h
                ROUND       43, r13d, r14d, r15d, r8d , r9d , r10d, r11d, r12d, -3893AE5Dh
                ROUND       44, r12d, r13d, r14d, r15d, r8d , r9d , r10d, r11d, -2E6D17E7h
                ROUND       45, r11d, r12d, r13d, r14d, r15d, r8d , r9d , r10d, -2966F9DCh
                ROUND       46, r10d, r11d, r12d, r13d, r14d, r15d, r8d , r9d , -0BF1CA7Bh
                ROUND       47, r9d , r10d, r11d, r12d, r13d, r14d, r15d, r8d ,  106AA070h
                ROUND       48, r8d , r9d , r10d, r11d, r12d, r13d, r14d, r15d,  19A4C116h
                ROUND       49, r15d, r8d , r9d , r10d, r11d, r12d, r13d, r14d,  1E376C08h
                ROUND       50, r14d, r15d, r8d , r9d , r10d, r11d, r12d, r13d,  2748774Ch
                ROUND       51, r13d, r14d, r15d, r8d , r9d , r10d, r11d, r12d,  34B0BCB5h
                ROUND       52, r12d, r13d, r14d, r15d, r8d , r9d , r10d, r11d,  391C0CB3h
                ROUND       53, r11d, r12d, r13d, r14d, r15d, r8d , r9d , r10d,  4ED8AA4Ah
                ROUND       54, r10d, r11d, r12d, r13d, r14d, r15d, r8d , r9d ,  5B9CCA4Fh
                ROUND       55, r9d , r10d, r11d, r12d, r13d, r14d, r15d, r8d ,  682E6FF3h
                ROUND       56, r8d , r9d , r10d, r11d, r12d, r13d, r14d, r15d,  748F82EEh
                ROUND       57, r15d, r8d , r9d , r10d, r11d, r12d, r13d, r14d,  78A5636Fh
                ROUND       58, r14d, r15d, r8d , r9d , r10d, r11d, r12d, r13d, -7B3787ECh
                ROUND       59, r13d, r14d, r15d, r8d , r9d , r10d, r11d, r12d, -7338FDF8h
                ROUND       60, r12d, r13d, r14d, r15d, r8d , r9d , r10d, r11d, -6F410006h
                ROUND       61, r11d, r12d, r13d, r14d, r15d, r8d , r9d , r10d, -5BAF9315h
                ROUND       62, r10d, r11d, r12d, r13d, r14d, r15d, r8d , r9d , -41065C09h
                ROUND       63, r9d , r10d, r11d, r12d, r13d, r14d, r15d, r8d , -398E870Eh

                ; Compute intermediate hash value
                add         [rdx]     ,  r8d
                add         [rdx +  4],  r9d
                add         [rdx +  8], r10d
                add         [rdx + 12], r11d
                add         [rdx + 16], r12d
                add         [rdx + 20], r13d
                add         [rdx + 24], r14d
                add         [rdx + 28], r15d

                ; Restore nonvolatile registers
                add         rsp, 64
                pop         r15
                pop         r14
                pop         r13
                pop         r12
                pop         rsi
                pop         rdi
                pop         rbx
                ret
sha256_compress endp
                end
