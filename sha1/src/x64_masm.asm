;
; SHA1 hash in x64 MASM
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
;       8  rsp       no        x64 stack pointer
;       4  r8d       yes       SHA1 working variable A
;       4  r9d       yes       SHA1 working variable B
;       4  r10d      yes       SHA1 working variable C
;       4  r11d      yes       SHA1 working variable D
;       4  r12d      no        SHA1 working variable E
;      64  [rsp+0]   no        Circular buffer of most recent 16 message schedule items, 4 bytes each

                option  casemap:none

                .const
SCHED           macro       i
                index       textequ %i AND 0fh              ; i mod 16
                exitm       <[rsp + index*4]>
                endm

ROUNDTAIL       macro       a, b, e, k                      ; eax = f[i], e -> e + w[i]
                ; (obj1) e -> a rol 5 + f[i] + e + w[i] + k[i]
                ; (obj2) b -> b rol 30
                mov         ebx, a
                rol         ebx, 5
                lea         e, [ebx + e + k]                ; e -> a rol 5 + e + w[i] + k[i]
                add         e, eax                          ; e -> a rol 5 + f[i] + e + w[i] + k[i] (obj1)
                rol         b, 30                           ; b -> b rol 30 (obj2)
                endm

ROUND           macro       i, a, b, c, d, e

if i LT 16

                mov         eax, [rcx + i*4]
                bswap       eax

else

                mov         eax, SCHED(i -  3)
                xor         eax, SCHED(i -  8)
                xor         eax, SCHED(i - 14)
                xor         eax, SCHED(i - 16)
                rol         eax, 1

endif

                mov         SCHED(i), eax
                add         e, eax                          ; e -> e + w[i]

if i LT 20

                ; eax = f[i] = (b & c) ^ (~b & d) = d ^ b & (c ^ d)
                ; & and ^ form the Z/2Z ring (& is *, ^ is +)
                ; ~b is (1 + b)
                ; bc + (1 + b)d = bc + d + bd = d + b(c + d)
                mov         eax, c
                xor         eax, d
                and         eax, b
                xor         eax, d
                ROUNDTAIL   a, b, e,  5A827999h

elseif i GE 40 AND i LT 60

                ; eax = f[i] = (b & c) ^ (b & d) ^ (c & d) = (b & (c | d)) | (c & d)
                ; https://www.wolframalpha.com/input?i=simplify+%28b+%26%26+c%29+xor+%28b+%26%26+d%29+xor+%28c+%26%26+d%29
                mov         eax, c
                mov         ebx, c
                or          eax, d
                and         eax, b
                and         ebx, d
                or          eax, ebx
                ROUNDTAIL   a, b, e, -70E44324h

else

                ; eax = f[i] = b ^ c ^ d
                mov         eax, b
                xor         eax, c
                xor         eax, d

    if i LT 40

                ROUNDTAIL   a, b, e,  6ED9EBA1h

    else

                ROUNDTAIL   a, b, e, -359D3E2Ah

    endif

endif

                endm

                .code
                ; void sha1_compress(const uint8_t block[64], uint32_t state[5])
                public      sha1_compress
sha1_compress   proc
                ; Save nonvolatile registers, allocate scratch space
                push        rbx
                push        r12
                sub         rsp, 64

                ; Initialize working variables with previous hash value
                mov          r8d, [rdx]                     ; a
                mov          r9d, [rdx +  4]                ; b
                mov         r10d, [rdx +  8]                ; c
                mov         r11d, [rdx + 12]                ; d
                mov         r12d, [rdx + 16]                ; e

                ; 80 rounds of hashing
                ROUND        0, r8d, r9d, r10d, r11d, r12d
                ROUND        1, r12d, r8d, r9d, r10d, r11d
                ROUND        2, r11d, r12d, r8d, r9d, r10d
                ROUND        3, r10d, r11d, r12d, r8d, r9d
                ROUND        4, r9d, r10d, r11d, r12d, r8d
                ROUND        5, r8d, r9d, r10d, r11d, r12d
                ROUND        6, r12d, r8d, r9d, r10d, r11d
                ROUND        7, r11d, r12d, r8d, r9d, r10d
                ROUND        8, r10d, r11d, r12d, r8d, r9d
                ROUND        9, r9d, r10d, r11d, r12d, r8d
                ROUND       10, r8d, r9d, r10d, r11d, r12d
                ROUND       11, r12d, r8d, r9d, r10d, r11d
                ROUND       12, r11d, r12d, r8d, r9d, r10d
                ROUND       13, r10d, r11d, r12d, r8d, r9d
                ROUND       14, r9d, r10d, r11d, r12d, r8d
                ROUND       15, r8d, r9d, r10d, r11d, r12d
                ROUND       16, r12d, r8d, r9d, r10d, r11d
                ROUND       17, r11d, r12d, r8d, r9d, r10d
                ROUND       18, r10d, r11d, r12d, r8d, r9d
                ROUND       19, r9d, r10d, r11d, r12d, r8d
                ROUND       20, r8d, r9d, r10d, r11d, r12d
                ROUND       21, r12d, r8d, r9d, r10d, r11d
                ROUND       22, r11d, r12d, r8d, r9d, r10d
                ROUND       23, r10d, r11d, r12d, r8d, r9d
                ROUND       24, r9d, r10d, r11d, r12d, r8d
                ROUND       25, r8d, r9d, r10d, r11d, r12d
                ROUND       26, r12d, r8d, r9d, r10d, r11d
                ROUND       27, r11d, r12d, r8d, r9d, r10d
                ROUND       28, r10d, r11d, r12d, r8d, r9d
                ROUND       29, r9d, r10d, r11d, r12d, r8d
                ROUND       30, r8d, r9d, r10d, r11d, r12d
                ROUND       31, r12d, r8d, r9d, r10d, r11d
                ROUND       32, r11d, r12d, r8d, r9d, r10d
                ROUND       33, r10d, r11d, r12d, r8d, r9d
                ROUND       34, r9d, r10d, r11d, r12d, r8d
                ROUND       35, r8d, r9d, r10d, r11d, r12d
                ROUND       36, r12d, r8d, r9d, r10d, r11d
                ROUND       37, r11d, r12d, r8d, r9d, r10d
                ROUND       38, r10d, r11d, r12d, r8d, r9d
                ROUND       39, r9d, r10d, r11d, r12d, r8d
                ROUND       40, r8d, r9d, r10d, r11d, r12d
                ROUND       41, r12d, r8d, r9d, r10d, r11d
                ROUND       42, r11d, r12d, r8d, r9d, r10d
                ROUND       43, r10d, r11d, r12d, r8d, r9d
                ROUND       44, r9d, r10d, r11d, r12d, r8d
                ROUND       45, r8d, r9d, r10d, r11d, r12d
                ROUND       46, r12d, r8d, r9d, r10d, r11d
                ROUND       47, r11d, r12d, r8d, r9d, r10d
                ROUND       48, r10d, r11d, r12d, r8d, r9d
                ROUND       49, r9d, r10d, r11d, r12d, r8d
                ROUND       50, r8d, r9d, r10d, r11d, r12d
                ROUND       51, r12d, r8d, r9d, r10d, r11d
                ROUND       52, r11d, r12d, r8d, r9d, r10d
                ROUND       53, r10d, r11d, r12d, r8d, r9d
                ROUND       54, r9d, r10d, r11d, r12d, r8d
                ROUND       55, r8d, r9d, r10d, r11d, r12d
                ROUND       56, r12d, r8d, r9d, r10d, r11d
                ROUND       57, r11d, r12d, r8d, r9d, r10d
                ROUND       58, r10d, r11d, r12d, r8d, r9d
                ROUND       59, r9d, r10d, r11d, r12d, r8d
                ROUND       60, r8d, r9d, r10d, r11d, r12d
                ROUND       61, r12d, r8d, r9d, r10d, r11d
                ROUND       62, r11d, r12d, r8d, r9d, r10d
                ROUND       63, r10d, r11d, r12d, r8d, r9d
                ROUND       64, r9d, r10d, r11d, r12d, r8d
                ROUND       65, r8d, r9d, r10d, r11d, r12d
                ROUND       66, r12d, r8d, r9d, r10d, r11d
                ROUND       67, r11d, r12d, r8d, r9d, r10d
                ROUND       68, r10d, r11d, r12d, r8d, r9d
                ROUND       69, r9d, r10d, r11d, r12d, r8d
                ROUND       70, r8d, r9d, r10d, r11d, r12d
                ROUND       71, r12d, r8d, r9d, r10d, r11d
                ROUND       72, r11d, r12d, r8d, r9d, r10d
                ROUND       73, r10d, r11d, r12d, r8d, r9d
                ROUND       74, r9d, r10d, r11d, r12d, r8d
                ROUND       75, r8d, r9d, r10d, r11d, r12d
                ROUND       76, r12d, r8d, r9d, r10d, r11d
                ROUND       77, r11d, r12d, r8d, r9d, r10d
                ROUND       78, r10d, r11d, r12d, r8d, r9d
                ROUND       79, r9d, r10d, r11d, r12d, r8d

                ; Compute intermediate hash value
                add         [rdx]     ,  r8d
                add         [rdx +  4],  r9d
                add         [rdx +  8], r10d
                add         [rdx + 12], r11d
                add         [rdx + 16], r12d

                ; Restore nonvolatile registers
                add         rsp, 64
                pop         r12
                pop         rbx
                ret
sha1_compress   endp
                end
