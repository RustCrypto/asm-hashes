/*
 * SHA-1 hash in LoongArch64 assembly
 *
 * Copyright (c) 2023, Loongson Technology. (MIT License)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 * - The above copyright notice and this permission notice shall be included in
 *   all copies or substantial portions of the Software.
 * - The Software is provided "as is", without warranty of any kind, express or
 *   implied, including but not limited to the warranties of merchantability,
 *   fitness for a particular purpose and noninfringement. In no event shall the
 *   authors or copyright holders be liable for any claim, damages or other
 *   liability, whether in an action of contract, tort or otherwise, arising from,
 *   out of or in connection with the Software or the use or other dealings in the
 *   Software.
 */

/* void sha1_compress(uint32_t state[5], const uint8_t block[64]) */
.globl sha1_compress
sha1_compress:
    /*
     * Storage usage:
     *   Bytes  Location  Description
     *       4  $t0       SHA-1 state variable A
     *       4  $t1       SHA-1 state variable B
     *       4  $t2       SHA-1 state variable C
     *       4  $t3       SHA-1 state variable D
     *       4  $t4       SHA-1 state variable E
     *       4  $t5       Temporary for calculation per round
     *       4  $t6       Temporary for calculation per round
     *       4  $t7       Temporary for calculation per round
     *       4  $t8       Temporary for calculation per round
     *       8  $a1       (First 16 rounds) base address of block array argument (read-only)
     *       8  $a0       Base address of state array argument (read-only)
     *       8  $sp       Stack pointer
     *      64  [$sp+0]   Circular buffer of most recent 16 key schedule items, 4 bytes each
     */

    #define ROUND0a(a, b, c, d, e, i) \
        ld.w    $t5, $a1, (i * 4);    \
        revb.2h $t5, $t5;             \
        rotri.w $t5, $t5, 16;         \
        add.w   e, e, $t5;            \
        st.w    $t5, $sp, (i * 4);    \
        xor     $t5, c, d;            \
        and     $t5, $t5, b;          \
        xor     $t5, $t5, d;          \
        ROUNDTAIL(a, b, e, i, $a4);

    #define SCHEDULE(i, e)                        \
        ld.w    $t5, $sp, (((i - 3) & 0xF) * 4);  \
        ld.w    $t6, $sp, (((i - 8) & 0xF) * 4);  \
        ld.w    $t7, $sp, (((i - 14) & 0xF) * 4); \
        ld.w    $t8, $sp, (((i - 16) & 0xF) * 4); \
        xor     $t5, $t5, $t6;                    \
        xor     $t5, $t5, $t7;                    \
        xor     $t5, $t5, $t8;                    \
        rotri.w $t5, $t5, 31;                     \
        add.w   e, e, $t5;                        \
        st.w    $t5, $sp, ((i & 0xF) * 4);

    #define ROUND0b(a, b, c, d, e, i) \
        SCHEDULE(i, e);               \
        xor     $t5, c, d;            \
        and     $t5, $t5, b;          \
        xor     $t5, $t5, d;          \
        ROUNDTAIL(a, b, e, i, $a4);

    #define ROUND1(a, b, c, d, e, i) \
        SCHEDULE(i, e);              \
        xor     $t5, b, c;           \
        xor     $t5, $t5, d;         \
        ROUNDTAIL(a, b, e, i, $a5);

    #define ROUND2(a, b, c, d, e, i) \
        SCHEDULE(i, e);              \
        or      $t5, c, d;           \
        and     $t5, $t5, b;         \
        and     $t7, c, d;           \
        or      $t5, $t5, $t7;       \
        ROUNDTAIL(a, b, e, i, $a6);

    #define ROUND3(a, b, c, d, e, i) \
        SCHEDULE(i, e);              \
        xor     $t5, b, c;           \
        xor     $t5, $t5, d;         \
        ROUNDTAIL(a, b, e, i, $a7);

    #define ROUNDTAIL(a, b, e, i, k) \
        rotri.w b, b, 2;             \
        add.w   e, e, $t5;           \
        add.w   e, e, k;             \
        rotri.w $t5, a, 27;          \
        add.w   e, e, $t5;

    /* Save registers, allocate scratch space */
    addi.d  $sp, $sp, -64

    /* Load keys */
    la.pcrel $t0, .Lkeys
    ld.w     $a4, $t0, 0
    ld.w     $a5, $t0, 4
    ld.w     $a6, $t0, 8
    ld.w     $a7, $t0, 12

    /* Load arguments */
    ld.w    $t0, $a0, 0  /* a */
    ld.w    $t1, $a0, 4  /* b */
    ld.w    $t2, $a0, 8  /* c */
    ld.w    $t3, $a0, 12 /* d */
    ld.w    $t4, $a0, 16 /* e */

    /* 80 rounds of hashing */
    ROUND0a($t0, $t1, $t2, $t3, $t4,  0)
    ROUND0a($t4, $t0, $t1, $t2, $t3,  1)
    ROUND0a($t3, $t4, $t0, $t1, $t2,  2)
    ROUND0a($t2, $t3, $t4, $t0, $t1,  3)
    ROUND0a($t1, $t2, $t3, $t4, $t0,  4)
    ROUND0a($t0, $t1, $t2, $t3, $t4,  5)
    ROUND0a($t4, $t0, $t1, $t2, $t3,  6)
    ROUND0a($t3, $t4, $t0, $t1, $t2,  7)
    ROUND0a($t2, $t3, $t4, $t0, $t1,  8)
    ROUND0a($t1, $t2, $t3, $t4, $t0,  9)
    ROUND0a($t0, $t1, $t2, $t3, $t4, 10)
    ROUND0a($t4, $t0, $t1, $t2, $t3, 11)
    ROUND0a($t3, $t4, $t0, $t1, $t2, 12)
    ROUND0a($t2, $t3, $t4, $t0, $t1, 13)
    ROUND0a($t1, $t2, $t3, $t4, $t0, 14)
    ROUND0a($t0, $t1, $t2, $t3, $t4, 15)
    ROUND0b($t4, $t0, $t1, $t2, $t3, 16)
    ROUND0b($t3, $t4, $t0, $t1, $t2, 17)
    ROUND0b($t2, $t3, $t4, $t0, $t1, 18)
    ROUND0b($t1, $t2, $t3, $t4, $t0, 19)
    ROUND1($t0, $t1, $t2, $t3, $t4, 20)
    ROUND1($t4, $t0, $t1, $t2, $t3, 21)
    ROUND1($t3, $t4, $t0, $t1, $t2, 22)
    ROUND1($t2, $t3, $t4, $t0, $t1, 23)
    ROUND1($t1, $t2, $t3, $t4, $t0, 24)
    ROUND1($t0, $t1, $t2, $t3, $t4, 25)
    ROUND1($t4, $t0, $t1, $t2, $t3, 26)
    ROUND1($t3, $t4, $t0, $t1, $t2, 27)
    ROUND1($t2, $t3, $t4, $t0, $t1, 28)
    ROUND1($t1, $t2, $t3, $t4, $t0, 29)
    ROUND1($t0, $t1, $t2, $t3, $t4, 30)
    ROUND1($t4, $t0, $t1, $t2, $t3, 31)
    ROUND1($t3, $t4, $t0, $t1, $t2, 32)
    ROUND1($t2, $t3, $t4, $t0, $t1, 33)
    ROUND1($t1, $t2, $t3, $t4, $t0, 34)
    ROUND1($t0, $t1, $t2, $t3, $t4, 35)
    ROUND1($t4, $t0, $t1, $t2, $t3, 36)
    ROUND1($t3, $t4, $t0, $t1, $t2, 37)
    ROUND1($t2, $t3, $t4, $t0, $t1, 38)
    ROUND1($t1, $t2, $t3, $t4, $t0, 39)
    ROUND2($t0, $t1, $t2, $t3, $t4, 40)
    ROUND2($t4, $t0, $t1, $t2, $t3, 41)
    ROUND2($t3, $t4, $t0, $t1, $t2, 42)
    ROUND2($t2, $t3, $t4, $t0, $t1, 43)
    ROUND2($t1, $t2, $t3, $t4, $t0, 44)
    ROUND2($t0, $t1, $t2, $t3, $t4, 45)
    ROUND2($t4, $t0, $t1, $t2, $t3, 46)
    ROUND2($t3, $t4, $t0, $t1, $t2, 47)
    ROUND2($t2, $t3, $t4, $t0, $t1, 48)
    ROUND2($t1, $t2, $t3, $t4, $t0, 49)
    ROUND2($t0, $t1, $t2, $t3, $t4, 50)
    ROUND2($t4, $t0, $t1, $t2, $t3, 51)
    ROUND2($t3, $t4, $t0, $t1, $t2, 52)
    ROUND2($t2, $t3, $t4, $t0, $t1, 53)
    ROUND2($t1, $t2, $t3, $t4, $t0, 54)
    ROUND2($t0, $t1, $t2, $t3, $t4, 55)
    ROUND2($t4, $t0, $t1, $t2, $t3, 56)
    ROUND2($t3, $t4, $t0, $t1, $t2, 57)
    ROUND2($t2, $t3, $t4, $t0, $t1, 58)
    ROUND2($t1, $t2, $t3, $t4, $t0, 59)
    ROUND3($t0, $t1, $t2, $t3, $t4, 60)
    ROUND3($t4, $t0, $t1, $t2, $t3, 61)
    ROUND3($t3, $t4, $t0, $t1, $t2, 62)
    ROUND3($t2, $t3, $t4, $t0, $t1, 63)
    ROUND3($t1, $t2, $t3, $t4, $t0, 64)
    ROUND3($t0, $t1, $t2, $t3, $t4, 65)
    ROUND3($t4, $t0, $t1, $t2, $t3, 66)
    ROUND3($t3, $t4, $t0, $t1, $t2, 67)
    ROUND3($t2, $t3, $t4, $t0, $t1, 68)
    ROUND3($t1, $t2, $t3, $t4, $t0, 69)
    ROUND3($t0, $t1, $t2, $t3, $t4, 70)
    ROUND3($t4, $t0, $t1, $t2, $t3, 71)
    ROUND3($t3, $t4, $t0, $t1, $t2, 72)
    ROUND3($t2, $t3, $t4, $t0, $t1, 73)
    ROUND3($t1, $t2, $t3, $t4, $t0, 74)
    ROUND3($t0, $t1, $t2, $t3, $t4, 75)
    ROUND3($t4, $t0, $t1, $t2, $t3, 76)
    ROUND3($t3, $t4, $t0, $t1, $t2, 77)
    ROUND3($t2, $t3, $t4, $t0, $t1, 78)
    ROUND3($t1, $t2, $t3, $t4, $t0, 79)

    /* Save updated state */
    ld.w    $t5, $a0, 0  /* a */
    ld.w    $t6, $a0, 4  /* b */
    ld.w    $t7, $a0, 8  /* c */
    ld.w    $t8, $a0, 12 /* d */
    add.w   $t0, $t0, $t5
    ld.w    $t5, $a0, 16 /* e */
    add.w   $t1, $t1, $t6
    add.w   $t2, $t2, $t7
    add.w   $t3, $t3, $t8
    add.w   $t4, $t4, $t5
    st.w    $t0, $a0, 0  /* a */
    st.w    $t1, $a0, 4  /* b */
    st.w    $t2, $a0, 8  /* c */
    st.w    $t3, $a0, 12 /* d */
    st.w    $t4, $a0, 16 /* e */

    /* Restore registers */
    addi.d  $sp, $sp, 64
    jirl    $zero, $ra, 0

.Lkeys:
    .word   0x5A827999
    .word   0x6ED9EBA1
    .word   0x8F1BBCDC
    .word   0xCA62C1D6
