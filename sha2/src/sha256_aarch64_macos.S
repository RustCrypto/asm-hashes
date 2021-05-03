/*
 * SHA-256 hash in AArch64 assembly for macos/M1
 *
 * Based on the following C intrinsics implementation:
 * <https://github.com/noloader/SHA-Intrinsics/blob/master/sha256-arm.c>
 *
 * Original C written and placed in public domain by Jeffrey Walton.
 * Based on code from ARM, and by Johannes Schneiders, Skip Hovsmith and
 * Barry O'Rourke for the mbedTLS project.
 */


/* void sha256_compress(uint32_t state[8], const uint8_t block[64]) */
.global sha256_compress
        sub     sp, sp, #96
        stp     d11, d10, [sp, #64]
        stp     d9, d8, [sp, #80]
        ldp     q0, q1, [x0]
        cbz     x2, LBB0_5
        adrp    x8, lCPI0_0@PAGE
        ldr     q2, [x8, lCPI0_0@PAGEOFF]
        adrp    x8, lCPI0_1@PAGE
        ldr     q3, [x8, lCPI0_1@PAGEOFF]
        add     x8, x1, x2, lsl #6
        adrp    x9, lCPI0_2@PAGE
        ldr     q4, [x9, lCPI0_2@PAGEOFF]
        mov     x9, sp
        adrp    x10, lCPI0_3@PAGE
        ldr     q5, [x10, lCPI0_3@PAGEOFF]
        adrp    x10, lCPI0_4@PAGE
        ldr     q6, [x10, lCPI0_4@PAGEOFF]
        adrp    x10, lCPI0_5@PAGE
        ldr     q7, [x10, lCPI0_5@PAGEOFF]
        adrp    x10, lCPI0_6@PAGE
        ldr     q16, [x10, lCPI0_6@PAGEOFF]
        adrp    x10, lCPI0_7@PAGE
        ldr     q17, [x10, lCPI0_7@PAGEOFF]
        adrp    x10, lCPI0_8@PAGE
        ldr     q18, [x10, lCPI0_8@PAGEOFF]
        adrp    x10, lCPI0_9@PAGE
        ldr     q19, [x10, lCPI0_9@PAGEOFF]
        adrp    x10, lCPI0_10@PAGE
        ldr     q20, [x10, lCPI0_10@PAGEOFF]
        adrp    x10, lCPI0_11@PAGE
        ldr     q21, [x10, lCPI0_11@PAGEOFF]
        adrp    x10, lCPI0_12@PAGE
        ldr     q22, [x10, lCPI0_12@PAGEOFF]
        adrp    x10, lCPI0_13@PAGE
        ldr     q23, [x10, lCPI0_13@PAGEOFF]
        adrp    x10, lCPI0_14@PAGE
        ldr     q24, [x10, lCPI0_14@PAGEOFF]
        adrp    x10, lCPI0_15@PAGE
        ldr     q25, [x10, lCPI0_15@PAGEOFF]

LBB0_2:
        mov     x10, #0
        ldp     q26, q27, [x1]
        ldp     q28, q29, [x1, #32]
        stp     q26, q27, [sp]
        stp     q28, q29, [sp, #32]
LBB0_3:
        ldr     q26, [x9, x10]
        rev32.16b       v26, v26
        str     q26, [x9, x10]
        add     x10, x10, #16
        cmp     x10, #64
        b.ne    LBB0_3
        add     x1, x1, #64
        ldp     q30, q28, [sp]
        add.4s  v27, v30, v2

        // Rounds 0-3
        sha256su0.4s    v30, v28
        add.4s  v31, v28, v3
        mov.16b v8, v0
        sha256h.4s      q8, q1, v27
        mov.16b v26, v1
        sha256h2.4s     q26, q0, v27
        ldp     q29, q27, [sp, #32]
        sha256su1.4s    v30, v29, v27

        // Rounds 4-7
        sha256su0.4s    v28, v29
        add.4s  v9, v29, v4
        mov.16b v10, v8
        sha256h.4s      q10, q26, v31
        sha256h2.4s     q26, q8, v31
        sha256su1.4s    v28, v27, v30

        // Rounds 8-11
        sha256su0.4s    v29, v27
        add.4s  v31, v27, v5
        mov.16b v8, v10
        sha256h.4s      q8, q26, v9
        sha256h2.4s     q26, q10, v9
        sha256su1.4s    v29, v30, v28

        // Rounds 12-15
        sha256su0.4s    v27, v30
        add.4s  v9, v30, v6
        mov.16b v10, v8
        sha256h.4s      q10, q26, v31
        sha256h2.4s     q26, q8, v31
        sha256su1.4s    v27, v28, v29

        // Rounds 16-19
        sha256su0.4s    v30, v28
        add.4s  v31, v28, v7
        mov.16b v8, v10
        sha256h.4s      q8, q26, v9
        sha256h2.4s     q26, q10, v9
        sha256su1.4s    v30, v29, v27

        // Rounds 20-23
        sha256su0.4s    v28, v29
        add.4s  v9, v29, v16
        mov.16b v10, v8
        sha256h.4s      q10, q26, v31
        sha256h2.4s     q26, q8, v31
        sha256su1.4s    v28, v27, v30

        // Rounds 24-27
        sha256su0.4s    v29, v27
        add.4s  v31, v27, v17
        mov.16b v8, v10
        sha256h.4s      q8, q26, v9
        sha256h2.4s     q26, q10, v9
        sha256su1.4s    v29, v30, v28

        // Rounds 28-31
        sha256su0.4s    v27, v30
        add.4s  v9, v30, v18
        mov.16b v10, v8
        sha256h.4s      q10, q26, v31
        sha256h2.4s     q26, q8, v31
        sha256su1.4s    v27, v28, v29

        // Rounds 32-35
        sha256su0.4s    v30, v28
        add.4s  v31, v28, v19
        mov.16b v8, v10
        sha256h.4s      q8, q26, v9
        sha256h2.4s     q26, q10, v9
        sha256su1.4s    v30, v29, v27

        // Rounds 36-39
        sha256su0.4s    v28, v29
        add.4s  v9, v29, v20
        mov.16b v10, v8
        sha256h.4s      q10, q26, v31
        sha256h2.4s     q26, q8, v31
        sha256su1.4s    v28, v27, v30

        // Rounds 40-43
        sha256su0.4s    v29, v27
        add.4s  v31, v27, v21
        mov.16b v8, v10
        sha256h.4s      q8, q26, v9
        sha256h2.4s     q26, q10, v9
        sha256su1.4s    v29, v30, v28

        //  Rounds 44-47
        sha256su0.4s    v27, v30
        add.4s  v30, v30, v22
        mov.16b v9, v8
        sha256h.4s      q9, q26, v31
        sha256h2.4s     q26, q8, v31
        sha256su1.4s    v27, v28, v29

        // Rounds 48-51
        add.4s  v28, v28, v23
        mov.16b v31, v9
        sha256h.4s      q31, q26, v30
        sha256h2.4s     q26, q9, v30

        // Rounds 52-55
        add.4s  v29, v29, v24
        mov.16b v30, v31
        sha256h.4s      q30, q26, v28
        sha256h2.4s     q26, q31, v28

        // Rounds 56-59
        add.4s  v27, v27, v25
        mov.16b v28, v30
        sha256h.4s      q28, q26, v29
        sha256h2.4s     q26, q30, v29

        // Rounds 60-63
        mov.16b v29, v28
        sha256h.4s      q29, q26, v27
        sha256h2.4s     q26, q28, v27

        // Update state
        add.4s  v0, v29, v0
        add.4s  v1, v26, v1
        cmp     x1, x8
        b.ne    LBB0_2
        
LBB0_5:
        stp     q0, q1, [x0]

        // restore
        ldp     d9, d8, [sp, #80]
        ldp     d11, d10, [sp, #64]
        add     sp, sp, #96
        ret


.align 4
lCPI0_0:
        .long   1116352408
        .long   1899447441
        .long   3049323471
        .long   3921009573
lCPI0_1:
        .long   961987163
        .long   1508970993
        .long   2453635748
        .long   2870763221
lCPI0_2:
        .long   3624381080
        .long   310598401
        .long   607225278
        .long   1426881987
lCPI0_3:
        .long   1925078388
        .long   2162078206
        .long   2614888103
        .long   3248222580
lCPI0_4:
        .long   3835390401
        .long   4022224774
        .long   264347078
        .long   604807628
lCPI0_5:
        .long   770255983
        .long   1249150122
        .long   1555081692
        .long   1996064986
lCPI0_6:
        .long   2554220882
        .long   2821834349
        .long   2952996808
        .long   3210313671
lCPI0_7:
        .long   3336571891
        .long   3584528711
        .long   113926993
        .long   338241895
lCPI0_8:
        .long   666307205
        .long   773529912
        .long   1294757372
        .long   1396182291
lCPI0_9:
        .long   1695183700
        .long   1986661051
        .long   2177026350
        .long   2456956037
lCPI0_10:
        .long   2730485921
        .long   2820302411
        .long   3259730800
        .long   3345764771
lCPI0_11:
        .long   3516065817
        .long   3600352804
        .long   4094571909
        .long   275423344
lCPI0_12:
        .long   430227734
        .long   506948616
        .long   659060556
        .long   883997877
lCPI0_13:
        .long   958139571
        .long   1322822218
        .long   1537002063
        .long   1747873779
lCPI0_14:
        .long   1955562222
        .long   2024104815
        .long   2227730452
        .long   2361852424
lCPI0_15:
        .long   2428436474
        .long   2756734187
        .long   3204031479
        .long   3329325298
