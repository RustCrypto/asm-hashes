;
; Whirlpool hash in x64 MASM
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
;       4  esi       no        Upward loop counter for 10 rounds
;       8  rsp       no        x64 stack pointer
;       8  r8...r11  yes       Output rows for current round being computed, in little endian (8 bytes per register)
;       8  r12..r15  no        Output rows for current round being computed, in little endian (8 bytes per register)
;      64  xmm0..3   yes       All contents of current state array, in little endian (16 bytes per register)
;      64  xmm4..7   no(6,7)   All contents of current block array, in little endian (16 bytes per register)
;       8  [rsp+0]   no        Temporary storage for transferring r15 to xmm

                    option  casemap:none

NUM_ROUNDS          =       10
                    .const
; Starting from the beginning, each round uses 8 bytes
roundconstants      byte    018h, 023h, 0C6h, 0E8h, 087h, 0B8h, 001h, 04Fh, 036h, 0A6h, 0D2h, 0F5h, 079h, 06Fh, 091h, 052h
                    byte    060h, 0BCh, 09Bh, 08Eh, 0A3h, 00Ch, 07Bh, 035h, 01Dh, 0E0h, 0D7h, 0C2h, 02Eh, 04Bh, 0FEh, 057h
                    byte    015h, 077h, 037h, 0E5h, 09Fh, 0F0h, 04Ah, 0DAh, 058h, 0C9h, 029h, 00Ah, 0B1h, 0A0h, 06Bh, 085h
                    byte    0BDh, 05Dh, 010h, 0F4h, 0CBh, 03Eh, 005h, 067h, 0E4h, 027h, 041h, 08Bh, 0A7h, 07Dh, 095h, 0D8h
                    byte    0FBh, 0EEh, 07Ch, 066h, 0DDh, 017h, 047h, 09Eh, 0CAh, 02Dh, 0BFh, 007h, 0ADh, 05Ah, 083h, 033h
                    byte    063h, 002h, 0AAh, 071h, 0C8h, 019h, 049h, 0D9h, 0F2h, 0E3h, 05Bh, 088h, 09Ah, 026h, 032h, 0B0h
                    byte    0E9h, 00Fh, 0D5h, 080h, 0BEh, 0CDh, 034h, 048h, 0FFh, 07Ah, 090h, 05Fh, 020h, 068h, 01Ah, 0AEh
                    byte    0B4h, 054h, 093h, 022h, 064h, 0F1h, 073h, 012h, 040h, 008h, 0C3h, 0ECh, 0DBh, 0A1h, 08Dh, 03Dh
                    byte    097h, 000h, 0CFh, 02Bh, 076h, 082h, 0D6h, 01Bh, 0B5h, 0AFh, 06Ah, 050h, 045h, 0F3h, 030h, 0EFh
                    byte    03Fh, 055h, 0A2h, 0EAh, 065h, 0BAh, 02Fh, 0C0h, 0DEh, 01Ch, 0FDh, 04Dh, 092h, 075h, 006h, 08Ah
                    byte    0B2h, 0E6h, 00Eh, 01Fh, 062h, 0D4h, 0A8h, 096h, 0F9h, 0C5h, 025h, 059h, 084h, 072h, 039h, 04Ch
                    byte    05Eh, 078h, 038h, 08Ch, 0D1h, 0A5h, 0E2h, 061h, 0B3h, 021h, 09Ch, 01Eh, 043h, 0C7h, 0FCh, 004h
                    byte    051h, 099h, 06Dh, 00Dh, 0FAh, 0DFh, 07Eh, 024h, 03Bh, 0ABh, 0CEh, 011h, 08Fh, 04Eh, 0B7h, 0EBh
                    byte    03Ch, 081h, 094h, 0F7h, 0B9h, 013h, 02Ch, 0D3h, 0E7h, 06Eh, 0C4h, 003h, 056h, 044h, 07Fh, 0A9h
                    byte    02Ah, 0BBh, 0C1h, 053h, 0DCh, 00Bh, 09Dh, 06Ch, 031h, 074h, 0F6h, 046h, 0ACh, 089h, 014h, 0E1h
                    byte    016h, 03Ah, 069h, 009h, 070h, 0B6h, 0D0h, 0EDh, 0CCh, 042h, 098h, 0A4h, 028h, 05Ch, 0F8h, 086h

; The combined effect of gamma (SubBytes) and theta (MixRows)
magictable0         qword   0D83078C018601818h, 02646AF05238C2323h, 0B891F97EC63FC6C6h, 0FBCD6F13E887E8E8h, 0CB13A14C87268787h, 0116D62A9B8DAB8B8h, 00902050801040101h, 00D9E6E424F214F4Fh
                    qword   09B6CEEAD36D83636h, 0FF510459A6A2A6A6h, 00CB9BDDED26FD2D2h, 00EF706FBF5F3F5F5h, 096F280EF79F97979h, 030DECE5F6FA16F6Fh, 06D3FEFFC917E9191h, 0F8A407AA52555252h
                    qword   047C0FD27609D6060h, 035657689BCCABCBCh, 0372BCDAC9B569B9Bh, 08A018C048E028E8Eh, 0D25B1571A3B6A3A3h, 06C183C600C300C0Ch, 084F68AFF7BF17B7Bh, 0806AE1B535D43535h
                    qword   0F53A69E81D741D1Dh, 0B3DD4753E0A7E0E0h, 021B3ACF6D77BD7D7h, 09C99ED5EC22FC2C2h, 0435C966D2EB82E2Eh, 029967A624B314B4Bh, 05DE121A3FEDFFEFEh, 0D5AE168257415757h
                    qword   0BD2A41A815541515h, 0E8EEB69F77C17777h, 0926EEBA537DC3737h, 09ED7567BE5B3E5E5h, 01323D98C9F469F9Fh, 023FD17D3F0E7F0F0h, 020947F6A4A354A4Ah, 044A9959EDA4FDADAh
                    qword   0A2B025FA587D5858h, 0CF8FCA06C903C9C9h, 07C528D5529A42929h, 05A1422500A280A0Ah, 0507F4FE1B1FEB1B1h, 0C95D1A69A0BAA0A0h, 014D6DA7F6BB16B6Bh, 0D917AB5C852E8585h
                    qword   03C677381BDCEBDBDh, 08FBA34D25D695D5Dh, 09020508010401010h, 007F503F3F4F7F4F4h, 0DD8BC016CB0BCBCBh, 0D37CC6ED3EF83E3Eh, 02D0A112805140505h, 078CEE61F67816767h
                    qword   097D55373E4B7E4E4h, 0024EBB25279C2727h, 07382583241194141h, 0A70B9D2C8B168B8Bh, 0F6530151A7A6A7A7h, 0B2FA94CF7DE97D7Dh, 04937FBDC956E9595h, 056AD9F8ED847D8D8h
                    qword   070EB308BFBCBFBFBh, 0CDC17123EE9FEEEEh, 0BBF891C77CED7C7Ch, 071CCE31766856666h, 07BA78EA6DD53DDDDh, 0AF2E4BB8175C1717h, 0458E460247014747h, 01A21DC849E429E9Eh
                    qword   0D489C51ECA0FCACAh, 0585A99752DB42D2Dh, 02E637991BFC6BFBFh, 03F0E1B38071C0707h, 0AC472301AD8EADADh, 0B0B42FEA5A755A5Ah, 0EF1BB56C83368383h, 0B666FF8533CC3333h
                    qword   05CC6F23F63916363h, 012040A1002080202h, 093493839AA92AAAAh, 0DEE2A8AF71D97171h, 0C68DCF0EC807C8C8h, 0D1327DC819641919h, 03B92707249394949h, 05FAF9A86D943D9D9h
                    qword   031F91DC3F2EFF2F2h, 0A8DB484BE3ABE3E3h, 0B9B62AE25B715B5Bh, 0BC0D9234881A8888h, 03E29C8A49A529A9Ah, 00B4CBE2D26982626h, 0BF64FA8D32C83232h, 0597D4AE9B0FAB0B0h
                    qword   0F2CF6A1BE983E9E9h, 0771E33780F3C0F0Fh, 033B7A6E6D573D5D5h, 0F41DBA74803A8080h, 027617C99BEC2BEBEh, 0EB87DE26CD13CDCDh, 08968E4BD34D03434h, 03290757A483D4848h
                    qword   054E324ABFFDBFFFFh, 08DF48FF77AF57A7Ah, 0643DEAF4907A9090h, 09DBE3EC25F615F5Fh, 03D40A01D20802020h, 00FD0D56768BD6868h, 0CA3472D01A681A1Ah, 0B7412C19AE82AEAEh
                    qword   07D755EC9B4EAB4B4h, 0CEA8199A544D5454h, 07F3BE5EC93769393h, 02F44AA0D22882222h, 063C8E907648D6464h, 02AFF12DBF1E3F1F1h, 0CCE6A2BF73D17373h, 082245A9012481212h
                    qword   07A805D3A401D4040h, 04810284008200808h, 0959BE856C32BC3C3h, 0DFC57B33EC97ECECh, 04DAB9096DB4BDBDBh, 0C05F1F61A1BEA1A1h, 09107831C8D0E8D8Dh, 0C87AC9F53DF43D3Dh
                    qword   05B33F1CC97669797h, 00000000000000000h, 0F983D436CF1BCFCFh, 06E5687452BAC2B2Bh, 0E1ECB39776C57676h, 0E619B06482328282h, 028B1A9FED67FD6D6h, 0C33677D81B6C1B1Bh
                    qword   074775BC1B5EEB5B5h, 0BE432911AF86AFAFh, 01DD4DF776AB56A6Ah, 0EAA00DBA505D5050h, 0578A4C1245094545h, 038FB18CBF3EBF3F3h, 0AD60F09D30C03030h, 0C4C3742BEF9BEFEFh
                    qword   0DA7EC3E53FFC3F3Fh, 0C7AA1C9255495555h, 0DB591079A2B2A2A2h, 0E9C96503EA8FEAEAh, 06ACAEC0F65896565h, 0036968B9BAD2BABAh, 04A5E93652FBC2F2Fh, 08E9DE74EC027C0C0h
                    qword   060A181BEDE5FDEDEh, 0FC386CE01C701C1Ch, 046E72EBBFDD3FDFDh, 01F9A64524D294D4Dh, 07639E0E492729292h, 0FAEABC8F75C97575h, 0360C1E3006180606h, 0AE0998248A128A8Ah
                    qword   04B7940F9B2F2B2B2h, 085D15963E6BFE6E6h, 07E1C36700E380E0Eh, 0E73E63F81F7C1F1Fh, 055C4F73762956262h, 03AB5A3EED477D4D4h, 0814D3229A89AA8A8h, 05231F4C496629696h
                    qword   062EF3A9BF9C3F9F9h, 0A397F666C533C5C5h, 0104AB13525942525h, 0ABB220F259795959h, 0D015AE54842A8484h, 0C5E4A7B772D57272h, 0EC72DDD539E43939h, 01698615A4C2D4C4Ch
                    qword   094BC3BCA5E655E5Eh, 09FF085E778FD7878h, 0E570D8DD38E03838h, 0980586148C0A8C8Ch, 017BFB2C6D163D1D1h, 0E4570B41A5AEA5A5h, 0A1D94D43E2AFE2E2h, 04EC2F82F61996161h
                    qword   0427B45F1B3F6B3B3h, 03442A51521842121h, 00825D6949C4A9C9Ch, 0EE3C66F01E781E1Eh, 06186522243114343h, 0B193FC76C73BC7C7h, 04FE52BB3FCD7FCFCh, 02408142004100404h
                    qword   0E3A208B251595151h, 0252FC7BC995E9999h, 022DAC44F6DA96D6Dh, 0651A39680D340D0Dh, 079E93583FACFFAFAh, 069A384B6DF5BDFDFh, 0A9FC9BD77EE57E7Eh, 01948B43D24902424h
                    qword   0FE76D7C53BEC3B3Bh, 09A4B3D31AB96ABABh, 0F081D13ECE1FCECEh, 09922558811441111h, 08303890C8F068F8Fh, 0049C6B4A4E254E4Eh, 0667351D1B7E6B7B7h, 0E0CB600BEB8BEBEBh
                    qword   0C178CCFD3CF03C3Ch, 0FD1FBF7C813E8181h, 04035FED4946A9494h, 01CF30CEBF7FBF7F7h, 0186F67A1B9DEB9B9h, 08B265F98134C1313h, 051589C7D2CB02C2Ch, 005BBB8D6D36BD3D3h
                    qword   08CD35C6BE7BBE7E7h, 039DCCB576EA56E6Eh, 0AA95F36EC437C4C4h, 01B060F18030C0303h, 0DCAC138A56455656h, 05E88491A440D4444h, 0A0FE9EDF7FE17F7Fh, 0884F3721A99EA9A9h
                    qword   06754824D2AA82A2Ah, 00A6B6DB1BBD6BBBBh, 0879FE246C123C1C1h, 0F1A602A253515353h, 072A58BAEDC57DCDCh, 0531627580B2C0B0Bh, 00127D39C9D4E9D9Dh, 02BD8C1476CAD6C6Ch
                    qword   0A462F59531C43131h, 0F3E8B98774CD7474h, 015F109E3F6FFF6F6h, 04C8C430A46054646h, 0A5452609AC8AACACh, 0B50F973C891E8989h, 0B42844A014501414h, 0BADF425BE1A3E1E1h
                    qword   0A62C4EB016581616h, 0F774D2CD3AE83A3Ah, 006D2D06F69B96969h, 041122D4809240909h, 0D7E0ADA770DD7070h, 06F7154D9B6E2B6B6h, 01EBDB7CED067D0D0h, 0D6C77E3BED93EDEDh
                    qword   0E285DB2ECC17CCCCh, 06884572A42154242h, 02C2DC2B4985A9898h, 0ED550E49A4AAA4A4h, 07550885D28A02828h, 086B831DA5C6D5C5Ch, 06BED3F93F8C7F8F8h, 0C211A44486228686h

; Same table but rotated by 1 byte
magictable1         qword   03078C018601818D8h, 046AF05238C232326h, 091F97EC63FC6C6B8h, 0CD6F13E887E8E8FBh, 013A14C87268787CBh, 06D62A9B8DAB8B811h, 00205080104010109h, 09E6E424F214F4F0Dh
                    qword   06CEEAD36D836369Bh, 0510459A6A2A6A6FFh, 0B9BDDED26FD2D20Ch, 0F706FBF5F3F5F50Eh, 0F280EF79F9797996h, 0DECE5F6FA16F6F30h, 03FEFFC917E91916Dh, 0A407AA52555252F8h
                    qword   0C0FD27609D606047h, 0657689BCCABCBC35h, 02BCDAC9B569B9B37h, 0018C048E028E8E8Ah, 05B1571A3B6A3A3D2h, 0183C600C300C0C6Ch, 0F68AFF7BF17B7B84h, 06AE1B535D4353580h
                    qword   03A69E81D741D1DF5h, 0DD4753E0A7E0E0B3h, 0B3ACF6D77BD7D721h, 099ED5EC22FC2C29Ch, 05C966D2EB82E2E43h, 0967A624B314B4B29h, 0E121A3FEDFFEFE5Dh, 0AE168257415757D5h
                    qword   02A41A815541515BDh, 0EEB69F77C17777E8h, 06EEBA537DC373792h, 0D7567BE5B3E5E59Eh, 023D98C9F469F9F13h, 0FD17D3F0E7F0F023h, 0947F6A4A354A4A20h, 0A9959EDA4FDADA44h
                    qword   0B025FA587D5858A2h, 08FCA06C903C9C9CFh, 0528D5529A429297Ch, 01422500A280A0A5Ah, 07F4FE1B1FEB1B150h, 05D1A69A0BAA0A0C9h, 0D6DA7F6BB16B6B14h, 017AB5C852E8585D9h
                    qword   0677381BDCEBDBD3Ch, 0BA34D25D695D5D8Fh, 02050801040101090h, 0F503F3F4F7F4F407h, 08BC016CB0BCBCBDDh, 07CC6ED3EF83E3ED3h, 00A1128051405052Dh, 0CEE61F6781676778h
                    qword   0D55373E4B7E4E497h, 04EBB25279C272702h, 08258324119414173h, 00B9D2C8B168B8BA7h, 0530151A7A6A7A7F6h, 0FA94CF7DE97D7DB2h, 037FBDC956E959549h, 0AD9F8ED847D8D856h
                    qword   0EB308BFBCBFBFB70h, 0C17123EE9FEEEECDh, 0F891C77CED7C7CBBh, 0CCE3176685666671h, 0A78EA6DD53DDDD7Bh, 02E4BB8175C1717AFh, 08E46024701474745h, 021DC849E429E9E1Ah
                    qword   089C51ECA0FCACAD4h, 05A99752DB42D2D58h, 0637991BFC6BFBF2Eh, 00E1B38071C07073Fh, 0472301AD8EADADACh, 0B42FEA5A755A5AB0h, 01BB56C83368383EFh, 066FF8533CC3333B6h
                    qword   0C6F23F639163635Ch, 0040A100208020212h, 0493839AA92AAAA93h, 0E2A8AF71D97171DEh, 08DCF0EC807C8C8C6h, 0327DC819641919D1h, 0927072493949493Bh, 0AF9A86D943D9D95Fh
                    qword   0F91DC3F2EFF2F231h, 0DB484BE3ABE3E3A8h, 0B62AE25B715B5BB9h, 00D9234881A8888BCh, 029C8A49A529A9A3Eh, 04CBE2D269826260Bh, 064FA8D32C83232BFh, 07D4AE9B0FAB0B059h
                    qword   0CF6A1BE983E9E9F2h, 01E33780F3C0F0F77h, 0B7A6E6D573D5D533h, 01DBA74803A8080F4h, 0617C99BEC2BEBE27h, 087DE26CD13CDCDEBh, 068E4BD34D0343489h, 090757A483D484832h
                    qword   0E324ABFFDBFFFF54h, 0F48FF77AF57A7A8Dh, 03DEAF4907A909064h, 0BE3EC25F615F5F9Dh, 040A01D208020203Dh, 0D0D56768BD68680Fh, 03472D01A681A1ACAh, 0412C19AE82AEAEB7h
                    qword   0755EC9B4EAB4B47Dh, 0A8199A544D5454CEh, 03BE5EC937693937Fh, 044AA0D228822222Fh, 0C8E907648D646463h, 0FF12DBF1E3F1F12Ah, 0E6A2BF73D17373CCh, 0245A901248121282h
                    qword   0805D3A401D40407Ah, 01028400820080848h, 09BE856C32BC3C395h, 0C57B33EC97ECECDFh, 0AB9096DB4BDBDB4Dh, 05F1F61A1BEA1A1C0h, 007831C8D0E8D8D91h, 07AC9F53DF43D3DC8h
                    qword   033F1CC976697975Bh, 00000000000000000h, 083D436CF1BCFCFF9h, 05687452BAC2B2B6Eh, 0ECB39776C57676E1h, 019B06482328282E6h, 0B1A9FED67FD6D628h, 03677D81B6C1B1BC3h
                    qword   0775BC1B5EEB5B574h, 0432911AF86AFAFBEh, 0D4DF776AB56A6A1Dh, 0A00DBA505D5050EAh, 08A4C124509454557h, 0FB18CBF3EBF3F338h, 060F09D30C03030ADh, 0C3742BEF9BEFEFC4h
                    qword   07EC3E53FFC3F3FDAh, 0AA1C9255495555C7h, 0591079A2B2A2A2DBh, 0C96503EA8FEAEAE9h, 0CAEC0F658965656Ah, 06968B9BAD2BABA03h, 05E93652FBC2F2F4Ah, 09DE74EC027C0C08Eh
                    qword   0A181BEDE5FDEDE60h, 0386CE01C701C1CFCh, 0E72EBBFDD3FDFD46h, 09A64524D294D4D1Fh, 039E0E49272929276h, 0EABC8F75C97575FAh, 00C1E300618060636h, 00998248A128A8AAEh
                    qword   07940F9B2F2B2B24Bh, 0D15963E6BFE6E685h, 01C36700E380E0E7Eh, 03E63F81F7C1F1FE7h, 0C4F7376295626255h, 0B5A3EED477D4D43Ah, 04D3229A89AA8A881h, 031F4C49662969652h
                    qword   0EF3A9BF9C3F9F962h, 097F666C533C5C5A3h, 04AB1352594252510h, 0B220F259795959ABh, 015AE54842A8484D0h, 0E4A7B772D57272C5h, 072DDD539E43939ECh, 098615A4C2D4C4C16h
                    qword   0BC3BCA5E655E5E94h, 0F085E778FD78789Fh, 070D8DD38E03838E5h, 00586148C0A8C8C98h, 0BFB2C6D163D1D117h, 0570B41A5AEA5A5E4h, 0D94D43E2AFE2E2A1h, 0C2F82F619961614Eh
                    qword   07B45F1B3F6B3B342h, 042A5152184212134h, 025D6949C4A9C9C08h, 03C66F01E781E1EEEh, 08652224311434361h, 093FC76C73BC7C7B1h, 0E52BB3FCD7FCFC4Fh, 00814200410040424h
                    qword   0A208B251595151E3h, 02FC7BC995E999925h, 0DAC44F6DA96D6D22h, 01A39680D340D0D65h, 0E93583FACFFAFA79h, 0A384B6DF5BDFDF69h, 0FC9BD77EE57E7EA9h, 048B43D2490242419h
                    qword   076D7C53BEC3B3BFEh, 04B3D31AB96ABAB9Ah, 081D13ECE1FCECEF0h, 02255881144111199h, 003890C8F068F8F83h, 09C6B4A4E254E4E04h, 07351D1B7E6B7B766h, 0CB600BEB8BEBEBE0h
                    qword   078CCFD3CF03C3CC1h, 01FBF7C813E8181FDh, 035FED4946A949440h, 0F30CEBF7FBF7F71Ch, 06F67A1B9DEB9B918h, 0265F98134C13138Bh, 0589C7D2CB02C2C51h, 0BBB8D6D36BD3D305h
                    qword   0D35C6BE7BBE7E78Ch, 0DCCB576EA56E6E39h, 095F36EC437C4C4AAh, 0060F18030C03031Bh, 0AC138A56455656DCh, 088491A440D44445Eh, 0FE9EDF7FE17F7FA0h, 04F3721A99EA9A988h
                    qword   054824D2AA82A2A67h, 06B6DB1BBD6BBBB0Ah, 09FE246C123C1C187h, 0A602A253515353F1h, 0A58BAEDC57DCDC72h, 01627580B2C0B0B53h, 027D39C9D4E9D9D01h, 0D8C1476CAD6C6C2Bh
                    qword   062F59531C43131A4h, 0E8B98774CD7474F3h, 0F109E3F6FFF6F615h, 08C430A460546464Ch, 0452609AC8AACACA5h, 00F973C891E8989B5h, 02844A014501414B4h, 0DF425BE1A3E1E1BAh
                    qword   02C4EB016581616A6h, 074D2CD3AE83A3AF7h, 0D2D06F69B9696906h, 0122D480924090941h, 0E0ADA770DD7070D7h, 07154D9B6E2B6B66Fh, 0BDB7CED067D0D01Eh, 0C77E3BED93EDEDD6h
                    qword   085DB2ECC17CCCCE2h, 084572A4215424268h, 02DC2B4985A98982Ch, 0550E49A4AAA4A4EDh, 050885D28A0282875h, 0B831DA5C6D5C5C86h, 0ED3F93F8C7F8F86Bh, 011A44486228686C2h

DOBYTEPAIRFIRST     macro               inreg, offset, outreg0, outreg1
                    pextrw              eax, inreg, offset
                    movzx               ebx, ah
                    and                 eax, 0FFh
                    lea                 rdi, magictable0
                    mov                 outreg0, [rdi + rax*8]
                    lea                 rdi, magictable1
                    mov                 outreg1, [rdi + rbx*8]
                    endm

DOBYTEPAIR          macro               inreg, offset, outreg0, outreg1
                    pextrw              eax, inreg, offset
                    movzx               ebx, ah
                    and                 eax, 0FFh
                    lea                 rdi, magictable0
                    xor                 outreg0, [rdi + rax*8]
                    lea                 rdi, magictable1
                    xor                 outreg1, [rdi + rbx*8]
                    endm

ROTATERIGHT         macro
                    ror                  r8, 16
                    ror                  r9, 16
                    ror                 r10, 16
                    ror                 r11, 16
                    ror                 r12, 16
                    ror                 r13, 16
                    ror                 r14, 16
                    ror                 r15, 16
                    endm

XORSTATETOBLOCK     macro                                           ; Used for sigma (AddRoundKey)
                    xorpd               xmm4, xmm0
                    xorpd               xmm5, xmm1
                    xorpd               xmm6, xmm2
                    xorpd               xmm7, xmm3
                    endm

                    .code
                    ; void whirlpool_compress(const uint64_t block[8], uint8_t state[64])
                    public              whirlpool_compress
whirlpool_compress  proc
                    ; Save nonvolatile registers, allocate scratch space
                    push                rbx
                    push                rdi
                    push                rsi
                    push                r12
                    push                r13
                    push                r14
                    push                r15
                    sub                 rsp, 30h
                    movdqu              [rsp + 10h], xmm6
                    movdqu              [rsp + 20h], xmm7

                    ; Load state into XMM
                    movdqu              xmm0, [rdx]
                    movdqu              xmm1, [rdx + 16]
                    movdqu              xmm2, [rdx + 32]
                    movdqu              xmm3, [rdx + 48]

                    ; Load block into XMM
                    movdqu              xmm4, [rcx]
                    movdqu              xmm5, [rcx + 16]
                    movdqu              xmm6, [rcx + 32]
                    movdqu              xmm7, [rcx + 48]

                    ; XOR block with state
                    XORSTATETOBLOCK

                    ; 10 rounds of hashing
                    mov                 esi, 0

                    ; Process all 64 state bytes
looptop:            DOBYTEPAIRFIRST     xmm0, 0, r8 , r9
                    DOBYTEPAIRFIRST     xmm1, 0, r10, r11
                    DOBYTEPAIRFIRST     xmm2, 0, r12, r13
                    DOBYTEPAIRFIRST     xmm3, 0, r14, r15
                    DOBYTEPAIR          xmm0, 4, r9 , r10
                    DOBYTEPAIR          xmm1, 4, r11, r12
                    DOBYTEPAIR          xmm2, 4, r13, r14
                    DOBYTEPAIR          xmm3, 4, r15, r8
                    ROTATERIGHT
                    DOBYTEPAIR          xmm3, 1, r8 , r9
                    DOBYTEPAIR          xmm0, 1, r10, r11
                    DOBYTEPAIR          xmm1, 1, r12, r13
                    DOBYTEPAIR          xmm2, 1, r14, r15
                    DOBYTEPAIR          xmm3, 5, r9 , r10
                    DOBYTEPAIR          xmm0, 5, r11, r12
                    DOBYTEPAIR          xmm1, 5, r13, r14
                    DOBYTEPAIR          xmm2, 5, r15, r8
                    ROTATERIGHT
                    DOBYTEPAIR          xmm2, 2, r8 , r9
                    DOBYTEPAIR          xmm3, 2, r10, r11
                    DOBYTEPAIR          xmm0, 2, r12, r13
                    DOBYTEPAIR          xmm1, 2, r14, r15
                    DOBYTEPAIR          xmm2, 6, r9 , r10
                    DOBYTEPAIR          xmm3, 6, r11, r12
                    DOBYTEPAIR          xmm0, 6, r13, r14
                    DOBYTEPAIR          xmm1, 6, r15, r8
                    ROTATERIGHT
                    DOBYTEPAIR          xmm1, 3, r8 , r9
                    DOBYTEPAIR          xmm2, 3, r10, r11
                    DOBYTEPAIR          xmm3, 3, r12, r13
                    DOBYTEPAIR          xmm0, 3, r14, r15
                    DOBYTEPAIR          xmm1, 7, r9 , r10
                    DOBYTEPAIR          xmm2, 7, r11, r12
                    DOBYTEPAIR          xmm3, 7, r13, r14
                    DOBYTEPAIR          xmm0, 7, r15, r8
                    ROTATERIGHT
                    lea                 rax, roundconstants
                    xor                 r8, [rax + rsi*8]           ; Add round constant

                    ; Copy state back to XMM
                    mov                 [rsp], r15
                    movq                xmm0, r8
                    movq                xmm1, r9
                    shufpd              xmm0, xmm1, 0
                    movq                xmm1, r10
                    movq                xmm2, r11
                    shufpd              xmm1, xmm2, 0
                    movq                xmm2, r12
                    movq                xmm3, r13
                    shufpd              xmm2, xmm3, 0
                    movq                xmm3, r14
                    movhps              xmm3, qword ptr [rsp]
    
                    ; Process all 64 block bytes
                    DOBYTEPAIRFIRST     xmm4, 0, r8 , r9
                    DOBYTEPAIRFIRST     xmm5, 0, r10, r11
                    DOBYTEPAIRFIRST     xmm6, 0, r12, r13
                    DOBYTEPAIRFIRST     xmm7, 0, r14, r15
                    DOBYTEPAIR          xmm4, 4, r9 , r10
                    DOBYTEPAIR          xmm5, 4, r11, r12
                    DOBYTEPAIR          xmm6, 4, r13, r14
                    DOBYTEPAIR          xmm7, 4, r15, r8
                    ROTATERIGHT
                    DOBYTEPAIR          xmm7, 1, r8 , r9
                    DOBYTEPAIR          xmm4, 1, r10, r11
                    DOBYTEPAIR          xmm5, 1, r12, r13
                    DOBYTEPAIR          xmm6, 1, r14, r15
                    DOBYTEPAIR          xmm7, 5, r9 , r10
                    DOBYTEPAIR          xmm4, 5, r11, r12
                    DOBYTEPAIR          xmm5, 5, r13, r14
                    DOBYTEPAIR          xmm6, 5, r15, r8
                    ROTATERIGHT
                    DOBYTEPAIR          xmm6, 2, r8 , r9
                    DOBYTEPAIR          xmm7, 2, r10, r11
                    DOBYTEPAIR          xmm4, 2, r12, r13
                    DOBYTEPAIR          xmm5, 2, r14, r15
                    DOBYTEPAIR          xmm6, 6, r9 , r10
                    DOBYTEPAIR          xmm7, 6, r11, r12
                    DOBYTEPAIR          xmm4, 6, r13, r14
                    DOBYTEPAIR          xmm5, 6, r15, r8
                    ROTATERIGHT
                    DOBYTEPAIR          xmm5, 3, r8 , r9
                    DOBYTEPAIR          xmm6, 3, r10, r11
                    DOBYTEPAIR          xmm7, 3, r12, r13
                    DOBYTEPAIR          xmm4, 3, r14, r15
                    DOBYTEPAIR          xmm5, 7, r9 , r10
                    DOBYTEPAIR          xmm6, 7, r11, r12
                    DOBYTEPAIR          xmm7, 7, r13, r14
                    DOBYTEPAIR          xmm4, 7, r15, r8
                    ROTATERIGHT

                    ; Copy block back to XMM
                    mov                 [rsp], r15
                    movq                xmm4, r8
                    movq                xmm5, r9
                    shufpd              xmm4, xmm5, 0
                    movq                xmm5, r10
                    movq                xmm6, r11
                    shufpd              xmm5, xmm6, 0
                    movq                xmm6, r12
                    movq                xmm7, r13
                    shufpd              xmm6, xmm7, 0
                    movq                xmm7, r14
                    movhps              xmm7, qword ptr [rsp]

                    ; Add state to block
                    XORSTATETOBLOCK

                    ; Loop back */
                    inc                 esi
                    cmp                 esi, NUM_ROUNDS
                    jne                 looptop

                    ; XOR old state (in memory) with old block (in memory) and new block (in XMM)
                    movdqu              xmm0, [rdx]                 ; Load old state
                    movdqu              xmm1, [rdx + 16]
                    movdqu              xmm2, [rdx + 32]
                    movdqu              xmm3, [rdx + 48]
                    XORSTATETOBLOCK                                 ; XOR into new block
                    movdqu              xmm0, [rcx]                 ; Load old block
                    movdqu              xmm1, [rcx + 16]
                    movdqu              xmm2, [rcx + 32]
                    movdqu              xmm3, [rcx + 48]
                    XORSTATETOBLOCK                                 ; XOR into new block
                    movdqu              [rdx]     , xmm4            ; Store new state
                    movdqu              [rdx + 16], xmm5
                    movdqu              [rdx + 32], xmm6
                    movdqu              [rdx + 48], xmm7

                    ; Restore nonvolatile registers
                    movdqu              xmm7, [rsp + 20h]
                    movdqu              xmm6, [rsp + 10h]
                    add                 rsp, 30h
                    pop                 r15
                    pop                 r14
                    pop                 r13
                    pop                 r12
                    pop                 rsi
                    pop                 rdi
                    pop                 rbx
                    ret
whirlpool_compress  endp
                    end
