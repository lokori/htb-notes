s1 = "HackTheBox"

#.rodata:0000000000001BF2 unk_1BF2        db  0Eh                 ; DATA XREF: darkarmy+E
#.rodata:0000000000001BF3                 db  14h
#.rodata:0000000000001BF4                 db  0Dh
#.rodata:0000000000001BF5                 db  38h ; 8
#.rodata:0000000000001BF6                 db  3Bh ; ;
#.rodata:0000000000001BF7                 db  0Bh
#.rodata:0000000000001BF8                 db  0Ch
#.rodata:0000000000001BF9                 db  27h ; '
#.rodata:0000000000001BFA                 db  1Bh
#.rodata:0000000000001BFB                 db    1
#.rodata:0000000000001BFC                 db    0


s2 = '\x0e\x14\x0d\x38\x3b\x0b\x0c\x27\x1b\x01\x00'

pas=''
for i in range(0,10):
  pas = pas +  chr(ord(s1[i]) ^ ord(s2[i]))
print(pas)

