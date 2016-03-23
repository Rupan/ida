/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *      Hitchi H8
 *
 */

#include "h8.hpp"

//lint -estring(958,member) padding is required

//--------------------------------------------------------------------------
struct map_t
{
  proctype_t proc;
  nameNum itype;
  ushort op1;
  ushort op2;
};

#define MAP2         nameNum(H8_last + 1)
#define MAP3         nameNum(H8_last + 2)
#define MAP4         nameNum(H8_last + 3)
#define MAP014       nameNum(H8_last + 4)
#define EXIT_40      nameNum(H8_last + 5)
#define EXIT_54      nameNum(H8_last + 6)
#define EXIT_56      nameNum(H8_last + 7)
#define EXIT_59      nameNum(H8_last + 8)
#define EXIT_5D      nameNum(H8_last + 9)
#define EXIT_7B      nameNum(H8_last + 10)

static const ushort OPTYPE = 0x7F;
static const ushort i3       =  1; // zero bit + immediate 3 bits in high nibble
static const ushort i8       =  2; // immediate 8 bits
static const ushort i16      =  3; // immediate 16 bits
static const ushort i32      =  4; // immediate 32 bits
static const ushort rCCR     =  5; // CCR
static const ushort rEXR     =  6; // EXR
static const ushort rLB      =  7; // register number in low nibble  (r0l..r7h)
static const ushort rHB      =  8; // register number in high nibble (r0l..r7h)
static const ushort rLW      =  9; // register number in low nibble  (r0..e7)
static const ushort rHW      = 10; // register number in high nibble (r0..e7)
static const ushort rLL0     = 11; // register number in low nibble
                                  // (er0..er7) high bit is zero
static const ushort rHL0     = 12; // register number in high nibble
                                  // (er0..er7) high bit is zero
static const ushort rLL1     = 13; // register number in low nibble
                                  // (er0..er7) high bit is one
static const ushort rHL1     = 14; // register number in high nibble
                                  // (er0..er7) high bit is one
static const ushort C1       = 15; // constant #1
static const ushort C2       = 16; // constant #2
static const ushort C4       = 17; // constant #4
static const ushort savedHL0 = 18; // same as rHL0 but uses code3
static const ushort savedAA  = 19; // absolute address in code3
static const ushort j8       = 20; // branch displacement 8 bit
static const ushort j16      = 21; // branch displacement 16 bit
static const ushort atHL     = 22; // @ERx
static const ushort aa8      = 23; // 8bit address
static const ushort aa16     = 24; // 16bit address
static const ushort aa24     = 25; // 24bit address
static const ushort aa32     = 26; // 32bit address
static const ushort rMACH    = 27; // MACH
static const ushort rMACL    = 28; // MACL
static const ushort d16      = 29; // @(d:16, ERs)
static const ushort ai8      = 30; // @@a8
static const ushort rV0      = 31; // 16bit or 32bit register depending
                                   // on the processor mode
static const ushort C8       = 32; // constant #8
static const ushort rVBR     = 33; // VBR
static const ushort rSBR     = 34; // SBR
static const ushort i4L      = 35; // immediate 4 bits in low nibble
static const ushort i4H      = 36; // immediate 4 bits in high nibble
static const ushort rL       = 37; // register number in low  nibble (depends of aux_pref)
static const ushort rH       = 38; // register number in high nibble (depends of aux_pref)
static const ushort Cxh      = 39; // fake imm operand, hidden

static const ushort NEXT     = 0x0080;  // read next byte

static const ushort CMD_SIZE = 0x0F00;
static const ushort B        = 0x0100;  // .b
static const ushort W        = 0x0200;  // .w
static const ushort L        = 0x0400;  // .l
static const ushort V        = 0x0800;  // .w or .l

static const ushort zL       = 0x1000; // low  nibble should be zero
static const ushort zH       = 0x2000; // high nibble should be zero
static const ushort MANUAL   = 0x4000; // manual processing
static const ushort X        = 0x8000; // no explicit postfix


//--------------------------------------------------------------------------
static const map_t map[256] =
{
  { P300,       H8_nop,         NEXT|zL|zH,     0,               }, // 00
  { P300,       MAP2,           0,              0,               }, // 01
  { P300,       MAP2,           0,              0,               }, // 02
  { P300,       MAP2,           0,              0,               }, // 03
  { P300,       H8_orc,         i8,             rCCR,            }, // 04
  { P300,       H8_xorc,        i8,             rCCR,            }, // 05
  { P300,       H8_andc,        i8,             rCCR,            }, // 06
  { P300,       H8_ldc,         B | i8,         rCCR,            }, // 07
  { P300,       H8_add,         B | NEXT | rHB, rLB,             }, // 08
  { P300,       H8_add,         W | NEXT | rHW, rLW,             }, // 09
  { P300,       MAP2,           0,              0,               }, // 0A
  { P300,       MAP2,           0,              0,               }, // 0B
  { P300,       H8_mov,         B | NEXT | rHB, rLB,             }, // 0C
  { P300,       H8_mov,         W | NEXT | rHW, rLW,             }, // 0D
  { P300,       H8_addx,        NEXT | rHB,     rLB,             }, // 0E
  { P300,       MAP2,           0,              0,               }, // 0F

  { P300,       MAP2,           0,              0,               }, // 10
  { P300,       MAP2,           0,              0,               }, // 11
  { P300,       MAP2,           0,              0,               }, // 12
  { P300,       MAP2,           0,              0,               }, // 13
  { P300,       H8_or,          B | NEXT | rHB, rLB              }, // 14
  { P300,       H8_xor,         B | NEXT | rHB, rLB              }, // 15
  { P300,       H8_and,         B | NEXT | rHB, rLB              }, // 16
  { P300,       MAP2,           0,              0,               }, // 17
  { P300,       H8_sub,         B | NEXT | rHB, rLB              }, // 18
  { P300,       H8_sub,         W | NEXT | rHW, rLW,             }, // 19
  { P300,       MAP2,           0,              0,               }, // 1A
  { P300,       MAP2,           0,              0,               }, // 1B
  { P300,       H8_cmp,         B | NEXT | rHB, rLB              }, // 1C
  { P300,       H8_cmp,         W | NEXT | rHW, rLW,             }, // 1D
  { P300,       H8_subx,        NEXT | rHB,     rLB,             }, // 1E
  { P300,       MAP2,           0,              0,               }, // 1F

  { P300,       H8_mov,         B | aa8,        rLB,             }, // 20
  { P300,       H8_mov,         B | aa8,        rLB,             }, // 21
  { P300,       H8_mov,         B | aa8,        rLB,             }, // 22
  { P300,       H8_mov,         B | aa8,        rLB,             }, // 23
  { P300,       H8_mov,         B | aa8,        rLB,             }, // 24
  { P300,       H8_mov,         B | aa8,        rLB,             }, // 25
  { P300,       H8_mov,         B | aa8,        rLB,             }, // 26
  { P300,       H8_mov,         B | aa8,        rLB,             }, // 27
  { P300,       H8_mov,         B | aa8,        rLB,             }, // 28
  { P300,       H8_mov,         B | aa8,        rLB,             }, // 29
  { P300,       H8_mov,         B | aa8,        rLB,             }, // 2A
  { P300,       H8_mov,         B | aa8,        rLB,             }, // 2B
  { P300,       H8_mov,         B | aa8,        rLB,             }, // 2C
  { P300,       H8_mov,         B | aa8,        rLB,             }, // 2D
  { P300,       H8_mov,         B | aa8,        rLB,             }, // 2E
  { P300,       H8_mov,         B | aa8,        rLB,             }, // 2F

  { P300,       H8_mov,         B | rLB,        B | aa8,         }, // 30
  { P300,       H8_mov,         B | rLB,        B | aa8,         }, // 31
  { P300,       H8_mov,         B | rLB,        B | aa8,         }, // 32
  { P300,       H8_mov,         B | rLB,        B | aa8,         }, // 33
  { P300,       H8_mov,         B | rLB,        B | aa8,         }, // 34
  { P300,       H8_mov,         B | rLB,        B | aa8,         }, // 35
  { P300,       H8_mov,         B | rLB,        B | aa8,         }, // 36
  { P300,       H8_mov,         B | rLB,        B | aa8,         }, // 37
  { P300,       H8_mov,         B | rLB,        B | aa8,         }, // 38
  { P300,       H8_mov,         B | rLB,        B | aa8,         }, // 39
  { P300,       H8_mov,         B | rLB,        B | aa8,         }, // 3A
  { P300,       H8_mov,         B | rLB,        B | aa8,         }, // 3B
  { P300,       H8_mov,         B | rLB,        B | aa8,         }, // 3C
  { P300,       H8_mov,         B | rLB,        B | aa8,         }, // 3D
  { P300,       H8_mov,         B | rLB,        B | aa8,         }, // 3E
  { P300,       H8_mov,         B | rLB,        B | aa8,         }, // 3F

  { P300,       EXIT_40,         0,             0,               }, // 40
  { P300,       H8_brn,         j8,             0,               }, // 41
  { P300,       H8_bhi,         j8,             0,               }, // 42
  { P300,       H8_bls,         j8,             0,               }, // 43
  { P300,       H8_bcc,         j8,             0,               }, // 44
  { P300,       H8_bcs,         j8,             0,               }, // 45
  { P300,       H8_bne,         j8,             0,               }, // 46
  { P300,       H8_beq,         j8,             0,               }, // 47
  { P300,       H8_bvc,         j8,             0,               }, // 48
  { P300,       H8_bvs,         j8,             0,               }, // 49
  { P300,       H8_bpl,         j8,             0,               }, // 4A
  { P300,       H8_bmi,         j8,             0,               }, // 4B
  { P300,       H8_bge,         j8,             0,               }, // 4C
  { P300,       H8_blt,         j8,             0,               }, // 4D
  { P300,       H8_bgt,         j8,             0,               }, // 4E
  { P300,       H8_ble,         j8,             0,               }, // 4F

  { P300,       H8_mulxu,       B | NEXT | rHB, rLW,             }, // 50
  { P300,       H8_divxu,       B | NEXT | rHB, rLW,             }, // 51
  { P30A,       H8_mulxu,       W | NEXT | rHW, rLL0,            }, // 52
  { P30A,       H8_divxu,       W | NEXT | rHW, rLL0,            }, // 53
  { P300,       EXIT_54,        0,              0,               }, // 54
  { P300,       H8_bsr,         j8,             0,               }, // 55
  { P300,       EXIT_56,        0,              0,               }, // 56
  { P300,       H8_trapa,       MANUAL,         0,               }, // 57
  { P300,       MAP2,           0,              0,               }, // 58
  { P300,       EXIT_59,        0,              0,               }, // 59
  { P300,       H8_jmp,         aa24,           0,               }, // 5A
  { P300,       H8_jmp,         ai8,            0,               }, // 5B
  { P300,       H8_bsr,         NEXT|zL|zH| j16,0,               }, // 5C
  { P300,       EXIT_5D,        0,              0,               }, // 5D
  { P300,       H8_jsr,         aa24,           0,               }, // 5E
  { P300,       H8_jsr,         ai8,            0,               }, // 5F

  { P300,       H8_bset,        NEXT | rHB,     rLB,             }, // 60
  { P300,       H8_bnot,        NEXT | rHB,     rLB,             }, // 61
  { P300,       H8_bclr,        NEXT | rHB,     rLB,             }, // 62
  { P300,       H8_btst,        NEXT | rHB,     rLB,             }, // 63
  { P300,       H8_or,          W | NEXT | rHW, rLW              }, // 64
  { P300,       H8_xor,         W | NEXT | rHW, rLW              }, // 65
  { P300,       H8_and,         W | NEXT | rHW, rLW              }, // 66
  { P300,       H8_bst,         NEXT | i3,      rLB,             }, // 67
  { P300,       H8_mov,         B | NEXT | atHL,rLB,             }, // 68
  { P300,       H8_mov,         W | NEXT | atHL,rLW,             }, // 69
  { P300,       MAP2,           0,              0,               }, // 6A
  { P300,       H8_mov,         MANUAL,         0,               }, // 6B
  { P300,       H8_mov,         MANUAL,         0,               }, // 6C
  { P300,       H8_mov,         MANUAL,         0,               }, // 6D
  { P300,       H8_mov,         B | NEXT | d16, rLB,             }, // 6E
  { P300,       H8_mov,         W | NEXT | d16, rLW,             }, // 6F

  { P300,       H8_bset,        NEXT | i3,      rLB,             }, // 70
  { P300,       H8_bnot,        NEXT | i3,      rLB,             }, // 71
  { P300,       H8_bclr,        NEXT | i3,      rLB,             }, // 72
  { P300,       H8_btst,        NEXT | i3,      rLB,             }, // 73
  { P300,       H8_bor,         NEXT | i3,      rLB,             }, // 74
  { P300,       H8_bxor,        NEXT | i3,      rLB,             }, // 75
  { P300,       H8_band,        NEXT | i3,      rLB,             }, // 76
  { P300,       H8_bld,         NEXT | i3,      rLB,             }, // 77
  { P300,       H8_mov,         MANUAL,         0,               }, // 78
  { P300,       MAP2,           0,              0,               }, // 79
  { P300,       MAP2,           0,              0,               }, // 7A
  { P300,       EXIT_7B,        0,              0,               }, // 7B
  { P300,       MAP3,           0,              0,               }, // 7C
  { P300,       MAP3,           0,              0,               }, // 7D
  { P300,       MAP3,           0,              0,               }, // 7E
  { P300,       MAP3,           0,              0,               }, // 7F

  { P300,       H8_add,         B | i8,         rLB,             }, // 80
  { P300,       H8_add,         B | i8,         rLB,             }, // 81
  { P300,       H8_add,         B | i8,         rLB,             }, // 82
  { P300,       H8_add,         B | i8,         rLB,             }, // 83
  { P300,       H8_add,         B | i8,         rLB,             }, // 84
  { P300,       H8_add,         B | i8,         rLB,             }, // 85
  { P300,       H8_add,         B | i8,         rLB,             }, // 86
  { P300,       H8_add,         B | i8,         rLB,             }, // 87
  { P300,       H8_add,         B | i8,         rLB,             }, // 88
  { P300,       H8_add,         B | i8,         rLB,             }, // 89
  { P300,       H8_add,         B | i8,         rLB,             }, // 8A
  { P300,       H8_add,         B | i8,         rLB,             }, // 8B
  { P300,       H8_add,         B | i8,         rLB,             }, // 8C
  { P300,       H8_add,         B | i8,         rLB,             }, // 8D
  { P300,       H8_add,         B | i8,         rLB,             }, // 8E
  { P300,       H8_add,         B | i8,         rLB,             }, // 8F

  { P300,       H8_addx,        i8,             rLB,             }, // 90
  { P300,       H8_addx,        i8,             rLB,             }, // 91
  { P300,       H8_addx,        i8,             rLB,             }, // 92
  { P300,       H8_addx,        i8,             rLB,             }, // 93
  { P300,       H8_addx,        i8,             rLB,             }, // 94
  { P300,       H8_addx,        i8,             rLB,             }, // 95
  { P300,       H8_addx,        i8,             rLB,             }, // 96
  { P300,       H8_addx,        i8,             rLB,             }, // 97
  { P300,       H8_addx,        i8,             rLB,             }, // 98
  { P300,       H8_addx,        i8,             rLB,             }, // 99
  { P300,       H8_addx,        i8,             rLB,             }, // 9A
  { P300,       H8_addx,        i8,             rLB,             }, // 9B
  { P300,       H8_addx,        i8,             rLB,             }, // 9C
  { P300,       H8_addx,        i8,             rLB,             }, // 9D
  { P300,       H8_addx,        i8,             rLB,             }, // 9E
  { P300,       H8_addx,        i8,             rLB,             }, // 9F

  { P300,       H8_cmp,         B | i8,         rLB,             }, // A0
  { P300,       H8_cmp,         B | i8,         rLB,             }, // A1
  { P300,       H8_cmp,         B | i8,         rLB,             }, // A2
  { P300,       H8_cmp,         B | i8,         rLB,             }, // A3
  { P300,       H8_cmp,         B | i8,         rLB,             }, // A4
  { P300,       H8_cmp,         B | i8,         rLB,             }, // A5
  { P300,       H8_cmp,         B | i8,         rLB,             }, // A6
  { P300,       H8_cmp,         B | i8,         rLB,             }, // A7
  { P300,       H8_cmp,         B | i8,         rLB,             }, // A8
  { P300,       H8_cmp,         B | i8,         rLB,             }, // A9
  { P300,       H8_cmp,         B | i8,         rLB,             }, // AA
  { P300,       H8_cmp,         B | i8,         rLB,             }, // AB
  { P300,       H8_cmp,         B | i8,         rLB,             }, // AC
  { P300,       H8_cmp,         B | i8,         rLB,             }, // AD
  { P300,       H8_cmp,         B | i8,         rLB,             }, // AE
  { P300,       H8_cmp,         B | i8,         rLB,             }, // AF

  { P300,       H8_subx,        i8,             rLB,             }, // B0
  { P300,       H8_subx,        i8,             rLB,             }, // B1
  { P300,       H8_subx,        i8,             rLB,             }, // B2
  { P300,       H8_subx,        i8,             rLB,             }, // B3
  { P300,       H8_subx,        i8,             rLB,             }, // B4
  { P300,       H8_subx,        i8,             rLB,             }, // B5
  { P300,       H8_subx,        i8,             rLB,             }, // B6
  { P300,       H8_subx,        i8,             rLB,             }, // B7
  { P300,       H8_subx,        i8,             rLB,             }, // B8
  { P300,       H8_subx,        i8,             rLB,             }, // B9
  { P300,       H8_subx,        i8,             rLB,             }, // BA
  { P300,       H8_subx,        i8,             rLB,             }, // BB
  { P300,       H8_subx,        i8,             rLB,             }, // BC
  { P300,       H8_subx,        i8,             rLB,             }, // BD
  { P300,       H8_subx,        i8,             rLB,             }, // BE
  { P300,       H8_subx,        i8,             rLB,             }, // BF

  { P300,       H8_or,          B | i8,         rLB,             }, // C0
  { P300,       H8_or,          B | i8,         rLB,             }, // C1
  { P300,       H8_or,          B | i8,         rLB,             }, // C2
  { P300,       H8_or,          B | i8,         rLB,             }, // C3
  { P300,       H8_or,          B | i8,         rLB,             }, // C4
  { P300,       H8_or,          B | i8,         rLB,             }, // C5
  { P300,       H8_or,          B | i8,         rLB,             }, // C6
  { P300,       H8_or,          B | i8,         rLB,             }, // C7
  { P300,       H8_or,          B | i8,         rLB,             }, // C8
  { P300,       H8_or,          B | i8,         rLB,             }, // C9
  { P300,       H8_or,          B | i8,         rLB,             }, // CA
  { P300,       H8_or,          B | i8,         rLB,             }, // CB
  { P300,       H8_or,          B | i8,         rLB,             }, // CC
  { P300,       H8_or,          B | i8,         rLB,             }, // CD
  { P300,       H8_or,          B | i8,         rLB,             }, // CE
  { P300,       H8_or,          B | i8,         rLB,             }, // CF

  { P300,       H8_xor,         B | i8,         rLB,             }, // D0
  { P300,       H8_xor,         B | i8,         rLB,             }, // D1
  { P300,       H8_xor,         B | i8,         rLB,             }, // D2
  { P300,       H8_xor,         B | i8,         rLB,             }, // D3
  { P300,       H8_xor,         B | i8,         rLB,             }, // D4
  { P300,       H8_xor,         B | i8,         rLB,             }, // D5
  { P300,       H8_xor,         B | i8,         rLB,             }, // D6
  { P300,       H8_xor,         B | i8,         rLB,             }, // D7
  { P300,       H8_xor,         B | i8,         rLB,             }, // D8
  { P300,       H8_xor,         B | i8,         rLB,             }, // D9
  { P300,       H8_xor,         B | i8,         rLB,             }, // DA
  { P300,       H8_xor,         B | i8,         rLB,             }, // DB
  { P300,       H8_xor,         B | i8,         rLB,             }, // DC
  { P300,       H8_xor,         B | i8,         rLB,             }, // DD
  { P300,       H8_xor,         B | i8,         rLB,             }, // DE
  { P300,       H8_xor,         B | i8,         rLB,             }, // DF

  { P300,       H8_and,         B | i8,         rLB,             }, // E0
  { P300,       H8_and,         B | i8,         rLB,             }, // E1
  { P300,       H8_and,         B | i8,         rLB,             }, // E2
  { P300,       H8_and,         B | i8,         rLB,             }, // E3
  { P300,       H8_and,         B | i8,         rLB,             }, // E4
  { P300,       H8_and,         B | i8,         rLB,             }, // E5
  { P300,       H8_and,         B | i8,         rLB,             }, // E6
  { P300,       H8_and,         B | i8,         rLB,             }, // E7
  { P300,       H8_and,         B | i8,         rLB,             }, // E8
  { P300,       H8_and,         B | i8,         rLB,             }, // E9
  { P300,       H8_and,         B | i8,         rLB,             }, // EA
  { P300,       H8_and,         B | i8,         rLB,             }, // EB
  { P300,       H8_and,         B | i8,         rLB,             }, // EC
  { P300,       H8_and,         B | i8,         rLB,             }, // ED
  { P300,       H8_and,         B | i8,         rLB,             }, // EE
  { P300,       H8_and,         B | i8,         rLB,             }, // EF

  { P300,       H8_mov,         B | rLB,        B | i8,          }, // F0
  { P300,       H8_mov,         B | rLB,        B | i8,          }, // F1
  { P300,       H8_mov,         B | rLB,        B | i8,          }, // F2
  { P300,       H8_mov,         B | rLB,        B | i8,          }, // F3
  { P300,       H8_mov,         B | rLB,        B | i8,          }, // F4
  { P300,       H8_mov,         B | rLB,        B | i8,          }, // F5
  { P300,       H8_mov,         B | rLB,        B | i8,          }, // F6
  { P300,       H8_mov,         B | rLB,        B | i8,          }, // F7
  { P300,       H8_mov,         B | rLB,        B | i8,          }, // F8
  { P300,       H8_mov,         B | rLB,        B | i8,          }, // F9
  { P300,       H8_mov,         B | rLB,        B | i8,          }, // FA
  { P300,       H8_mov,         B | rLB,        B | i8,          }, // FB
  { P300,       H8_mov,         B | rLB,        B | i8,          }, // FC
  { P300,       H8_mov,         B | rLB,        B | i8,          }, // FD
  { P300,       H8_mov,         B | rLB,        B | i8,          }, // FE
  { P300,       H8_mov,         B | rLB,        B | i8,          }, // FF

};


//--------------------------------------------------------------------------
static const map_t map2_01[16] =
{
  { P300,       H8_mov,         MANUAL,         0,               }, // 01 0?
  { P300,       H8_ldm,         MANUAL,         0,               }, // 01 1?
  { P300,       H8_ldm,         MANUAL,         0,               }, // 01 2?
  { P300,       H8_ldm,         MANUAL,         0,               }, // 01 3?
  { P300,       MAP014,         0,              0,               }, // 01 4?
  { none,       H8_null,        0,              0,               }, // 01 5?
  { P2600,      H8_mac,         0,              0,               }, // 01 6?
  { none,       H8_null,        0,              0,               }, // 01 7?
  { P300,       H8_sleep,       zL,             0,               }, // 01 8?
  { none,       H8_null,        0,              0,               }, // 01 9?
  { P2600,      H8_clrmac,      zL,             0,               }, // 01 A?
  { none,       H8_null,        0,              0,               }, // 01 B?
  { P300,       MAP3,           0,              0,               }, // 01 C?
  { P300,       MAP3,           0,              0,               }, // 01 D?
  { P300,       H8_tas,         MANUAL,         0,               }, // 01 E?
  { P300,       MAP3,           0,              0,               }, // 01 F?
};

//--------------------------------------------------------------------------
static const map_t map2_02[16] =
{
  { P300,       H8_stc,         B | rCCR,       rLB,             }, // 02 0?
  { P300,       H8_stc,         B | rEXR,       rLB,             }, // 02 1?
  { P2600,      H8_stmac,       rMACH,          rLL0,            }, // 02 2?
  { P2600,      H8_stmac,       rMACL,          rLL0,            }, // 02 3?
  { none,       H8_null,        0,              0,               }, // 02 4?
  { none,       H8_null,        0,              0,               }, // 02 5?
  { PSX,        H8_stc,         L | rVBR,       rLL0,            }, // 02 6?
  { PSX,        H8_stc,         L | rSBR,       rLL0,            }, // 02 7?
  { none,       H8_null,        0,              0,               }, // 02 8?
  { none,       H8_null,        0,              0,               }, // 02 9?
  { none,       H8_null,        0,              0,               }, // 02 A?
  { none,       H8_null,        0,              0,               }, // 02 B?
  { none,       H8_null,        0,              0,               }, // 02 C?
  { none,       H8_null,        0,              0,               }, // 02 D?
  { none,       H8_null,        0,              0,               }, // 02 E?
  { none,       H8_null,        0,              0,               }, // 02 F?
};

//--------------------------------------------------------------------------
static const map_t map2_03[16] =
{
  { P300,       H8_ldc,         B | rLB,        rCCR,            }, // 03 0?
  { P300,       H8_ldc,         B | rLB,        rEXR,            }, // 03 1?
  { P2600,      H8_ldmac,       rLL0,           rMACH,           }, // 03 2?
  { P2600,      H8_ldmac,       rLL0,           rMACL,           }, // 03 3?
  { none,       H8_null,        0,              0,               }, // 03 4?
  { none,       H8_null,        0,              0,               }, // 03 5?
  { none,       H8_null,        0,              0,               }, // 03 6?
  { none,       H8_null,        0,              0,               }, // 03 7?
  { none,       H8_null,        0,              0,               }, // 03 8?
  { none,       H8_null,        0,              0,               }, // 03 9?
  { none,       H8_null,        0,              0,               }, // 03 A?
  { none,       H8_null,        0,              0,               }, // 03 B?
  { none,       H8_null,        0,              0,               }, // 03 C?
  { none,       H8_null,        0,              0,               }, // 03 D?
  { none,       H8_null,        0,              0,               }, // 03 E?
  { none,       H8_null,        0,              0,               }, // 03 F?
};

//--------------------------------------------------------------------------
static const map_t map2_0A[16] =
{
  { P300,       H8_inc,         B | Cxh,        rLB,             }, // 0A 0?
  { none,       H8_null,        0,              0,               }, // 0A 1?
  { none,       H8_null,        0,              0,               }, // 0A 2?
  { none,       H8_null,        0,              0,               }, // 0A 3?
  { none,       H8_null,        0,              0,               }, // 0A 4?
  { none,       H8_null,        0,              0,               }, // 0A 5?
  { none,       H8_null,        0,              0,               }, // 0A 6?
  { none,       H8_null,        0,              0,               }, // 0A 7?
  { P30A,       H8_add,         L | rHL1,       rLL0,            }, // 0A 8?
  { P30A,       H8_add,         L | rHL1,       rLL0,            }, // 0A 9?
  { P30A,       H8_add,         L | rHL1,       rLL0,            }, // 0A A?
  { P30A,       H8_add,         L | rHL1,       rLL0,            }, // 0A B?
  { P30A,       H8_add,         L | rHL1,       rLL0,            }, // 0A C?
  { P30A,       H8_add,         L | rHL1,       rLL0,            }, // 0A D?
  { P30A,       H8_add,         L | rHL1,       rLL0,            }, // 0A E?
  { P30A,       H8_add,         L | rHL1,       rLL0,            }, // 0A F?
};

//--------------------------------------------------------------------------
static const map_t map2_0B[16] =
{
  { P300,       H8_adds,        C1,             rV0,             }, // 0B 0?
  { none,       H8_null,        0,              0,               }, // 0B 1?
  { none,       H8_null,        0,              0,               }, // 0B 2?
  { none,       H8_null,        0,              0,               }, // 0B 3?
  { none,       H8_null,        0,              0,               }, // 0B 4?
  { P300,       H8_inc,         W | C1,         rLW,             }, // 0B 5?
  { none,       H8_null,        0,              0,               }, // 0B 6?
  { P30A,       H8_inc,         L | C1,         rLL0,            }, // 0B 7?
  { P300,       H8_adds,        C2,             rV0,             }, // 0B 8?
  { P30A,       H8_adds,        C4,             rLL0,            }, // 0B 9?
  { none,       H8_null,        0,              0,               }, // 0B A?
  { none,       H8_null,        0,              0,               }, // 0B B?
  { none,       H8_null,        0,              0,               }, // 0B C?
  { P300,       H8_inc,         W | C2,         rLW,             }, // 0B D?
  { none,       H8_null,        0,              0,               }, // 0B E?
  { P30A,       H8_inc,         L | C2,         rLL0,            }, // 0B F?
};

//--------------------------------------------------------------------------
static const map_t map2_0F[16] =
{
  { P300,       H8_daa,         rLB,            0,               }, // 0F 0?
  { none,       H8_null,        0,              0,               }, // 0F 1?
  { none,       H8_null,        0,              0,               }, // 0F 2?
  { none,       H8_null,        0,              0,               }, // 0F 3?
  { none,       H8_null,        0,              0,               }, // 0F 4?
  { none,       H8_null,        0,              0,               }, // 0F 5?
  { none,       H8_null,        0,              0,               }, // 0F 6?
  { none,       H8_null,        0,              0,               }, // 0F 7?
  { P30A,       H8_mov,         L | rLL0,       rHL1,            }, // 0F 8?
  { P30A,       H8_mov,         L | rLL0,       rHL1,            }, // 0F 9?
  { P30A,       H8_mov,         L | rLL0,       rHL1,            }, // 0F A?
  { P30A,       H8_mov,         L | rLL0,       rHL1,            }, // 0F B?
  { P30A,       H8_mov,         L | rLL0,       rHL1,            }, // 0F C?
  { P30A,       H8_mov,         L | rLL0,       rHL1,            }, // 0F D?
  { P30A,       H8_mov,         L | rLL0,       rHL1,            }, // 0F E?
  { P30A,       H8_mov,         L | rLL0,       rHL1,            }, // 0F F?
};

//--------------------------------------------------------------------------
static const map_t map2_10[16] =
{
  { P300,       H8_shll,        B | Cxh,        rLB,             }, // 10 0?
  { P300,       H8_shll,        W | Cxh,        rLW,             }, // 10 1?
  { PSX,        H8_shll,        W | C4,         rLW,             }, // 10 2?
  { P30A,       H8_shll,        L | Cxh,        rLL0             }, // 10 3?
  { P300,       H8_shll,        B | C2,         rLB,             }, // 10 4?
  { P300,       H8_shll,        W | C2,         rLW,             }, // 10 5?
  { PSX,        H8_shll,        W | C8,         rLW,             }, // 10 6?
  { P30A,       H8_shll,        L | C2,         rLL0,            }, // 10 7?
  { P300,       H8_shal,        B | Cxh,        rLB,             }, // 10 8?
  { P300,       H8_shal,        W | Cxh,        rLW,             }, // 10 9?
  { PSX,        H8_shll,        B | C4,         rLB,             }, // 10 A?
  { P30A,       H8_shal,        L | Cxh,        rLL0,            }, // 10 B?
  { P300,       H8_shal,        B | C2,         rLB,             }, // 10 C?
  { P300,       H8_shal,        W | C2,         rLW,             }, // 10 D?
  { none,       H8_null,        0,              0,               }, // 10 E?
  { P30A,       H8_shal,        L | C2,         rLL0,            }, // 10 F?
};

//--------------------------------------------------------------------------
static const map_t map2_11[16] =
{
  { P300,       H8_shlr,        B | Cxh,        rLB,             }, // 11 0?
  { P300,       H8_shlr,        W | Cxh,        rLW,             }, // 11 1?
  { PSX,        H8_shlr,        W | C4,         rLW,             }, // 11 2?
  { P30A,       H8_shlr,        L | Cxh,        rLL0             }, // 11 3?
  { P300,       H8_shlr,        B | C2,         rLB,             }, // 11 4?
  { P300,       H8_shlr,        W | C2,         rLW,             }, // 11 5?
  { PSX,        H8_shlr,        W | C8,         rLW,             }, // 11 6?
  { P30A,       H8_shlr,        L | C2,         rLL0,            }, // 11 7?
  { P300,       H8_shar,        B | Cxh,        rLB,             }, // 11 8?
  { P300,       H8_shar,        W | Cxh,        rLW,             }, // 11 9?
  { PSX,        H8_shlr,        B | C4,         rLB,             }, // 11 A?
  { P30A,       H8_shar,        L | Cxh,        rLL0,            }, // 11 B?
  { P300,       H8_shar,        B | C2,         rLB,             }, // 11 C?
  { P300,       H8_shar,        W | C2,         rLW,             }, // 11 D?
  { none,       H8_null,        0,              0,               }, // 11 E?
  { P30A,       H8_shar,        L | C2,         rLL0,            }, // 11 F?
};

//--------------------------------------------------------------------------
static const map_t map2_12[16] =
{
  { P300,       H8_rotxl,       B | Cxh,        rLB,             }, // 12 0?
  { P300,       H8_rotxl,       W | Cxh,        rLW,             }, // 12 1?
  { none,       H8_null,        0,              0,               }, // 12 2?
  { P30A,       H8_rotxl,       L | Cxh,        rLL0,            }, // 12 3?
  { P300,       H8_rotxl,       B | C2,         rLB,             }, // 12 4?
  { P300,       H8_rotxl,       W | C2,         rLW,             }, // 12 5?
  { none,       H8_null,        0,              0,               }, // 12 6?
  { P30A,       H8_rotxl,       L | C2,         rLL0,            }, // 12 7?
  { P300,       H8_rotl,        B | Cxh,        rLB,             }, // 12 8?
  { P300,       H8_rotl,        W | Cxh,        rLW,             }, // 12 9?
  { none,       H8_null,        0,              0,               }, // 12 A?
  { P30A,       H8_rotl,        L | Cxh,        rLL0,            }, // 12 B?
  { P300,       H8_rotl,        B | C2,         rLB,             }, // 12 C?
  { P300,       H8_rotl,        W | C2,         rLW,             }, // 12 D?
  { none,       H8_null,        0,              0,               }, // 12 E?
  { P30A,       H8_rotl,        L | C2,         rLL0,            }, // 12 F?
};

//--------------------------------------------------------------------------
static const map_t map2_13[16] =
{
  { P300,       H8_rotxr,       B | Cxh,        rLB,             }, // 13 0?
  { P300,       H8_rotxr,       W | Cxh,        rLW,             }, // 13 1?
  { none,       H8_null,        0,              0,               }, // 13 2?
  { P30A,       H8_rotxr,       L | Cxh,        rLL0,            }, // 13 3?
  { P300,       H8_rotxr,       B | C2,         rLB,             }, // 13 4?
  { P300,       H8_rotxr,       W | C2,         rLW,             }, // 13 5?
  { none,       H8_null,        0,              0,               }, // 13 6?
  { P30A,       H8_rotxr,       L | C2,         rLL0,            }, // 13 7?
  { P300,       H8_rotr,        B | Cxh,        rLB,             }, // 13 8?
  { P300,       H8_rotr,        W | Cxh,        rLW,             }, // 13 9?
  { none,       H8_null,        0,              0,               }, // 13 A?
  { P30A,       H8_rotr,        L | Cxh,        rLL0,            }, // 13 B?
  { P300,       H8_rotr,        B | C2,         rLB,             }, // 13 C?
  { P300,       H8_rotr,        W | C2,         rLW,             }, // 13 D?
  { none,       H8_null,        0,              0,               }, // 13 E?
  { P30A,       H8_rotr,        L | C2,         rLL0,            }, // 13 F?
};

//--------------------------------------------------------------------------
static const map_t map2_17[16] =
{
  { P300,       H8_not,         B | rLB,        0,               }, // 17 0?
  { P300,       H8_not,         W | rLW,        0,               }, // 17 1?
  { none,       H8_null,        0,              0,               }, // 17 2?
  { P30A,       H8_not,         L | rLL0,       0,               }, // 17 3?
  { none,       H8_null,        0,              0,               }, // 17 4?
  { P300,       H8_extu,        W | Cxh,        rLW,             }, // 17 5?
  { PSX,        H8_extu,        L | C2,         rLL0,            }, // 17 6?
  { P30A,       H8_extu,        L | Cxh,        rLL0,            }, // 17 7?
  { P300,       H8_neg,         B | rLB,        0,               }, // 17 8?
  { P300,       H8_neg,         W | rLW,        0,               }, // 17 9?
  { none,       H8_null,        0,              0,               }, // 17 A?
  { P30A,       H8_neg,         L | rLL0,       0,               }, // 17 B?
  { none,       H8_null,        0,              0,               }, // 17 C?
  { P300,       H8_exts,        W | Cxh,        rLW,             }, // 17 D?
  { PSX,        H8_exts,        L | C2,         rLL0,            }, // 17 E?
  { P30A,       H8_exts,        L | Cxh,        rLL0,            }, // 17 F?
};

//--------------------------------------------------------------------------
static const map_t map2_1A[16] =
{
  { P300,       H8_dec,         B | Cxh,        rLB,             }, // 1A 0?
  { none,       H8_null,        0,              0,               }, // 1A 1?
  { none,       H8_null,        0,              0,               }, // 1A 2?
  { none,       H8_null,        0,              0,               }, // 1A 3?
  { none,       H8_null,        0,              0,               }, // 1A 4?
  { none,       H8_null,        0,              0,               }, // 1A 5?
  { none,       H8_null,        0,              0,               }, // 1A 6?
  { none,       H8_null,        0,              0,               }, // 1A 7?
  { P30A,       H8_sub,         L | rHL1,       rLL0,            }, // 1A 8?
  { P30A,       H8_sub,         L | rHL1,       rLL0,            }, // 1A 9?
  { P30A,       H8_sub,         L | rHL1,       rLL0,            }, // 1A A?
  { P30A,       H8_sub,         L | rHL1,       rLL0,            }, // 1A B?
  { P30A,       H8_sub,         L | rHL1,       rLL0,            }, // 1A C?
  { P30A,       H8_sub,         L | rHL1,       rLL0,            }, // 1A D?
  { P30A,       H8_sub,         L | rHL1,       rLL0,            }, // 1A E?
  { P30A,       H8_sub,         L | rHL1,       rLL0,            }, // 1A F?
};

//--------------------------------------------------------------------------
static const map_t map2_1B[16] =
{
  { P300,       H8_subs,        C1,             rV0,             }, // 1B 0?
  { none,       H8_null,        0,              0,               }, // 1B 1?
  { none,       H8_null,        0,              0,               }, // 1B 2?
  { none,       H8_null,        0,              0,               }, // 1B 3?
  { none,       H8_null,        0,              0,               }, // 1B 4?
  { P300,       H8_dec,         W | C1,         rLW,             }, // 1B 5?
  { none,       H8_null,        0,              0,               }, // 1B 6?
  { P30A,       H8_dec,         L | C1,         rLL0,            }, // 1B 7?
  { P300,       H8_subs,        C2,             rV0,             }, // 1B 8?
  { P30A,       H8_subs,        C4,             rLL0,            }, // 1B 9?
  { none,       H8_null,        0,              0,               }, // 1B A?
  { none,       H8_null,        0,              0,               }, // 1B B?
  { none,       H8_null,        0,              0,               }, // 1B C?
  { P300,       H8_dec,         W | C2,         rLW,             }, // 1B D?
  { none,       H8_null,        0,              0,               }, // 1B E?
  { P30A,       H8_dec,         L | C2,         rLL0,            }, // 1B F?
};

//--------------------------------------------------------------------------
static const map_t map2_1F[16] =
{
  { P300,       H8_das,         rLB,            0,               }, // 1F 0?
  { none,       H8_null,        0,              0,               }, // 1F 1?
  { none,       H8_null,        0,              0,               }, // 1F 2?
  { none,       H8_null,        0,              0,               }, // 1F 3?
  { none,       H8_null,        0,              0,               }, // 1F 4?
  { none,       H8_null,        0,              0,               }, // 1F 5?
  { none,       H8_null,        0,              0,               }, // 1F 6?
  { none,       H8_null,        0,              0,               }, // 1F 7?
  { P30A,       H8_cmp,         L | rHL1,       rLL0,            }, // 1F 8?
  { P30A,       H8_cmp,         L | rHL1,       rLL0,            }, // 1F 9?
  { P30A,       H8_cmp,         L | rHL1,       rLL0,            }, // 1F A?
  { P30A,       H8_cmp,         L | rHL1,       rLL0,            }, // 1F B?
  { P30A,       H8_cmp,         L | rHL1,       rLL0,            }, // 1F C?
  { P30A,       H8_cmp,         L | rHL1,       rLL0,            }, // 1F D?
  { P30A,       H8_cmp,         L | rHL1,       rLL0,            }, // 1F E?
  { P30A,       H8_cmp,         L | rHL1,       rLL0,            }, // 1F F?
};

//--------------------------------------------------------------------------
static const map_t map2_58[16] =
{
  { P300,       H8_bra,         zL | j16,       0,               }, // 58 0?
  { P300,       H8_brn,         zL | j16,       0,               }, // 58 1?
  { P300,       H8_bhi,         zL | j16,       0,               }, // 58 2?
  { P300,       H8_bls,         zL | j16,       0,               }, // 58 3?
  { P300,       H8_bcc,         zL | j16,       0,               }, // 58 4?
  { P300,       H8_bcs,         zL | j16,       0,               }, // 58 5?
  { P300,       H8_bne,         zL | j16,       0,               }, // 58 6?
  { P300,       H8_beq,         zL | j16,       0,               }, // 58 7?
  { P300,       H8_bvc,         zL | j16,       0,               }, // 58 8?
  { P300,       H8_bvs,         zL | j16,       0,               }, // 58 9?
  { P300,       H8_bpl,         zL | j16,       0,               }, // 58 A?
  { P300,       H8_bmi,         zL | j16,       0,               }, // 58 B?
  { P300,       H8_bge,         zL | j16,       0,               }, // 58 C?
  { P300,       H8_blt,         zL | j16,       0,               }, // 58 D?
  { P300,       H8_bgt,         zL | j16,       0,               }, // 58 E?
  { P300,       H8_ble,         zL | j16,       0,               }, // 58 F?
};

//--------------------------------------------------------------------------
static const map_t map2_6A[16] =
{
  { P300,       H8_mov,         B | aa16,       rLB,             }, // 6A 0?
  { P300,       MAP4,           0,              0,               }, // 6A 1?
  { P300,       H8_mov,         B | aa32,       rLB,             }, // 6A 2?
  { P300,       MAP4,           0,              0,               }, // 6A 3?
  { P300,       H8_movfpe,      B | X | aa16,   rLB,             }, // 6A 4?
  { none,       H8_null,        0,              0,               }, // 6A 5?
  { none,       H8_null,        0,              0,               }, // 6A 6?
  { none,       H8_null,        0,              0,               }, // 6A 7?
  { P300,       H8_mov,         B | aa16,       rLB,             }, // 6A 8?
  { none,       H8_null,        0,              0,               }, // 6A 9?
  { P300,       H8_mov,         B | aa32,       rLB,             }, // 6A A?
  { none,       H8_null,        0,              0,               }, // 6A B?
  { P300,       H8_movtpe,      rLB,            B | aa16,        }, // 6A C?
  { none,       H8_null,        0,              0,               }, // 6A D?
  { none,       H8_null,        0,              0,               }, // 6A E?
  { none,       H8_null,        0,              0,               }, // 6A F?
};

//--------------------------------------------------------------------------
static const map_t map2_6A_h8sx[16] =
{
  { P300,       H8_mov,         B | aa16,       rLB,             }, // 6A 0?
  { P300,       H8_null,        0,              0,               }, // 6A 1?
  { P300,       H8_mov,         B | aa32,       rLB,             }, // 6A 2?
  { P300,       H8_null,        0,              0,               }, // 6A 3?
  { P300,       H8_movfpe,      B | X | aa16,   rLB,             }, // 6A 4?
  { none,       H8_null,        0,              0,               }, // 6A 5?
  { none,       H8_null,        0,              0,               }, // 6A 6?
  { none,       H8_null,        0,              0,               }, // 6A 7?
  { P300,       H8_mov,         B | rLB,        B | aa16,        }, // 6A 8?
  { none,       H8_null,        0,              0,               }, // 6A 9?
  { P300,       H8_mov,         B | rLB,        B | aa32,        }, // 6A A?
  { none,       H8_null,        0,              0,               }, // 6A B?
  { P300,       H8_movtpe,      rLB,            B | aa16,        }, // 6A C?
  { PSX,        H8_mov,         B | i4L,        B | aa16,        }, // 6A D?
  { none,       H8_null,        0,              0,               }, // 6A E?
  { PSX,        H8_mov,         B | i4L,        B | aa32,        }, // 6A F?
};

//--------------------------------------------------------------------------
static const map_t map2_6B_h8sx[16] =
{
  { P300,       H8_mov,         W | aa16,       rLW,             }, // 6A 0?
  { P300,       H8_null,        0,              0,               }, // 6A 1?
  { P300,       H8_mov,         W | aa32,       rLW,             }, // 6A 2?
  { P300,       H8_null,        0,              0,               }, // 6A 3?
  { P300,       H8_null,        0,              0,               }, // 6A 4?
  { none,       H8_null,        0,              0,               }, // 6A 5?
  { none,       H8_null,        0,              0,               }, // 6A 6?
  { none,       H8_null,        0,              0,               }, // 6A 7?
  { P300,       H8_mov,         W | rLW,        W | aa16,        }, // 6A 8?
  { none,       H8_null,        0,              0,               }, // 6A 9?
  { P300,       H8_mov,         W | rLW,        W | aa32,        }, // 6A A?
  { none,       H8_null,        0,              0,               }, // 6A B?
  { P300,       H8_null,        0,              0,               }, // 6A C?
  { PSX,        H8_mov,         W | i4L,        W | aa16,        }, // 6A D?
  { none,       H8_null,        0,              0,               }, // 6A E?
  { PSX,        H8_mov,         W | i4L,        W | aa32,        }, // 6A F?
};

//--------------------------------------------------------------------------
static const map_t map2_79[16] =
{
  { P300,       H8_mov,         W | i16,        rLW              }, // 79 0?
  { P300,       H8_add,         W | i16,        rLW              }, // 79 1?
  { P300,       H8_cmp,         W | i16,        rLW              }, // 79 2?
  { P300,       H8_sub,         W | i16,        rLW              }, // 79 3?
  { P300,       H8_or,          W | i16,        rLW              }, // 79 4?
  { P300,       H8_xor,         W | i16,        rLW              }, // 79 5?
  { P300,       H8_and,         W | i16,        rLW              }, // 79 6?
  { none,       H8_null,        0,              0,               }, // 79 7?
  { none,       H8_null,        0,              0,               }, // 79 8?
  { none,       H8_null,        0,              0,               }, // 79 9?
  { none,       H8_null,        0,              0,               }, // 79 A?
  { none,       H8_null,        0,              0,               }, // 79 B?
  { none,       H8_null,        0,              0,               }, // 79 C?
  { none,       H8_null,        0,              0,               }, // 79 D?
  { none,       H8_null,        0,              0,               }, // 79 E?
  { none,       H8_null,        0,              0,               }, // 79 F?
};

//--------------------------------------------------------------------------
static const map_t map2_7A[16] =
{
  { P30A,       H8_mov,         L | i32,        rLL0,            }, // 7A 0?
  { P30A,       H8_add,         L | i32,        rLL0,            }, // 7A 1?
  { P30A,       H8_cmp,         L | i32,        rLL0,            }, // 7A 2?
  { P30A,       H8_sub,         L | i32,        rLL0,            }, // 7A 3?
  { P30A,       H8_or,          L | i32,        rLL0,            }, // 7A 4?
  { P30A,       H8_xor,         L | i32,        rLL0,            }, // 7A 5?
  { P30A,       H8_and,         L | i32,        rLL0,            }, // 7A 6?
  { none,       H8_null,        0,              0,               }, // 7A 7?
  { none,       H8_null,        0,              0,               }, // 7A 8?
  { none,       H8_null,        0,              0,               }, // 7A 9?
  { none,       H8_null,        0,              0,               }, // 7A A?
  { none,       H8_null,        0,              0,               }, // 7A B?
  { none,       H8_null,        0,              0,               }, // 7A C?
  { none,       H8_null,        0,              0,               }, // 7A D?
  { none,       H8_null,        0,              0,               }, // 7A E?
  { none,       H8_null,        0,              0,               }, // 7A F?
};

//--------------------------------------------------------------------------
static const map_t map3_01C05[8] =
{
  { P300,       H8_mulxs,       B | NEXT | rHB, rLW,             }, // 01 C0 50
  { none,       H8_null,        0,              0,               }, // 01 C0 51
  { P30A,       H8_mulxs,       W | NEXT | rHW, rLL0,            }, // 01 C0 52
  { none,       H8_null,        0,              0,               }, // 01 C0 53
  { none,       H8_null,        0,              0,               }, // 01 C0 54
  { none,       H8_null,        0,              0,               }, // 01 C0 55
  { none,       H8_null,        0,              0,               }, // 01 C0 56
  { none,       H8_null,        0,              0,               }, // 01 C0 57
};

//--------------------------------------------------------------------------
static const map_t map3_01D05[8] =
{
  { none,       H8_null,        0,              0,               }, // 01 D0 50
  { P300,       H8_divxs,       B | NEXT | rHB, rLW,             }, // 01 D0 51
  { none,       H8_null,        0,              0,               }, // 01 D0 52
  { P30A,       H8_divxs,       W | NEXT | rHW, rLL0,            }, // 01 D0 53
  { none,       H8_null,        0,              0,               }, // 01 D0 54
  { none,       H8_null,        0,              0,               }, // 01 D0 55
  { none,       H8_null,        0,              0,               }, // 01 D0 56
  { none,       H8_null,        0,              0,               }, // 01 D0 57
};

//--------------------------------------------------------------------------
static const map_t map3_01F06[8] =
{
  { none,       H8_null,        0,              0,               }, // 01 F0 60
  { none,       H8_null,        0,              0,               }, // 01 F0 61
  { none,       H8_null,        0,              0,               }, // 01 F0 62
  { none,       H8_null,        0,              0,               }, // 01 F0 63
  { P30A,       H8_or,          L | NEXT | rHL0,rLL0,            }, // 01 F0 64
  { P30A,       H8_xor,         L | NEXT | rHL0,rLL0,            }, // 01 F0 65
  { P30A,       H8_and,         L | NEXT | rHL0,rLL0,            }, // 01 F0 66
  { none,       H8_null,        0,              0,               }, // 01 F0 67
};

//--------------------------------------------------------------------------
static const map_t map3_7Cr06[8] =
{
  { none,       H8_null,        0,              0,               }, // 7C r0 60
  { none,       H8_null,        0,              0,               }, // 7C r0 61
  { none,       H8_null,        0,              0,               }, // 7C r0 62
  { P300,       H8_btst,        NEXT | rHB | zL,savedHL0,        }, // 7C r0 63
  { none,       H8_null,        0,              0,               }, // 7C r0 64
  { none,       H8_null,        0,              0,               }, // 7C r0 65
  { none,       H8_null,        0,              0,               }, // 7C r0 66
  { none,       H8_null,        0,              0,               }, // 7C r0 67
};

//--------------------------------------------------------------------------
static const map_t map3_7Cr07[8] =
{
  { none,       H8_null,        0,              0,               }, // 7C r0 70
  { none,       H8_null,        0,              0,               }, // 7C r0 71
  { none,       H8_null,        0,              0,               }, // 7C r0 72
  { P300,       H8_btst,        NEXT | i3 | zL, savedHL0,        }, // 7C r0 73
  { P300,       H8_bor,         NEXT | i3 | zL, savedHL0,        }, // 7C r0 74
  { P300,       H8_bxor,        NEXT | i3 | zL, savedHL0,        }, // 7C r0 75
  { P300,       H8_band,        NEXT | i3 | zL, savedHL0,        }, // 7C r0 76
  { P300,       H8_bld,         NEXT | i3 | zL, savedHL0,        }, // 7C r0 77
};

//--------------------------------------------------------------------------
static const map_t map3_7Dr06[8] =
{
  { P300,       H8_bset,        NEXT | rHB | zL,savedHL0,        }, // 7D r0 60
  { P300,       H8_bnot,        NEXT | rHB | zL,savedHL0,        }, // 7D r0 61
  { P300,       H8_bclr,        NEXT | rHB | zL,savedHL0,        }, // 7D r0 62
  { none,       H8_null,        0,              0,               }, // 7D r0 63
  { none,       H8_null,        0,              0,               }, // 7D r0 64
  { none,       H8_null,        0,              0,               }, // 7D r0 65
  { none,       H8_null,        0,              0,               }, // 7D r0 66
  { P300,       H8_bst,         NEXT | i3  | zL,savedHL0,        }, // 7D r0 67
};

//--------------------------------------------------------------------------
static const map_t map3_7Dr07[8] =
{
  { P300,       H8_bset,        NEXT | i3 | zL, savedHL0,        }, // 7D r0 70
  { P300,       H8_bnot,        NEXT | i3 | zL, savedHL0,        }, // 7D r0 71
  { P300,       H8_bclr,        NEXT | i3 | zL, savedHL0,        }, // 7D r0 72
  { none,       H8_null,        0,              0,               }, // 7D r0 73
  { none,       H8_null,        0,              0,               }, // 7D r0 74
  { none,       H8_null,        0,              0,               }, // 7D r0 75
  { none,       H8_null,        0,              0,               }, // 7D r0 76
  { none,       H8_null,        0,              0,               }, // 7D r0 77
};

//--------------------------------------------------------------------------
static const map_t map3_7Eaa6[8] =
{
  { none,       H8_null,        0,              0,               }, // 7E aa 60
  { none,       H8_null,        0,              0,               }, // 7E aa 61
  { none,       H8_null,        0,              0,               }, // 7E aa 62
  { P300,       H8_btst,        NEXT | rHB | zL,savedAA,         }, // 7E r0 63
  { none,       H8_null,        0,              0,               }, // 7E aa 64
  { none,       H8_null,        0,              0,               }, // 7E aa 65
  { none,       H8_null,        0,              0,               }, // 7E aa 66
  { none,       H8_null,        0,              0,               }, // 7E aa 67
};

//--------------------------------------------------------------------------
static const map_t map3_7Eaa7[8] =
{
  { none,       H8_null,        0,              0,               }, // 7E aa 70
  { none,       H8_null,        0,              0,               }, // 7E aa 71
  { none,       H8_null,        0,              0,               }, // 7E aa 72
  { P300,       H8_btst,        NEXT | i3 | zL, savedAA,         }, // 7E aa 73
  { P300,       H8_bor,         NEXT | i3 | zL, savedAA,         }, // 7E aa 74
  { P300,       H8_bxor,        NEXT | i3 | zL, savedAA,         }, // 7E aa 75
  { P300,       H8_band,        NEXT | i3 | zL, savedAA,         }, // 7E aa 76
  { P300,       H8_bld,         NEXT | i3 | zL, savedAA,         }, // 7E aa 77
};

//--------------------------------------------------------------------------
static const map_t map3_7Faa6[8] =
{
  { P300,       H8_bset,        NEXT | rHB | zL,savedAA,         }, // 7F aa 60
  { P300,       H8_bnot,        NEXT | rHB | zL,savedAA,         }, // 7F aa 61
  { P300,       H8_bclr,        NEXT | rHB | zL,savedAA,         }, // 7F aa 62
  { none,       H8_null,        0,              0,               }, // 7F aa 63
  { none,       H8_null,        0,              0,               }, // 7F aa 64
  { none,       H8_null,        0,              0,               }, // 7F aa 65
  { none,       H8_null,        0,              0,               }, // 7F aa 66
  { P300,       H8_bst,         NEXT | i3  | zL,savedAA,         }, // 7F aa 67
};

//--------------------------------------------------------------------------
static const map_t map3_7Faa7[8] =
{
  { P300,       H8_bset,        NEXT | i3 | zL, savedAA,         }, // 7F r0 70
  { P300,       H8_bnot,        NEXT | i3 | zL, savedAA,         }, // 7F r0 71
  { P300,       H8_bclr,        NEXT | i3 | zL, savedAA,         }, // 7F r0 72
  { none,       H8_null,        0,              0,               }, // 7F aa 73
  { none,       H8_null,        0,              0,               }, // 7F aa 74
  { none,       H8_null,        0,              0,               }, // 7F aa 75
  { none,       H8_null,        0,              0,               }, // 7F aa 76
  { none,       H8_null,        0,              0,               }, // 7F aa 77
};

//--------------------------------------------------------------------------
struct map2_pointer_t
{
  uchar prefix;
  const map_t *map;
};

static const map2_pointer_t map2[] =
{
  { 0x01, map2_01 },
  { 0x02, map2_02 },
  { 0x03, map2_03 },
  { 0x0A, map2_0A },
  { 0x0B, map2_0B },
  { 0x0F, map2_0F },
  { 0x10, map2_10 },
  { 0x11, map2_11 },
  { 0x12, map2_12 },
  { 0x13, map2_13 },
  { 0x17, map2_17 },
  { 0x1A, map2_1A },
  { 0x1B, map2_1B },
  { 0x1F, map2_1F },
  { 0x58, map2_58 },
  { 0x6A, map2_6A },
  { 0x79, map2_79 },
  { 0x7A, map2_7A },
};

struct map3_pointer_t
{
  uint32 prefix;
  uint32 mask;           // bit set means that the bit is ignored
  const map_t *map;
};

static const map3_pointer_t map3[] =
{
  { 0x01C05, 0x000, map3_01C05 },
  { 0x01D05, 0x000, map3_01D05 },
  { 0x01F06, 0x000, map3_01F06 },
  { 0x7C006, 0xF00, map3_7Cr06 },
  { 0x7C007, 0xF00, map3_7Cr07 },
  { 0x7D006, 0xF00, map3_7Dr06 },
  { 0x7D007, 0xF00, map3_7Dr07 },
  { 0x7E006, 0xFF0, map3_7Eaa6 },
  { 0x7E007, 0xFF0, map3_7Eaa7 },
  { 0x7F006, 0xFF0, map3_7Faa6 },
  { 0x7F007, 0xFF0, map3_7Faa7 },
};

static uchar code;
static uchar code3;

static bool op_reg(op_t &x, uint8 reg, ushort place, uint16 aux_assumed = aux_none);
static bool op_phrase(op_t &x, uint8 reg, int pht, char dtyp = dt_byte);
static bool op_phrase_prepost(op_t &x, uint8 reg, uint8 selector);
static bool op_phrase_displ2(op_t &x, uint8 reg, uint8 displ);
static void op_imm(op_t &x, uval_t val);
static void op_imm_8(op_t &x, uint8 val);
static void op_imm_3(op_t &x, uint8 val);
static bool op_aa_8(op_t &x, uint8 val, char dtyp);
static bool op_reglist(op_t &x, uint8 reg, uint8 delta, bool is_inc);

//--------------------------------------------------------------------------------------
// possible address ranges for the Absolute Address operands
//
//--------------------------------------------------------------------------------------
// addressing   |  normal mode     |  advanced mode H8/300H  |   advanced mode H8S
//--------------+------------------+-------------------------+--------------------------
//   @aa:8      | H'FF00 to H'FFFF |   H'FFFF00 to H'FFFFFF  | H'FFFFFF00 to H'FFFFFFFF   (upper bits are 1s)
//--------------+------------------+-------------------------+--------------------------
//   @aa:16     | H'0000 to H'FFFF |   H'000000 to H'007FFF, | H'00000000 to H'00007FFF,  (sign extension)
//              |                  |   H'FF8000 to H'FFFFFF  | H'FFFF8000 to H'FFFFFFFF
//--------------+------------------+-------------------------+--------------------------
//   @aa:24     | H'0000 to H'FFFF |   H'000000 to H'FFFFFF  | H'00000000 to H'00FFFFFF   (upper bits are 0s)
//--------------+------------------+-------------------------+--------------------------
//   @aa:32     |                  |                         | H'00000000 to H'FFFFFFFF
//--------------+------------------+-------------------------+--------------------------

// NB: the 8-bit address already has upper bits set to 1s by the decoder
static void trimaddr(op_t &x)
{
  if ( x.szfl & disp_32 )
    return;
  if ( x.szfl & disp_16 )
  {
    if ( x.type == o_mem && advanced() && (x.addr & 0x8000) != 0 )
      x.addr |= 0xFFFF0000; // sign extend
  }
  if ( !advanced() )
    x.addr &= 0x00FFFFL; // 64K address space
  else if ( !is_h8s() )
    x.addr &= 0xFFFFFFL; // 16-Mbyte address space
}

//--------------------------------------------------------------------------
static void get_disp(op_t &x, bool disp32)
{
  x.offb = (uchar)cmd.size;
  if ( !disp32 )
  {
    x.szfl |= disp_16;
    x.addr = short(ua_next_word());
  }
  else
  {
    x.szfl |= disp_32;
    x.addr = ua_next_long();
  }
}

//--------------------------------------------------------------------------
static void opimm8(op_t &x)
{
  x.offb = (uchar)cmd.size;
  x.type = o_imm;
  x.dtyp = dt_byte;
  x.value = ua_next_byte();
}

//--------------------------------------------------------------------------
static void opreg8(op_t &x, uint16 reg)
{
  x.type = o_reg;
  x.dtyp = dt_byte;
  x.reg  = reg;
}

//--------------------------------------------------------------------------
inline regnum_t r0(void) { return advanced() ? ER0 : R0; }

//--------------------------------------------------------------------------
static void opatHL(op_t &x, char dtyp)
{
  x.type = o_phrase;
  x.dtyp = dtyp;
  x.reg  = r0() + ((code>>4) & 7);
  x.phtype = ph_normal;
}

//--------------------------------------------------------------------------
static void oppost(op_t &x, uint16 reg, char dtyp)
{
  x.type   = o_phrase;
  x.dtyp   = dtyp;
  x.reg    = reg;
  x.phtype = ph_post_inc;
}

//--------------------------------------------------------------------------
static void opdsp16(op_t &x, char dtyp)
{
  x.type = o_displ;
  x.dtyp = dtyp;
  x.reg  = r0() + ((code>>4) & 7);
  get_disp(x, false);
  if ( isOff(get_flags_novalue(cmd.ea), -1) )
    x.addr = ushort(x.addr);
}

//--------------------------------------------------------------------------
static void opdsp32(op_t &x, char dtyp)
{
  x.type = o_displ;
  x.dtyp = dtyp;
  x.reg  = r0() + ((code>>4) & 7);
  get_disp(x, true);
}

//--------------------------------------------------------------------------
static void opreg(op_t &x, uint16 reg, char dtyp)
{
  switch ( dtyp )
  {
    case dt_byte:
      reg += R0H;
      break;
    case dt_word:
      reg += R0;
      break;
    case dt_dword:
      reg += ER0;
      break;
  }
  x.type = o_reg;
  x.dtyp = dtyp;
  x.reg  = reg;
}

//--------------------------------------------------------------------------
static char calc_dtyp(ushort flags)
{
  char dtyp;
  if ( flags & B )
    dtyp = dt_byte;
  else if ( flags & W )
    dtyp = dt_word;
  else if ( flags & L )
    dtyp = dt_dword;
  else
    dtyp = dt_code;
  return dtyp;
}

//--------------------------------------------------------------------------
static bool read_operand(op_t &x, ushort flags)
{
  if ( flags & NEXT )
    code = ua_next_byte();
  if ( (flags & zL) && (code & 0x0F) != 0 )
    return false;
  if ( (flags & zH) && (code & 0xF0) != 0 )
    return false;

  switch ( flags & OPTYPE )
  {
    case 0:       // none
      break;
    case i3:      // immediate 3 bits
      x.type = o_imm;
      x.dtyp = dt_byte;
      x.value = (code >> 4) & 7;
      break;
    case i4L:     // immediate 4 bits
      x.type = o_imm;
      x.dtyp = dt_byte;
      x.value = code & 0xF;
      break;
    case i4H:     // immediate 4 bits
      x.type = o_imm;
      x.dtyp = dt_byte;
      x.value = (code >> 4) & 0xF;
      x.dtyp = calc_dtyp(flags);
      break;
    case i8:      // immediate 8 bits
      opimm8(x);
      break;
    case i16:     // immediate 16 bits
      x.offb = (uchar)cmd.size;
      x.type = o_imm;
      x.dtyp = dt_word;
      x.value = ua_next_word();
      break;
    case i32:     // immediate 32 bits
      if ( !advanced() )
        return false;
      x.offb = (uchar)cmd.size;
      x.type = o_imm;
      x.dtyp = dt_dword;
      x.value = ua_next_long();
      break;
    case rCCR:    // CCR
      opreg8(x, CCR);
      break;
    case rEXR:    // EXR
      opreg8(x, EXR);
      break;
    case rVBR:
      x.type = o_reg;
      x.dtyp = dt_dword;
      x.reg  = VBR;
      break;
    case rSBR:
      x.type = o_reg;
      x.dtyp = dt_dword;
      x.reg  = SBR;
      break;
    case rLB:     // register number in low nibble  (r0l..r7h)
      opreg8(x, R0H + (code & 15));
      break;
    case rHB:     // register number in high nibble (r0l..r7h)
      opreg8(x, R0H + ((code>>4) & 15));
      break;
    case rLW:     // register number in low nibble  (r0..e7)
LW:
      x.type = o_reg;
      x.dtyp = dt_word;
      x.reg  = R0 + (code & 15);
      break;
    case rHW:     // register number in high nibble (r0..e7)
      x.type = o_reg;
      x.dtyp = dt_word;
      x.reg  = R0 + ((code>>4) & 15);
      break;
    case rV0:     // register number in low nibble
      if ( (code & 0x08) != 0 )
        return false;
      if ( !advanced() )
        goto LW;
      goto LL;
    case rLL0:    // register number in low nibble
      if ( (code & 0x08) != 0 )
        return false;
      if ( !advanced() )
        return false;
LL:
      x.type = o_reg;
      x.dtyp = dt_dword;
      x.reg  = ER0 + (code & 7);
      break;
    case rHL0:    // register number in high nibble
      if ( (code & 0x80) != 0 )
        return false;
      if ( !advanced() )
        return false;
HL:
      x.type = o_reg;
      x.dtyp = dt_dword;
      x.reg  = ER0 + ((code>>4) & 7);
      break;
    case rMACH:
      x.type = o_reg;
      x.dtyp = dt_dword;
      x.reg  = MACH;
      break;
    case rMACL:
      x.type = o_reg;
      x.dtyp = dt_dword;
      x.reg  = MACL;
      break;
    case savedHL0:      // @ERx
      if ( (code3 & 0x80) != 0 )
        return false;
      x.type = o_phrase;
      x.dtyp = dt_dword;
      x.reg  = r0() + ((code3>>4) & 7);
      x.phtype = ph_normal;
      break;
    case atHL:          // @ERx
      opatHL(x, calc_dtyp(flags));
      break;
    case rLL1:    // register number in low nibble
      if ( (code & 0x08) == 0 )
        return false;
      if ( !advanced() )
        return false;
      goto LL;
    case rHL1:    // register number in high nibble
      if ( (code & 0x80) == 0 )
        return false;
      if ( !advanced() )
        return false;
      goto HL;
    case C1:      // constant #1
      x.type = o_imm;
      x.dtyp = dt_byte;
      x.value = 1;
      break;
    case C2:      // constant #2
      x.type = o_imm;
      x.dtyp = dt_byte;
      x.value = 2;
      break;
    case C4:      // constant #4
      x.type = o_imm;
      x.dtyp = dt_byte;
      x.value = 4;
      break;
    case C8:      // constant #8
      x.type = o_imm;
      x.dtyp = dt_byte;
      x.value = 8;
      break;
    case Cxh:     // hidden o_imm op
      x.type = o_imm;
      x.dtyp = calc_dtyp(flags);
      x.value = 1;
      x.clr_shown();
      break;
    case savedAA:
      x.type = o_mem;
      x.dtyp = dt_byte;
      x.addr = ~0xFF | code3;
      trimaddr(x);
      break;
    case j8:
      x.offb = (uchar)cmd.size;
      x.type = o_near;
      x.dtyp = dt_code;
      {
        signed char disp = ua_next_byte();
        x.addr = cmd.ip + cmd.size + disp;
        x.addr &= ~1;
      }
      break;
    case j16:
      x.offb = (uchar)cmd.size;
      x.type = o_near;
      x.dtyp = dt_code;
      {
        signed short disp = ua_next_word();
        x.addr = cmd.ip + cmd.size + disp;
        x.addr &= ~1;
        x.szfl |= disp_16;
      }
      break;
    case aa8:
      if ( !is_h8sx() )
      {
        x.offb = (uchar)cmd.size;
        x.type = o_mem;
        x.dtyp = calc_dtyp(flags);
        x.addr = ~0xFF | ua_next_byte();
        trimaddr(x);
      }
      else
      {
        uint8 val = ua_next_byte();
        op_aa_8(x, val, calc_dtyp(flags));
      }
      break;
    case ai8:
      x.offb = (uchar)cmd.size;
      x.type = o_mem;
      x.memtype = mem_ind;
      x.dtyp = advanced() ? dt_dword : dt_word;
      x.addr = ua_next_byte();
      break;
    case aa16:
      x.type = o_mem;
      x.dtyp = calc_dtyp(flags);
      get_disp(x, false);
      trimaddr(x);
      break;
    case aa32:
      x.type = o_mem;
      x.dtyp = calc_dtyp(flags);
      get_disp(x, true);
      break;
    case aa24:          // 24bit address (16bit in !advanced())
      x.offb = (uchar)cmd.size;
      x.type = o_near;
      x.dtyp = calc_dtyp(flags);
      {
        uint32 high = ua_next_byte();
        if ( !advanced() && high != 0 )
          return false;
        x.addr = (high << 16) | ua_next_word();
        x.szfl |= advanced() ? disp_24 : disp_16;
      }
      break;
    case d16:           // @(d:16, ERs)
      opdsp16(x, calc_dtyp(flags));
      break;
    default:
      INTERR(10092);
  }
  return true;
}

//--------------------------------------------------------------------------
// 01 4?
static bool map014(void)
{
  switch ( code )
  {
    case 0x40:
      opreg8(cmd.Op2, CCR);
      break;
    case 0x41:
      opreg8(cmd.Op2, EXR);
      break;
    default:
      return false;
  }

  cmd.itype = H8_ldc;
  code = ua_next_byte();
  char dtyp = dt_word;
  switch ( code )
  {
    case 0x04:
      cmd.itype = H8_orc;
      dtyp = dt_byte;
      opimm8(cmd.Op1);
      break;
    case 0x05:
      cmd.itype = H8_xorc;
      dtyp = dt_byte;
      opimm8(cmd.Op1);
      break;
    case 0x06:
      cmd.itype = H8_andc;
      dtyp = dt_byte;
      opimm8(cmd.Op1);
      break;
    case 0x07:
      dtyp = dt_byte;
      opimm8(cmd.Op1);
      break;
    case 0x69:
      code = ua_next_byte();
      if ( code & 0x0F )
        return false;
      opatHL(cmd.Op1, dtyp);
      break;
    case 0x6B:
      cmd.Op1.type = o_mem;
      cmd.Op1.dtyp = dtyp;
      code = ua_next_byte();
      switch ( code & 0x70 )
      {
        case 0x00:
          get_disp(cmd.Op1, false);
          break;
        case 0x20:
          get_disp(cmd.Op1, true);
          break;
        default:
          return false;
      }
      trimaddr(cmd.Op1);
      break;
    case 0x6D:
      code = ua_next_byte();
      if ( code & 0x0F )
        return false;
      oppost(cmd.Op1, r0() + ((code>>4) & 7), dtyp);
      break;
    case 0x6F:
      code = ua_next_byte();
      if ( code & 0x0F )
        return false;
      opdsp16(cmd.Op1, dtyp);
      break;
    case 0x78:
      code = ua_next_byte();
      if ( code & 0x8F )
        return false;
      if ( ua_next_byte() != 0x6B )
        return false;
      code3 = ua_next_byte();
      if ( (code3 & 0x70) != 0x20 )
        return false;
      opdsp32(cmd.Op1, dtyp);
      code = code3;
      break;
    default:
      return false;
  }
  if ( cmd.itype == H8_ldc )
    cmd.auxpref = (dtyp == dt_word) ? aux_word : aux_byte;
  return true;
}

//--------------------------------------------------------------------------
// 6A 1?
// 6A 3?
static bool map4(void)
{
  uchar pref = code;
  cmd.Op2.type = o_mem;
  cmd.Op2.dtyp = dt_byte;
  get_disp(cmd.Op2, pref >= 0x30);
  trimaddr(cmd.Op2);
  uchar pcode = ua_next_byte();
  code = ua_next_byte();
  if ( code & 0x0F )
    return false;
  if ( pcode >= 0x60 && pcode <= 0x63 )
  {
    opreg8(cmd.Op1, R0H + (code >> 4));
  }
  else
  {
    cmd.Op1.type = o_imm;
    cmd.Op1.dtyp = dt_byte;
    cmd.Op1.value = (code >> 4) & 7;
    if ( pcode >= 0x70 && pcode <= 0x73 )
      if ( code & 0x80 )
        return false;
  }
  switch ( pref )
  {
    case 0x10:
    case 0x30:
      switch ( pcode )
      {
        case 0x63:
        case 0x73:
          cmd.itype = H8_btst;
          break;
        case 0x74:
          cmd.itype = H8_bor;
          break;
        case 0x75:
          cmd.itype = H8_bxor;
          break;
        case 0x76:
          cmd.itype = H8_band;
          break;
        case 0x77:
          cmd.itype = H8_bld;
          break;
        default:
          return false;
      }
      break;

    case 0x18:
    case 0x38:
      switch ( pcode )
      {
        case 0x60:
        case 0x70:
          cmd.itype = H8_bset;
          break;
        case 0x61:
        case 0x71:
          cmd.itype = H8_bnot;
          break;
        case 0x62:
        case 0x72:
          cmd.itype = H8_bclr;
          break;
        case 0x67:
          cmd.itype = H8_bst;
          break;
      }
      break;

    default:
      return false;
  }
  return true;
}

//--------------------------------------------------------------------------
inline void swap_Op1_Op2()
{
  op_t x = cmd.Op1;
  cmd.Op1 = cmd.Op2;
  cmd.Op2 = x;
  cmd.Op1.n = 0;
  cmd.Op2.n = 1;
}

//--------------------------------------------------------------------------
static int exit_40(void);
static int exit_54_56(uint8 rts, uint8 rtsl);
static int exit_59_5D(uint16 jump, uint16 branch);
static int exit_7B(void);
static int h8sx_01(void);
static int h8sx_03(void);
static int h8sx_0A(void);
static int h8sx_0F(void);
static int h8sx_10(void);
static int h8sx_11(void);
static int h8sx_1A(void);
static int h8sx_1F(void);
static int h8sx_6A(void);
static int h8sx_6B(void);
static int h8sx_78(void);
static int h8sx_79(void);
static int h8sx_7A(void);
static int h8sx_7C(void);
static int h8sx_7D(void);
static int h8sx_7E(void);
static int h8sx_7F(void);

//--------------------------------------------------------------------------
int idaapi ana(void)
{
  code = ua_next_byte();
  uchar code0 = code;

  char dtyp;
  int idx = code;
  const map_t *m = map;
  int i = -1;
  bool noswap = false;
  while ( 1 )
  {
    uint32 p3;
    m += idx;
    if ( (m->proc & ptype) == 0 )
      return 0;
    cmd.itype = m->itype;
    switch ( cmd.itype )
    {
      case H8_null:
        return 0;

      case EXIT_40:
        return exit_40();

      case EXIT_54:
        return exit_54_56(H8_rts, H8_rtsl);

      case EXIT_56:
        return exit_54_56(H8_rte, H8_rtel);

      case EXIT_59:
        return exit_59_5D(H8_jmp, H8_bra);

      case EXIT_5D:
        return exit_59_5D(H8_jsr, H8_bsr);

      case EXIT_7B:
        return exit_7B();

      case H8_ldm:              // 01 [123]?
        if ( !advanced() )
          return false;
        if ( code & 15 )
          return 0;
        cmd.Op2.nregs = (code >> 4) + 1;
        if ( ua_next_byte() != 0x6D )
          return 0;
        code = ua_next_byte();
        if ( (code & 0x78) != 0x70 )
          return 0;
        cmd.auxpref = aux_long;                // .l
        cmd.Op1.type   = o_phrase;
        cmd.Op1.phtype = ph_post_inc;
        cmd.Op1.dtyp   = dt_dword;
        cmd.Op1.phrase = ER7;
        cmd.Op2.type   = o_reglist;
        cmd.Op2.dtyp   = dt_dword;
        cmd.Op2.reg    = ER0 + (code & 7);
        if ( (code & 0x80) == 0 )
          cmd.Op2.reg -= cmd.Op2.nregs - 1;
        switch ( cmd.Op2.nregs )
        {
          case 2:
            if ( cmd.Op2.reg != ER0
              && cmd.Op2.reg != ER2
              && cmd.Op2.reg != ER4
              && cmd.Op2.reg != ER6 )
            {
              return 0;
            }
            break;
          case 3:
          case 4:
            if ( cmd.Op2.reg != ER0
              && cmd.Op2.reg != ER4 )
            {
              return 0;
            }
            break;
        }
        break;

      case H8_mac:              // 01 6?
        if ( code & 15 )
          return 0;
        if ( ua_next_byte() != 0x6D )
          return 0;
        code = ua_next_byte();
        if ( code & 0x88 )
          return 0;
        oppost(cmd.Op1, ER0 + ((code>>4) & 7),  dt_dword);
        oppost(cmd.Op2, ER0 + ( code     & 7),  dt_dword);
        break;

      case H8_mov:
        if ( (m->op1 & MANUAL) == 0 )
        {
          if ( code0 == 0xC || code0 == 0xD )
            noswap = true;
          break;
        }
        switch ( code )
        {
          case 0x00:            // 01 0?
            if ( !advanced() )
              return false;
            cmd.auxpref = aux_long;
            dtyp = dt_dword;
            switch ( ua_next_byte() )
            {
              case 0x69:
                code = ua_next_byte();
                if ( code & 0x08 )
                  return 0;
                opatHL(cmd.Op1, dtyp);
                opreg(cmd.Op2, code & 7, dtyp);
                break;
              case 0x6B:
                goto MOVABS;
              case 0x6D:
                goto MOVPOST;
              case 0x6F:
                code = ua_next_byte();
                opdsp16(cmd.Op1, dtyp);
                opreg(cmd.Op2, code & 7, dtyp);
                break;
              case 0x78:
                code = ua_next_byte();
                if ( code & 0x0F )
                  return 0;
                if ( ua_next_byte() != 0x6B )
                  return 0;
                goto MOVDISP32;
              default:
                return 0;
            }
            break;
          case 0x6B:            // mov.w @aa, Rd
            if ( is_h8sx() )
              return h8sx_6B();

            cmd.auxpref = aux_word;
            dtyp = dt_word;
MOVABS:
            code = ua_next_byte();
            cmd.Op1.type = o_mem;
            cmd.Op1.dtyp = dtyp;
            switch ( (code >> 4) & 7 )
            {
              case 0x0:
                get_disp(cmd.Op1, false);
                break;
              case 0x2:
                get_disp(cmd.Op1, true);
                break;
              default:
                return 0;
            }
            trimaddr(cmd.Op1);
            opreg(cmd.Op2, code & 15, dtyp);
            break;
          case 0x6C:            // byte  mov.b @ERs+, Rd
            dtyp = dt_byte;
            cmd.auxpref = aux_byte;
            goto MOVPOST;
          case 0x6D:            // word  mov.w @ERs+, Rd
            dtyp = dt_word;
            cmd.auxpref = aux_word;
MOVPOST:
            code = ua_next_byte();
            if ( dtyp == dt_dword && (code & 0x08) )
              return 0;
            switch ( code & 0xF0 )
            {
              case 0x70:        // pop
                cmd.itype = H8_pop;
                opreg(cmd.Op1, (code & 15), dtyp);
                break;
              case 0xF0:        // push
                cmd.itype = H8_push;
                opreg(cmd.Op1, (code & 15), dtyp);
                break;
              default:          // mov
                oppost(cmd.Op1, r0() + ((code>>4) & 7), dtyp);
                opreg(cmd.Op2, (code & 15), dtyp);
                break;
            }
            break;
          case 0x78:            // 78 ?0 6A 2?
            if ( is_h8sx() )
              return h8sx_78();
            {
              code = ua_next_byte();
              if ( code & 0x8F )
                return 0;
              switch ( ua_next_byte() )
              {
                case 0x6A:        // byte
                  cmd.auxpref = aux_byte;
                  dtyp = dt_byte;
                  break;
                case 0x6B:        // word
                  dtyp = dt_word;
                  cmd.auxpref = aux_word;
                  break;
                default:
                  return 0;
              }
MOVDISP32:
              code3 = ua_next_byte();
              if ( (code3 & 0x70) != 0x20 )
                return 0;
              opdsp32(cmd.Op1, dtyp);
              opreg(cmd.Op2, code3 & 15, dtyp);
              code = code3;       // to swap operands if required
            }
            break;
          default:
            return 0;
        }
        break;

      case H8_tas:
        if ( code != 0xE0 )
          return 0;
        if ( ua_next_byte() != 0x7B )
          return 0;
        code = ua_next_byte();
        if ( (code & 0x8F) != 0x0C )
          return 0;
        opatHL(cmd.Op1, dt_byte);
        break;

      case H8_trapa:
        code = ua_next_byte();
        if ( (code & 0xC3) != 0x0 )
          return 0;
        cmd.Op1.type = o_imm;
        cmd.Op1.dtyp = dt_byte;
        cmd.Op1.value = code >> 4;
        break;

      case MAP2:
        if ( is_h8sx() )
        {
          switch ( code )
          {
            case 0x01: return h8sx_01();
            case 0x03: return h8sx_03();
            case 0x0A: return h8sx_0A();
            case 0x0F: return h8sx_0F();
            case 0x10: return h8sx_10();
            case 0x11: return h8sx_11();
            case 0x1A: return h8sx_1A();
            case 0x1F: return h8sx_1F();
            case 0x6A: return h8sx_6A();
            case 0x79: return h8sx_79();
            case 0x7A: return h8sx_7A();
          }
        }
        for ( i=0; i < qnumber(map2); i++ )
          if ( map2[i].prefix == code )
            break;
        if ( i >= qnumber(map2) )
          INTERR(10093);
        m = map2[i].map;
        code = ua_next_byte();
        idx = code >> 4;
        continue;

      case MAP3:
        if ( is_h8sx() )
        {
          switch ( code )
          {
            case 0x7C: return h8sx_7C();
            case 0x7D: return h8sx_7D();
            case 0x7E: return h8sx_7E();
            case 0x7F: return h8sx_7F();
          }
        }
        if ( i == -1 )
        {
          code3 = ua_next_byte();
          p3 = (code << 12);
        }
        else
        {
          code3 = code;
          p3 = (map2[i].prefix << 12);
        }
        code = ua_next_byte();
        p3 |= (code3<<4) | (code>>4);
        for ( i=0; i < qnumber(map3); i++ )
          if ( map3[i].prefix == (p3 & ~map3[i].mask) )
            break;
        if ( i == qnumber(map3) )
          return 0;
        m = map3[i].map;
        idx = code & 7;
        continue;

      case MAP4:
        if ( !map4() )
          return 0;
        break;

      case MAP014:
        if ( !map014() )
          return 0;
        break;
    }
    break;
  }

  // m points to the target map entry
  if ( (m->op1 & X) == 0 ) switch ( m->op1 & CMD_SIZE )
  {
    case B: cmd.auxpref = aux_byte; break;
    case W: cmd.auxpref = aux_word; break;
    case L: cmd.auxpref = aux_long; break;
    case V: cmd.auxpref = advanced() ? aux_long : aux_word; break;
  }
  if ( !read_operand(cmd.Op1, m->op1) )
    return 0;
  if ( !read_operand(cmd.Op2, m->op2) )
    return 0;

  if ( code & 0x80 ) switch ( cmd.itype )
  {
    case H8_bor:  cmd.itype = H8_bior;   break;
    case H8_bxor: cmd.itype = H8_bixor;  break;
    case H8_band: cmd.itype = H8_biand;  break;
    case H8_bld:  cmd.itype = H8_bild;   break;
    case H8_bst:  cmd.itype = H8_bist;   break;
    case H8_btst:
    case H8_bset:
    case H8_bnot:
    case H8_bclr:
      if ( cmd.Op1.type == o_imm )
        return 0;
      break;
    case H8_ldc:
      cmd.itype = H8_stc;
      goto SWAP;
    case H8_ldm:
      cmd.itype = H8_stm;
    case H8_mov:
SWAP:
      if ( !noswap )
      {
        swap_Op1_Op2();
        if ( cmd.Op2.type == o_imm )
          return 0;
        if ( cmd.Op2.type == o_phrase && cmd.Op2.phtype == ph_post_inc )
          cmd.Op2.phtype = ph_pre_dec;
      }
      break;
  }
  return cmd.size;
}

//--------------------------------------------------------------------------
inline uint8 hi_ni(uint8 reg)
{
  return (reg >> 4) & 0xF;
}

//--------------------------------------------------------------------------
inline void shift_Op1()
{
  cmd.Op2 = cmd.Op1;
  cmd.Op2.n = 1;
}

//--------------------------------------------------------------------------
static int exit_40()
{
  cmd.itype = H8_bra;
  cmd.Op1.offb = (uchar)cmd.size;
  cmd.Op1.type = o_near;
  cmd.Op1.dtyp = dt_code;

  signed char displ = ua_next_byte();
  if ( is_h8sx() && (displ & 1) != 0 )
    cmd.itype = H8_bras;
  displ &= ~1;
  cmd.Op1.addr = cmd.ip + cmd.size + displ;
  return cmd.size;
}

//--------------------------------------------------------------------------
static int exit_54_56(uint8 rts, uint8 rtsl)
{
  code = ua_next_byte();

  if ( code == 0x70 )
  {
    cmd.itype = rts;
    return cmd.size;
  }
  else if ( is_h8sx() )
  {
    cmd.itype = rtsl;
    uint8 hiNi = (code >> 4) & 0xF;
    if ( hiNi > 3 )
      return 0;
    bool res = hiNi == 0 ?
      read_operand(cmd.Op1, rLL0) :
      op_reglist(cmd.Op1, code & 0x0F, hiNi, true);
    cmd.Op1.dtyp = dt_code;
    return res ? cmd.size : 0;
  }
  return 0;
}

//--------------------------------------------------------------------------
static int exit_59_5D(uint16 jump, uint16 branch)
{
  cmd.itype = jump;
  code = ua_next_byte();
  if ( (code & 0x8F) == 0 )
  { // JMP @ERn
    return op_phrase(cmd.Op1, code >> 4, ph_normal, dt_code) ? cmd.size : 0;
  }
  if ( !is_h8sx() )
    return 0;

  if ( (code & 0x80) != 0 )
  { // JMP @@vec:7
    cmd.Op1.type = o_mem;
    cmd.Op1.memtype = mem_vec7;
    cmd.Op1.dtyp = advanced() ? dt_dword : dt_word;
    cmd.Op1.addr = /* (0x80 + (code & ~0x80)) */ code * (advanced() ? 4 : 2);
    return cmd.size;
  }

  if ( code == 8 )
  { // JMP @aa:32
    return read_operand(cmd.Op1, W | aa32) ? cmd.size : 0;
  }

  cmd.itype = branch;
  cmd.Op1.type = o_pcidx;
  cmd.Op1.dtyp = dt_code;
  regnum_t r;
  switch ( code & 0x0F )
  {
    case 5: // BRA Rn.B
      r = R0L;
      cmd.Op1.szfl |= idx_byte;
      break;
    case 6: // BRA Rn.W
      r = R0;
      cmd.Op1.szfl |= idx_word;
      break;
    case 7: // BRA ERn.L
      r = ER0;
      cmd.Op1.szfl |= idx_long;
      break;
    default:
      return 0;
  }
  cmd.Op1.reg = r + (code>>4);

  return cmd.size;
}

//--------------------------------------------------------------------------
static int exit_7B()
{
  code = ua_next_byte();

  if ( code == 0x5C || code == 0xD4 )
  {
    cmd.itype = H8_eepmov;
    cmd.auxpref = code == 0x5C ? aux_byte : aux_word;
    return ua_next_word() == 0x598F ? cmd.size : 0;
  }
  if ( !is_h8sx() )
    return 0;

  cmd.itype = H8_movmd;
  switch ( code )
  {
    case 0x94:
      cmd.auxpref = aux_byte;
      return cmd.size;
    case 0xA4:
      cmd.auxpref = aux_word;
      return cmd.size;
    case 0xB4:
      cmd.auxpref = aux_long;
      return cmd.size;
    case 0x84:
      cmd.itype = H8_movsd;
      cmd.auxpref = aux_byte;
      return read_operand(cmd.Op1, j16) ? cmd.size : 0;
  }
  return 0;
}

//--------------------------------------------------------------------------
static bool h8sx_010_00dd(void);
static bool h8sx_010_01dd(uint16 postfix);
static bool h8sx_0108(void);
static bool h8sx_0109_010A(op_t &regop, op_t &genop);
static bool h8sx_010D(void);
static bool h8sx_010E(void);
static bool h8sx_ldm(void);
static bool insn_ldc(uint8 byte2, regnum_t reg);
static bool h8sx_01_exr(void);
static bool insn_mac(void);
static bool insn_mova(void);
static int insn_mova_reg(uint8 opcode, uint8 rs, bool is_reg_equal);
static bool insn_tas(void);
static bool insn_or_xor_and(void);
static bool h8sx_01_other(void);

// for insn_sh_neg() and others
#define SET_BYTE  0x0001        // .B insn set
#define SET_WORD  0x0002        // .W insn set
#define SET_LONG  0x0004        // .L insn set
#define SET_BIT_1 0x0010        // btst, bor, bxor, band, bld
#define SET_BIT_2 0x0020        // bclr, bset, bst, bnot

static bool insn_sh_neg(uint8 byte4, uint8 byte5, uint16 mask);
static bool insn_addcmp(uint8 bt);
static bool insn_addcmp_reg(uint8 byte2, uint8 byte3, bool swap, uint16 mask);
static bool insn_addcmp_i3(uint8 byte2, uint8 byte3);
static bool insn_addcmp_i8(uint8 byte4, uint8 byte5);
static bool insn_addx_reg(op_t &x, uint8 byte2, uint8 byte3, uint16 mask, ushort place);
static bool insn_addx_reg_Op1(uint8 byte2, uint8 byte3, uint16 mask, ushort place);
static bool insn_addx_imm(op_t &x, uint8 byte2, uint8 byte3, uint16 mask, bool check_byte3);
static bool insn_addx_i8(uint8 byte4, uint8 byte5);
static bool insn_bit(uint8 byte2, uint8 byte3, uint16 mask);
static bool insn_bra(uint8 byte2, uint8 byte3);
static bool insn_bfld_bfst(uint8 byte2, uint8 byte3, bool is_bfld);
static bool use_leaf_map(const map_t *m, uint8 idx);
static bool op_from_byte(op_t &x, uint8 byte2);
static bool read_1st_op(uint8 byte2, uint8 byte3_hiNi);
static bool op_displ_regidx(op_t &x, uint8 selector, bool is_32, uint8 reg);

//--------------------------------------------------------------------------
static int h8sx_01()
{
  code = ua_next_byte();

  bool success = false;
  switch ( code )
  {
    case 0x00:
    case 0x01:
    case 0x02:
    case 0x03:
      cmd.auxpref = aux_long;
      success = h8sx_010_00dd();
      break;
    case 0x04:
    case 0x05:
    case 0x06:
    case 0x07:
      success = h8sx_010_01dd(aux_long);
      break;
    case 0x08:
      cmd.auxpref = aux_long;
      success = h8sx_0108();
      break;
    case 0x09:
      cmd.auxpref = aux_long;
      success = h8sx_0109_010A(cmd.Op1, cmd.Op2);
      break;
    case 0x0A:
      cmd.auxpref = aux_long;
      success = h8sx_0109_010A(cmd.Op2, cmd.Op1);
      break;
    case 0x0D:
      cmd.auxpref = aux_long;
      success = h8sx_010D();
      break;
    case 0x0E:
      cmd.auxpref = aux_long;
      success = h8sx_010E();
      break;
    case 0x10:
    case 0x20:
    case 0x30:
      success = h8sx_ldm();
      break;
    case 0x40:
      success = insn_ldc(ua_next_byte(), CCR);
      break;
    case 0x41:
      success = h8sx_01_exr();
      break;
    case 0x50:
    case 0x51:
    case 0x52:
    case 0x53:
      cmd.auxpref = aux_word;
      success = h8sx_010_00dd();
      break;
    case 0x54:
    case 0x55:
    case 0x56:
    case 0x57:
      success = h8sx_010_01dd(aux_word);
      break;
    case 0x58:
      cmd.auxpref = aux_word;
      success = h8sx_0108();
      break;
    case 0x59:
      cmd.auxpref = aux_word;
      success = h8sx_0109_010A(cmd.Op1, cmd.Op2);
      break;
    case 0x5A:
      cmd.auxpref = aux_word;
      success = h8sx_0109_010A(cmd.Op2, cmd.Op1);
      break;
    case 0x5D:
      cmd.auxpref = aux_word;
      success = h8sx_010D();
      break;
    case 0x5E:
      cmd.auxpref = aux_word;
      success = h8sx_010E();
      break;
    case 0x60:
      success = insn_mac();
      break;
    case 0x70:
    case 0x71:
    case 0x72:
    case 0x73:
      cmd.auxpref = aux_byte;
      success = h8sx_010_00dd();
      break;
    case 0x74:
    case 0x75:
    case 0x76:
    case 0x77:
      success = h8sx_010_01dd(aux_byte);
      break;
    case 0x78:
      cmd.auxpref = aux_byte;
      success = h8sx_0108();
      break;
    case 0x79:
      cmd.auxpref = aux_byte;
      success = h8sx_0109_010A(cmd.Op1, cmd.Op2);
      break;
    case 0x7A:
      cmd.auxpref = aux_byte;
      success = h8sx_0109_010A(cmd.Op2, cmd.Op1);
      break;
    case 0x7D:
      cmd.auxpref = aux_byte;
      success = h8sx_010D();
      break;
    case 0x5F:
    case 0x7F:
      success = insn_mova();
      break;
    case 0x80:
      cmd.itype = H8_sleep;
      success = true;
      break;
    case 0xA0:
      cmd.itype = H8_clrmac;
      success = true;
      break;
    case 0xE0:
      success = insn_tas();
      break;
    case 0xF0:
      success = insn_or_xor_and();
      break;
    default:
      success = h8sx_01_other();
      break;
  }
  return success ? cmd.size : 0;
}

//--------------------------------------------------------------------------
static int h8sx_03()
{
  code = ua_next_byte();
  switch ( hi_ni(code) )
  {
    case 0:
      cmd.itype = H8_ldc;
      cmd.auxpref = aux_byte;
      read_operand(cmd.Op2, rCCR);
      break;
    case 1:
      cmd.itype = H8_ldc;
      cmd.auxpref = aux_byte;
      read_operand(cmd.Op2, rEXR);
      break;
    case 2:
      cmd.itype = H8_ldmac;
      read_operand(cmd.Op2, rMACH);
      break;
    case 3:
      cmd.itype = H8_ldmac;
      read_operand(cmd.Op2, rMACL);
      break;
    case 6:
      cmd.itype = H8_ldc;
      cmd.auxpref = aux_long;
      read_operand(cmd.Op2, rVBR);
      break;
    case 7:
      cmd.itype = H8_ldc;
      cmd.auxpref = aux_long;
      read_operand(cmd.Op2, rSBR);
      break;
    case 8: // 100x
    case 9: // 100x
      {
        uint8 byte2 = ua_next_byte();
        uint8 byte3 = ua_next_byte();
        if ( byte2 == 0x10 )
          cmd.itype = H8_shll;
        else if ( byte2 == 0x11 )
          cmd.itype = H8_shlr;
        else
          return 0;
        switch ( byte3 >> 4 )
        {
          case 0: cmd.auxpref = aux_byte; cmd.Op1.dtyp = dt_byte; break;
          case 1: cmd.auxpref = aux_word; cmd.Op1.dtyp = dt_word; break;
          case 3: cmd.auxpref = aux_long; cmd.Op1.dtyp = dt_dword; break;
          default: return 0;
        }
        cmd.Op1.type = o_imm;
        cmd.Op1.value = code & 0x1F;
        return op_reg(cmd.Op2, byte3, rL) ? cmd.size : 0;
      }
    default:
      return 0;
  }
  return op_reg(cmd.Op1, code, rL, aux_long /* for ldmac */) ? cmd.size : 0;
}

//--------------------------------------------------------------------------
static int op_imm3_reg(uint8 byte1)
{
  uint8 hiNi = (byte1 >> 4) & 7;
  bool is_word = (byte1 & 0x80) == 0;   // else long

  bool res = true;
  if ( is_word )
  {
    cmd.auxpref = aux_word;
    cmd.Op1.type = o_imm;
    cmd.Op1.dtyp = dt_word;
    cmd.Op1.value = hiNi;
  }
  else
  {
    cmd.auxpref = aux_long;
    if ( byte1 & 8 )
    {
      byte1 &= 7;
      cmd.Op1.type = o_imm;
      cmd.Op1.dtyp = dt_dword;
      cmd.Op1.value = hiNi;
    }
    else
    {
      res = op_reg(cmd.Op1, hiNi, rL);
    }
  }
  return res && op_reg(cmd.Op2, byte1, rL) ? cmd.size : 0;
}

//--------------------------------------------------------------------------
static int h8sx_0A()
{
  code = ua_next_byte();

  if ( hi_ni(code) == 0 )
  {
    cmd.itype = H8_inc;
    cmd.auxpref = aux_byte;
    read_operand(cmd.Op1, B | Cxh);
    return op_reg(cmd.Op2, code, rL) ? cmd.size : 0;
  }

  cmd.itype = H8_add;
  return op_imm3_reg(code);
}

//--------------------------------------------------------------------------
static int h8sx_0F()
{
  code = ua_next_byte();

  if ( hi_ni(code) == 0 )
  {
    cmd.itype = H8_daa;
    return op_reg(cmd.Op1, code, rL, aux_byte) ? cmd.size : 0;
  }

  cmd.itype = H8_mov;
  return op_imm3_reg(code);
}

//--------------------------------------------------------------------------
static int unpack_8bit_shift(const map_t *m, uint16 insn, uint16 insn2)
{
  code = ua_next_byte();
  uint8 hiNi = hi_ni(code);

  if ( hiNi == 3 )
  {
    cmd.itype = insn;
    cmd.auxpref = aux_long;
    if ( !op_reg(cmd.Op1, code & 7, rL) )
      return 0;
    shift_Op1();
    op_imm(cmd.Op1, 4);
    if ( (code & 8) == 0 )
      cmd.Op1.clr_shown();
    return cmd.size;
  }
  else if ( hiNi == 7 )
  {
    cmd.itype = insn;
    cmd.auxpref = aux_long;
    op_imm(cmd.Op1, code & 8 ? 8 : 2);
    return op_reg(cmd.Op2, code & 7, rL) ? cmd.size : 0;
  }
  else if ( hiNi == 0xF )
  {
    cmd.itype = code & 8 ? insn : insn2;
    cmd.auxpref = aux_long;
    op_imm(cmd.Op1, code & 8 ? 16 : 2);
    return op_reg(cmd.Op2, code & 7, rL) ? cmd.size : 0;
  }

  return use_leaf_map(m, hiNi) ? cmd.size : 0;
}

//--------------------------------------------------------------------------
static int h8sx_10()
{
  return unpack_8bit_shift(&map2_10[0], H8_shll, H8_shal);
}

//--------------------------------------------------------------------------
static int h8sx_11()
{
  return unpack_8bit_shift(&map2_11[0], H8_shlr, H8_shar);
}

//--------------------------------------------------------------------------
static int h8sx_1A()
{
  code = ua_next_byte();
  uint8 hiNi = hi_ni(code);

  if ( hiNi == 0 )
  {
    cmd.itype = H8_dec;
    cmd.auxpref = aux_byte;
    read_operand(cmd.Op1, B | Cxh);
    return op_reg(cmd.Op2, code, rL) ? cmd.size : 0;
  }

  cmd.itype = H8_sub;
  return op_imm3_reg(code);
}

//--------------------------------------------------------------------------
static int h8sx_1F()
{
  code = ua_next_byte();
  uint8 hiNi = hi_ni(code);

  if ( hiNi == 0 )
  {
    cmd.itype = H8_das;
    return op_reg(cmd.Op1, code, rL, aux_byte) ? cmd.size : 0;
  }

  cmd.itype = H8_cmp;
  return op_imm3_reg(code);
}

//--------------------------------------------------------------------------
static int h8sx_6A()
{
  code = ua_next_byte();
  uint8 hiNi = (code >> 4) & 0x0F;
  uint8 loNi = code & 0x0F;

  if ( code != 0x10
    && code != 0x15
    && code != 0x18
    && code != 0x30
    && code != 0x35
    && code != 0x38 )
  {
    return use_leaf_map(&map2_6A_h8sx[0], hiNi) ? cmd.size : 0;
  }
  if ( !read_operand(cmd.Op1, B | (hiNi == 1 ? aa16 : aa32)) )
    return 0;

  uint8 byte2 = ua_next_byte();
  uint8 byte3 = ua_next_byte();

  if ( loNi == 5 )
  {
    if ( byte3 & 0x0F )
      return 0;

    cmd.auxpref = aux_byte;
    return op_from_byte(cmd.Op2, byte2)
        && insn_addcmp(byte3) ? cmd.size : 0;
  }
  else if ( loNi == 0 )
  {
    return insn_addcmp_reg(byte2, byte3, false, SET_BYTE)
        || insn_bit(byte2, byte3, SET_BIT_1)
        || insn_bra(byte2, byte3)
        || insn_bfld_bfst(byte2, byte3, true) ? cmd.size : 0;
  }
  // ( loNi == 8 )
  return insn_sh_neg(byte2, byte3, SET_BYTE)
      || insn_addcmp_i8(byte2, byte3)
      || insn_addcmp_reg(byte2, byte3, true, SET_BYTE)
      || insn_bit(byte2, byte3, SET_BIT_2)
      || insn_bra(byte2, byte3)
      || insn_bfld_bfst(byte2, byte3, false) ? cmd.size : 0;
}

//--------------------------------------------------------------------------
static int h8sx_6B()
{
  code = ua_next_byte();
  uint8 hiNi = (code >> 4) & 0x0F;
  uint8 loNi = code & 0x0F;

  if ( code != 0x10
    && code != 0x15
    && code != 0x18
    && code != 0x30
    && code != 0x35
    && code != 0x38 )
    return use_leaf_map(&map2_6B_h8sx[0], hiNi) ? cmd.size : 0;

  if ( !read_operand(cmd.Op1, W | (hiNi == 1 ? aa16 : aa32)) )
    return 0;

  uint8 byte2 = ua_next_byte();
  uint8 byte3 = ua_next_byte();

  if ( loNi == 5 )
  {
    if ( byte3 & 0x0F )
      return 0;

    cmd.auxpref = aux_word;
    return op_from_byte(cmd.Op2, byte2)
        && insn_addcmp(byte3) ? cmd.size : 0;
  }
  else if ( loNi == 0 )
  {
    return insn_addcmp_reg(byte2, byte3, false, SET_WORD) ? cmd.size : 0;
  }
  // ( loNi == 8 )
  return insn_addcmp_reg(byte2, byte3, true, SET_WORD)
      || insn_addcmp_i3(byte2, byte3)
      || insn_sh_neg(byte2, byte3, SET_WORD) ? cmd.size : 0;
}

//--------------------------------------------------------------------------
static int h8sx_78()
{
  code = ua_next_byte();
  uint8 hiNi = hi_ni(code);
  uint8 loNi = code & 0x0F;

  if ( loNi > 9 )
    return 0;

  uint8 byte2 = ua_next_byte();
  uint8 byte3 = ua_next_byte();

  if ( loNi <= 7 )
  {
    if ( byte2 == 0x6A )
    {
      cmd.auxpref = aux_byte;
      if ( hiNi & 8 )
        return 0;
    }
    else if ( byte2 == 0x6B )
    {
      cmd.auxpref = hiNi & 8 ? aux_long : aux_word;
      hiNi &= ~8;
    }
    else
      return 0;

    if ( !op_displ_regidx(cmd.Op1, loNi, true, hiNi) )
      return 0;

    if ( loNi <= 3 )
    {
      cmd.itype = H8_mov;
      op_reg(cmd.Op2, byte3, rL);
      bool swap;
      switch ( byte3 & 0xF0 )
      {
        case 0xA0: swap = true; break;
        case 0x20: swap = false; break;
        default: return 0;
      }
      if ( swap )
        swap_Op1_Op2();
      return cmd.size;
    }
    // 3 < loNi <= 7
    uint8 byte4 = ua_next_byte();
    uint8 byte5 = ua_next_byte();

    if ( byte3 == 0x28 )
    {
      return insn_sh_neg(byte4, byte5, SET_BYTE | SET_WORD | SET_LONG)
          || insn_addcmp_i8(byte4, byte5) ? cmd.size : 0;
    }
    // else if ( byte3 == 0x24 ) doc error?
    else if ( byte3 == 0x2C )
    {
      if ( byte5 & 0x0F )
        return 0;
      return op_from_byte(cmd.Op2, byte4)
          && insn_addcmp(byte5) ? cmd.size : 0;
    }

    return 0;
  } // loNi <= 7

  if ( byte2 == 0x7A )
    return insn_mova_reg(byte3, hi_ni(code), false);

  if ( loNi == 8 )
  {
    if ( byte2 == 0x10 )
      cmd.itype = H8_shll;
    else if ( byte2 == 0x11 )
      cmd.itype = H8_shlr;
    else
      return 0;
    switch ( byte3 & 0xF0 )
    {
      case 0x00: cmd.auxpref = aux_byte; break;
      case 0x10: cmd.auxpref = aux_word; break;
      case 0x30: cmd.auxpref = aux_long; break;
      default: return 0;
    }
    return read_operand(cmd.Op1, rHB)
        && op_reg(cmd.Op2, byte3, rL) ? cmd.size : 0;
  }

  return 0;
}

//--------------------------------------------------------------------------
static int h8sx_79()
{
  code = ua_next_byte();
  uint8 hiNi = (code >> 4) & 0xF;

  if ( hiNi <= 6 )
    return use_leaf_map(&map2_79[0], hiNi) ? cmd.size : 0;

  cmd.itype = H8_mov;
  cmd.auxpref = aux_word;
  if ( !read_operand(cmd.Op1, i16) )
    return 0;

  uint8 byte2 = ua_next_byte();
  uint8 byte3 = ua_next_byte();
  if ( byte3 != 0 )
    return 0;

  return op_from_byte(cmd.Op2, byte2) ? cmd.size : 0;
}

//--------------------------------------------------------------------------
static int h8sx_7A()
{
  code = ua_next_byte();
  uint8 hiNi = (code >> 4) & 0xF;

  if ( hiNi <= 6 )
  {
    if ( hiNi == 0 )
      cmd.itype = H8_mov;
    else if ( !insn_addcmp(code) )
      return 0;
    cmd.auxpref = aux_long;
    ushort op1_imm = code & 8 ? i16 : i32;
    return op_reg(cmd.Op2, code & 7, rL)
        && read_operand(cmd.Op1, op1_imm) ? cmd.size : 0;
  }
  else if ( 8 <= hiNi && hiNi <= 0xD )
  {
    return insn_mova_reg(code, 0, true);
  }
  else
  {
    cmd.itype = H8_mov;
    cmd.auxpref = aux_long;
    ushort op1_imm;
    if ( code == 0x74 )
      op1_imm = i32;
    else if ( code == 0x7C )
      op1_imm = i16;
    else
      return 0;
    if ( !read_operand(cmd.Op1, op1_imm) )
      return 0;

    uint8 byte2 = ua_next_byte();
    uint8 byte3 = ua_next_byte();
    if ( byte3 != 0 )
      return 0;

    return op_from_byte(cmd.Op2, byte2) ? cmd.size : 0;
  }
}

//--------------------------------------------------------------------------
static int h8sx_7C()
{
  code = ua_next_byte();

  bool is_word = (code & 0x80) == 0x80;   // else - byte
  op_phrase(cmd.Op1, (code >> 4) & 0x07, ph_normal);
  uint8 loNi = code & 0x0F;

  uint8 byte2 = ua_next_byte();
  uint8 byte3 = ua_next_byte();

  if ( loNi == 5 )
  {
    cmd.auxpref = is_word ? aux_word : aux_byte;
    return op_from_byte(cmd.Op2, byte2)
        && insn_addcmp(byte3) ? cmd.size : 0;
  }

  if ( loNi == 1 && (byte2 == 0x09 || byte2 == 0x19)
    || loNi == 0 && (byte2 == 0x0E || byte2 == 0x1E) )
  {
    return insn_addx_reg(cmd.Op2, byte2, byte3, SET_BYTE | SET_WORD, rL | zH) ? cmd.size : 0;
  }
  if ( loNi != 0 )
    return 0;

  return insn_addcmp_reg(byte2, byte3, false, is_word ? SET_WORD : SET_BYTE)
      || insn_bit(byte2, byte3, SET_BIT_1)
      || insn_bra(byte2, byte3)
      || insn_bfld_bfst(byte2, byte3, true) ? cmd.size : 0;
}

//--------------------------------------------------------------------------
static int h8sx_7D()
{
  code = ua_next_byte();

  bool is_word = (code & 0x80) == 0x80;   // else - byte
  op_phrase(cmd.Op1, (code >> 4) & 0x07, ph_normal);
  uint8 loNi = code & 0x0F;

  uint8 byte2 = ua_next_byte();
  uint8 byte3 = ua_next_byte();

  if ( loNi == 1 )
  {
    shift_Op1();
    return insn_addx_reg(cmd.Op1, byte2, byte3, SET_WORD, rH | zL)
        || insn_addx_imm(cmd.Op1, byte2, byte3, SET_WORD, true) ? cmd.size : 0;
  }
  if ( loNi != 0 )
    return 0;

  return insn_sh_neg(byte2, byte3, (is_word ? SET_WORD : SET_BYTE))
      || insn_bit(byte2, byte3, SET_BIT_2)
      || (is_word ? false : insn_addx_i8(byte2, byte3))
      || insn_addcmp_reg(byte2, byte3, true, is_word ? SET_WORD : SET_BYTE)
      || (is_word ? false : insn_addcmp_i8(byte2, byte3))
      || insn_bfld_bfst(byte2, byte3, false)
      || insn_addcmp_i3(byte2, byte3)
      || insn_addx_reg_Op1(byte2, byte3, SET_BYTE, rH | zL) ? cmd.size : 0;
}

//--------------------------------------------------------------------------
static int h8sx_7E()
{
  code = ua_next_byte();
  op_aa_8(cmd.Op1, code, dt_byte);

  uint8 byte2 = ua_next_byte();
  uint8 byte3 = ua_next_byte();

  return insn_addcmp_reg(byte2, byte3, false, SET_BYTE)
      || insn_bra(byte2, byte3)
      || insn_bit(byte2, byte3, SET_BIT_1)
      || insn_bfld_bfst(byte2, byte3, true) ? cmd.size : 0;
}

//--------------------------------------------------------------------------
static int h8sx_7F()
{
  code = ua_next_byte();
  op_aa_8(cmd.Op1, code, dt_byte);

  uint8 byte2 = ua_next_byte();
  uint8 byte3 = ua_next_byte();

  return insn_addcmp_reg(byte2, byte3, true, SET_BYTE)
      || insn_addcmp_i8(byte2, byte3)
      || insn_sh_neg(byte2, byte3, SET_BYTE)
      || insn_bit(byte2, byte3, SET_BIT_2)
      || insn_bfld_bfst(byte2, byte3, false) ? cmd.size : 0;
}

//--------------------------------------------------------------------------
static bool h8sx_010_00dd()
{
  uint8 byte2 = ua_next_byte();
  uint8 byte3 = ua_next_byte();

  if ( byte2 == 0x7A && code != 0x01
    || (byte2 == 0x09 || byte2 == 0x19 || byte2 == 0x79) && code != 0x51 )
  {
    return false;
  }

  if ( !op_reg(cmd.Op2, byte3, rL) )
    return false;

  if ( insn_addx_reg(cmd.Op1, byte2, byte3, SET_WORD | SET_LONG, rH) )
    return true;
  if ( insn_addx_imm(cmd.Op1, byte2, byte3, SET_WORD | SET_LONG, false) )
    return true;

  uint8 hiNi = (byte3 >> 4) & 7;
  bool swap = (byte3 & 0x80) != 0;

  if ( code == 0 && byte2 == 0x6D && hiNi == 7 )
  {
    // pop, push
    cmd.itype = swap ? H8_push : H8_pop;
    cmd.Op1 = cmd.Op2; cmd.Op1.n = 0;
    cmd.Op2.type = 0;
    return true;
  }

  cmd.itype = H8_mov;
  if ( !read_1st_op(byte2, hiNi) )
    return false;
  if ( swap )
  {
    swap_Op1_Op2();
    if ( cmd.Op2.type == o_phrase && cmd.Op2.phtype != ph_normal )
      cmd.Op2.phtype ^= 3;  // swap pre- & post-, see h8.hpp
  }

  return true;
}

//--------------------------------------------------------------------------
static bool h8sx_010_01dd(uint16 postfix)
{
  uint8 byte2 = ua_next_byte();
  uint8 byte3 = ua_next_byte();

  if ( byte3 & 0x80 )
    return false;
  uint8 loNi = byte3 & 0xF;
  uint8 hiNi = byte3 >> 4;

  cmd.auxpref = postfix;
  if ( !read_1st_op(byte2, hiNi) )
    return false;

  uint8 byte4 = ua_next_byte();
  uint8 byte5 = ua_next_byte();

  switch ( loNi )
  {
    case 8:
      return postfix == aux_byte
           ? insn_addx_reg_Op1(byte4, byte5, SET_BYTE, rH | zL)
          || insn_addcmp_i8(byte4, byte5)
          || insn_addx_i8(byte4, byte5)
          || insn_sh_neg(byte4, byte5, SET_BYTE)
           : insn_sh_neg(byte4, byte5, postfix == aux_word ? SET_WORD : SET_LONG);

    case 0xC:
      if ( (byte5 & 0x0F) != 0 )
        return false;
      return op_from_byte(cmd.Op2, byte4)
          && insn_addcmp(byte5);

    case 0:
      if ( !(code == 0x76 && byte2 == 0x6C) )
        return false;
      return insn_addx_reg(cmd.Op2, byte4, byte5, SET_BYTE, rL | zH);
    case 1:
      if ( (code != 0x04 || byte2 != 0x69)
        && (code != 0x06 || byte2 != 0x6D)
        && (code != 0x54 || byte2 != 0x69)
        && (code != 0x56 || byte2 != 0x6D) )
      {
        return false;
      }
      return insn_addx_reg(cmd.Op2, byte4, byte5, SET_WORD | SET_LONG, rL | zH);

    case 0xD:
      if ( (code != 0x04 || byte2 != 0x69)
        && (code != 0x06 || byte2 != 0x6D)
        && (code != 0x54 || byte2 != 0x69)
        && (code != 0x56 || byte2 != 0x6D)
        && (code != 0x74 || byte2 != 0x68)
        && (code != 0x76 || byte2 != 0x6C) )
      {
        return false;
      }
      if ( byte5 == 0x10 )
        cmd.itype = H8_addx;
      else if ( byte5 == 0x30 )
        cmd.itype = H8_subx;
      else
        return false;

      if ( !( (byte4 & 0xF8) == 0 || (byte4 & 0xF0) == 0xA0 ) )
        return false;
      op_phrase(cmd.Op2, byte4 & 7, ph_normal);
      if ( (byte4 & 0xF0) == 0xA0 )
        cmd.Op2.phtype = ph_post_dec;
      return cmd.size != 0;

    case 9:
      if ( (code != 0x04 || byte2 != 0x69)
        && (code != 0x06 || byte2 != 0x6D)
        && (code != 0x54 || byte2 != 0x69)
        && (code != 0x56 || byte2 != 0x6D) )
      {
        return false;
      }

      shift_Op1();
      return insn_addx_reg(cmd.Op1, byte4, byte5, SET_BYTE | SET_WORD | SET_LONG, rH | zL)
          || insn_addx_imm(cmd.Op1, byte4, byte5, SET_WORD | SET_LONG, true);
  }

  return false;
}

//--------------------------------------------------------------------------
static bool h8sx_0108()
{
  uint8 byte2 = ua_next_byte();
  uint8 byte3 = ua_next_byte();

  cmd.itype = H8_mov;
  return op_from_byte(cmd.Op1, byte2)
      && op_from_byte(cmd.Op2, byte3);
}

//--------------------------------------------------------------------------
static bool h8sx_0109_010A(op_t &regop, op_t &genop)
{
  uint8 byte2 = ua_next_byte();
  uint8 byte3 = ua_next_byte();

  return insn_addcmp(byte3)
      && op_reg(regop, byte3, rL)
      && op_from_byte(genop, byte2);
}

//--------------------------------------------------------------------------
static bool h8sx_010D()
{
  uint8 byte2 = ua_next_byte();

  cmd.itype = H8_mov;
  return read_operand(cmd.Op1, i8)
      && op_from_byte(cmd.Op2, byte2);
}

//--------------------------------------------------------------------------
static bool h8sx_010E()
{
  uint8 byte2 = ua_next_byte();
  uint8 byte3 = ua_next_byte();

  return op_from_byte(cmd.Op2, byte2)
      && insn_addcmp(byte3)
      && read_operand(cmd.Op1, byte3 & 8 ? i32 : i16);
}

//--------------------------------------------------------------------------
// any register range
static bool h8sx_ldm()
{
  uint8 byte2 = ua_next_byte();
  uint8 byte3 = ua_next_byte();
  if ( byte2 != 0x6D )
    return false;

  uint8 hiNi = byte3 & 0xF0;
  uint8 loNi = byte3 & 0x0F;
  if ( loNi & 8 )
    return false;

  uint8 delta = code >> 4;

  cmd.auxpref = aux_long;
  if ( hiNi == 0x70 )
  {
    cmd.itype = H8_ldm;
    return op_phrase(cmd.Op1, 7, ph_post_inc)
        && op_reglist(cmd.Op2, loNi, delta, true);
  }
  else if ( hiNi == 0xF0 )
  {
    cmd.itype = H8_stm;
    return op_reglist(cmd.Op1, loNi, delta, false)
        && op_phrase(cmd.Op2, 7, ph_pre_dec);
  }
  return false;
}

//--------------------------------------------------------------------------
static bool insn_ldc(uint8 byte2, regnum_t reg)
{
  uint8 byte3 = ua_next_byte();
  uint8 hiNi = (byte3 & 0x70) >> 4;
  bool swap = (byte3 & 0x80) != 0;

  cmd.itype = H8_ldc;
  cmd.auxpref = aux_word;

  cmd.Op2.type = o_reg;
  cmd.Op2.dtyp = dt_word;
  cmd.Op2.reg = reg;

  if ( byte2 == 0x78 )
  {
    if ( byte3 & 0x8F )
      return false;

    uint16 opcode3 = ua_next_word();
    if ( opcode3 == 0x6BA0 )
      swap = true;
    else if ( opcode3 == 0x6B20 )
      swap = false;
    else
      return false;
    code = byte3;
    opdsp32(cmd.Op1, dt_word);
  }
  else
  {
    if ( !read_1st_op(byte2, hiNi) )
      return false;
  }

  if ( swap )
  {
    cmd.itype = H8_stc;
    swap_Op1_Op2();
    if ( cmd.Op2.type == o_phrase && cmd.Op2.phtype != ph_normal )
      cmd.Op2.phtype ^= 3;  // swap pre- & post-, see h8.hpp
  }
  return true;
}

//--------------------------------------------------------------------------
static bool h8sx_01_exr()
{
  uint8 byte2 = ua_next_byte();

  if ( byte2 == 4 )
  {
    cmd.itype = H8_orc;
  }
  else if ( byte2 == 5 )
  {
    cmd.itype = H8_xorc;
  }
  else if ( byte2 == 6 )
  {
    cmd.itype = H8_andc;
  }
  else if ( byte2 == 7 )
  {
    cmd.itype = H8_ldc;
    cmd.auxpref = aux_byte;
  }
  else
  {
    code = 0x40;
    return insn_ldc(byte2, EXR);
  }

  cmd.Op2.type = o_reg;
  cmd.Op2.dtyp = dt_word;
  cmd.Op2.reg = EXR;
  return read_operand(cmd.Op1, i8);
}

//--------------------------------------------------------------------------
static bool insn_mac()
{
  uint8 byte2 = ua_next_byte();
  uint8 byte3 = ua_next_byte();

  if ( byte2 != 0x6D && (byte3 & 0x88) != 0 )
    return 0;

  cmd.itype = H8_mac;
  return op_phrase(cmd.Op1, byte3 >> 4, ph_post_inc)
      && op_phrase(cmd.Op2, byte3 & 0x0F, ph_post_inc);
}

//--------------------------------------------------------------------------
static bool insn_mova_op(uint8 opcode)
{
  switch ( (opcode >> 4) & 0xF )
  {
    case 0x8:
      cmd.itype     = H8_movab;
      cmd.Op1.dtyp  = dt_byte;
      cmd.Op1.szfl |= idx_byte;
      break;
    case 0x9:
      cmd.itype     = H8_movab;
      cmd.Op1.dtyp  = dt_byte;
      cmd.Op1.szfl |= idx_word;
      break;
    case 0xA:
      cmd.itype     = H8_movaw;
      cmd.Op1.dtyp  = dt_word;
      cmd.Op1.szfl |= idx_byte;
      break;
    case 0xB:
      cmd.itype     = H8_movaw;
      cmd.Op1.dtyp  = dt_word;
      cmd.Op1.szfl |= idx_word;
      break;
    case 0xC:
      cmd.itype     = H8_moval;
      cmd.Op1.dtyp  = dt_dword;
      cmd.Op1.szfl |= idx_byte;
      break;
    case 0xD:
      cmd.itype     = H8_moval;
      cmd.Op1.dtyp  = dt_dword;
      cmd.Op1.szfl |= idx_word;
      break;
    default:
      return false;
  }
  return true;
}

//--------------------------------------------------------------------------
static bool insn_mova()
{
  uint8 byte2 = ua_next_byte();
  uint8 byte3 = ua_next_byte();

  if ( !insn_mova_op(byte3) )
    return false;

  op_t ea;
  memset(&ea, 0, sizeof(ea));
  cmd.auxpref = cmd.Op1.szfl & idx_byte ? aux_byte : aux_word;
  if ( !op_from_byte(ea, byte2) )
    return false;
  cmd.auxpref = aux_none;

  (byte3 & 8 ? opdsp32 : opdsp16)(cmd.Op1, cmd.Op1.dtyp);

  cmd.Op1.idxt = ea.type;
  cmd.Op1.offo = ea.offb;
  cmd.Op1.phrase = ea.phrase;
  cmd.Op1.idxdt = ea.phtype;
  cmd.Op1.value = ea.addr;
  cmd.Op1.idxsz = ea.szfl;
  if ( cmd.Op1.idxt == o_displ
    || cmd.Op1.idxt == o_mem )
  {
    cmd.Op1.flags |= OF_OUTER_DISP;
  }

  cmd.Op1.displtype = dt_movaop1;

  cmd.auxpref = aux_long;
  return op_reg(cmd.Op2, byte3 & 7, rL);
}

//--------------------------------------------------------------------------
static int insn_mova_reg(uint8 opcode, uint8 rs, bool is_reg_equal)
{
  if ( !insn_mova_op(opcode) )
    return 0;

  (opcode & 8 ? opdsp16 : opdsp32)(cmd.Op1, cmd.Op1.dtyp);

  cmd.Op1.idxt = o_reg;
  rs = is_reg_equal ? opcode & 7 : rs & 0xF;
  cmd.Op1.reg = (cmd.Op1.szfl & idx_byte ? (is_reg_equal ? R0L : R0H) : R0)
                + (is_reg_equal ? opcode & 7 : rs & 0xF);
  cmd.Op1.idxsz = cmd.Op1.szfl;

  cmd.Op1.displtype = dt_movaop1;
  cmd.Op1.dtyp = dt_dword;

  cmd.auxpref = aux_long;
  return op_reg(cmd.Op2, opcode & 7, rL) ? cmd.size : 0;
}

//--------------------------------------------------------------------------
static bool insn_tas()
{
  uint8 byte2 = ua_next_byte();
  uint8 byte3 = ua_next_byte();

  if ( !(byte2 == 0x7B && (byte3 & 0x8F) == 0x0C) )
    return false;

  cmd.itype = H8_tas;
  return op_phrase(cmd.Op1, byte3 >> 4, ph_normal);
}

//--------------------------------------------------------------------------
static bool insn_or_xor_and()
{
  uint8 byte2 = ua_next_byte();
  uint8 byte3 = ua_next_byte();
  if ( byte3 & 0x88 )
    return false;

  if ( byte2 == 0x64 )
    cmd.itype = H8_or;
  else if ( byte2 == 0x65 )
    cmd.itype = H8_xor;
  else if ( byte2 == 0x66 )
    cmd.itype = H8_and;
  else
    return false;

  cmd.auxpref = aux_long;
  return op_reg(cmd.Op1, byte3, rH)
      && op_reg(cmd.Op2, byte3, rL);
}

//--------------------------------------------------------------------------
static bool h8sx_01_other()
{
  uint8 byte2 = ua_next_byte();
  uint8 byte3 = ua_next_byte();

  uint8 byte1 = code;
  code = byte3;
  switch ( byte1 )
  {
    case 0xC0:
      cmd.itype = H8_mulxs;
      if ( byte2 == 0x50 )
      {
        cmd.auxpref = aux_byte;
        return read_operand(cmd.Op1, rHB)
            && read_operand(cmd.Op2, rLW);
      }
      else if ( byte2 == 0x52 )
      {
        cmd.auxpref = aux_word;
        return read_operand(cmd.Op1, rHW)
            && read_operand(cmd.Op2, rLL0);
      }
      return false;

    case 0xD0:
      cmd.itype = H8_divxs;
      if ( byte2 == 0x51 )
      {
        cmd.auxpref = aux_byte;
        return read_operand(cmd.Op1, rHB)
            && read_operand(cmd.Op2, rLW);
      }
      else if ( byte2 == 0x53 )
      {
        cmd.auxpref = aux_word;
        return read_operand(cmd.Op1, rHW)
            && read_operand(cmd.Op2, rLL0);
      }
      return false;

    case 0xC2:
      cmd.itype = H8_muls;
      if ( byte2 == 0x50 )
      {
        cmd.auxpref = aux_word;
        return read_operand(cmd.Op1, rHW)
            && read_operand(cmd.Op2, rLW);
      }
      else if ( byte2 == 0x52 )
      {
        cmd.auxpref = aux_long;
        return read_operand(cmd.Op1, rHL0)
            && read_operand(cmd.Op2, rLL0);
      }
      return false;

    case 0xD2:
      cmd.itype = H8_divs;
      if ( byte2 == 0x51 )
      {
        cmd.auxpref = aux_word;
        return read_operand(cmd.Op1, rHW)
            && read_operand(cmd.Op2, rLW);
      }
      else if ( byte2 == 0x53 )
      {
        cmd.auxpref = aux_long;
        return read_operand(cmd.Op1, rHL0)
            && read_operand(cmd.Op2, rLL0);
      }
      return false;

    case 0xC3:
      if ( byte2 != 0x52 )
        return false;
      cmd.itype = H8_mulsu;
      cmd.auxpref = aux_long;
      return read_operand(cmd.Op1, rHL0)
          && read_operand(cmd.Op2, rLL0);

    case 0xC4:
      cmd.itype = H8_mulxs;
      if ( byte2 == 0x50 )
      {
        cmd.auxpref = aux_byte;
        return read_operand(cmd.Op1, B | i4H)
            && read_operand(cmd.Op2, rLW);
      }
      else if ( byte2 == 0x52 )
      {
        cmd.auxpref = aux_word;
        return read_operand(cmd.Op1, W | i4H)
            && read_operand(cmd.Op2, rLL0);
      }
      return false;

    case 0xD4:
      cmd.itype = H8_divxs;
      if ( byte2 == 0x51 )
      {
        cmd.auxpref = aux_byte;
        return read_operand(cmd.Op1, B | i4H)
            && read_operand(cmd.Op2, rLW);
      }
      else if ( byte2 == 0x53 )
      {
        cmd.auxpref = aux_word;
        return read_operand(cmd.Op1, W | i4H)
            && read_operand(cmd.Op2, rLL0);
      }
      return false;

    case 0xC6:
      cmd.itype = H8_muls;
      if ( byte2 == 0x50 )
      {
        cmd.auxpref = aux_word;
        return read_operand(cmd.Op1, W | i4H)
            && read_operand(cmd.Op2, rLW);
      }
      else if ( byte2 == 0x52 )
      {
        cmd.auxpref = aux_long;
        return read_operand(cmd.Op1, L | i4H)
            && read_operand(cmd.Op2, rLL0);
      }
      return false;

    case 0xD6:
      cmd.itype = H8_divs;
      if ( byte2 == 0x51 )
      {
        cmd.auxpref = aux_word;
        return read_operand(cmd.Op1, W | i4H)
            && read_operand(cmd.Op2, rLW);
      }
      else if ( byte2 == 0x53 )
      {
        cmd.auxpref = aux_long;
        return read_operand(cmd.Op1, L | i4H)
            && read_operand(cmd.Op2, rLL0);
      }
      return false;

    case 0xC7:
      if ( byte2 != 0x52 )
        return false;
      cmd.itype = H8_mulsu;
      cmd.auxpref = aux_long;
      return read_operand(cmd.Op1, L | i4H)
          && read_operand(cmd.Op2, rLL0);

    case 0xCA:
      cmd.itype = H8_mulu;
      if ( byte2 == 0x50 )
      {
        cmd.auxpref = aux_word;
        return read_operand(cmd.Op1, rHW)
            && read_operand(cmd.Op2, rLW);
      }
      else if ( byte2 == 0x52 )
      {
        cmd.auxpref = aux_long;
        return read_operand(cmd.Op1, rHL0)
            && read_operand(cmd.Op2, rLL0);
      }
      return false;

    case 0xDA:
      cmd.itype = H8_divu;
      if ( byte2 == 0x51 )
      {
        cmd.auxpref = aux_word;
        return read_operand(cmd.Op1, rHW)
            && read_operand(cmd.Op2, rLW);
      }
      else if ( byte2 == 0x53 )
      {
        cmd.auxpref = aux_long;
        return read_operand(cmd.Op1, rHL0)
            && read_operand(cmd.Op2, rLL0);
      }
      return false;

    case 0xCB:
      if ( byte2 != 0x52 )
        return false;
      cmd.itype = H8_muluu;
      cmd.auxpref = aux_long;
      return read_operand(cmd.Op1, rHL0)
          && read_operand(cmd.Op2, rLL0);

    case 0xCC:
      cmd.itype = H8_mulxu;
      if ( byte2 == 0x50 )
      {
        cmd.auxpref = aux_byte;
        return read_operand(cmd.Op1, B | i4H)
            && read_operand(cmd.Op2, rLW);
      }
      else if ( byte2 == 0x52 )
      {
        cmd.auxpref = aux_word;
        return read_operand(cmd.Op1, W | i4H)
            && read_operand(cmd.Op2, rLL0);
      }
      return false;

    case 0xDC:
      cmd.itype = H8_divxu;
      if ( byte2 == 0x51 )
      {
        cmd.auxpref = aux_byte;
        return read_operand(cmd.Op1, B | i4H)
            && read_operand(cmd.Op2, rLW);
      }
      else if ( byte2 == 0x53 )
      {
        cmd.auxpref = aux_word;
        return read_operand(cmd.Op1, W | i4H)
            && read_operand(cmd.Op2, rLL0);
      }
      return false;

    case 0xCE:
      cmd.itype = H8_mulu;
      if ( byte2 == 0x50 )
      {
        cmd.auxpref = aux_word;
        return read_operand(cmd.Op1, W | i4H)
            && read_operand(cmd.Op2, rLW);
      }
      else if ( byte2 == 0x52 )
      {
        cmd.auxpref = aux_long;
        return read_operand(cmd.Op1, L | i4H)
            && read_operand(cmd.Op2, rLL0);
      }
      return false;

    case 0xDE:
      cmd.itype = H8_divu;
      if ( byte2 == 0x51 )
      {
        cmd.auxpref = aux_word;
        return read_operand(cmd.Op1, W | i4H)
            && read_operand(cmd.Op2, rLW);
      }
      else if ( byte2 == 0x53 )
      {
        cmd.auxpref = aux_long;
        return read_operand(cmd.Op1, L | i4H)
            && read_operand(cmd.Op2, rLL0);
      }
      return false;

    case 0xCF:
      if ( byte2 != 0x52 )
        return false;
      cmd.itype = H8_muluu;
      cmd.auxpref = aux_long;
      return read_operand(cmd.Op1, L | i4H)
          && read_operand(cmd.Op2, rLL0);
  }
  return false;
}

//--------------------------------------------------------------------------
inline char dtyp_by_auxpref()
{
  CASSERT(aux_byte == dt_byte + 1 && aux_word == dt_word + 1 && aux_long == dt_dword + 1);
  // x.dtyp = cmd.auxpref == aux_long ? dt_dword : cmd.auxpref == aux_word ? dt_word : dt_byte;
  return cmd.auxpref - 1;
}

//--------------------------------------------------------------------------
static bool sh_ops_imm(nameNum insn, uint16 ap, uint8 v, bool shown)
{
  cmd.itype = insn;
  cmd.auxpref = ap;
  shift_Op1();
  cmd.Op1.type = o_imm;
  cmd.Op1.dtyp = dtyp_by_auxpref();
  cmd.Op1.value = v;
  if ( !shown )
    cmd.Op1.clr_shown();
  return true;
}

//--------------------------------------------------------------------------
#define M1    if ( !(SET_BYTE & mask) ) return false
#define M2    if ( !(SET_WORD & mask) ) return false
#define M3    if ( !(SET_LONG & mask) ) return false
#define MB1   if ( !(SET_BIT_1 & mask) ) return false
#define MB2   if ( !(SET_BIT_2 & mask) ) return false

//--------------------------------------------------------------------------
static bool insn_sh_neg(uint8 byte4, uint8 byte5, uint16 mask)
{
  uint16 opcode2 = (byte4 << 8) | byte5;
  switch ( opcode2 )
  {
    case 0x1000: M1; return sh_ops_imm(H8_shll, aux_byte, 1, false); // SHLL.B
    case 0x1040: M1; return sh_ops_imm(H8_shll, aux_byte, 2, true ); // SHLL.B #2
    case 0x10A0: M1; return sh_ops_imm(H8_shll, aux_byte, 4, true ); // SHLL.B #4
    case 0x1010: M2; return sh_ops_imm(H8_shll, aux_word, 1, false); // SHLL.W
    case 0x1050: M2; return sh_ops_imm(H8_shll, aux_word, 2, true ); // SHLL.W #2
    case 0x1020: M2; return sh_ops_imm(H8_shll, aux_word, 4, true ); // SHLL.W #4
    case 0x1060: M2; return sh_ops_imm(H8_shll, aux_word, 8, true ); // SHLL.W #8
    case 0x1030: M3; return sh_ops_imm(H8_shll, aux_long, 1, false); // SHLL.L
    case 0x1070: M3; return sh_ops_imm(H8_shll, aux_long, 2, true ); // SHLL.L #2
    case 0x1038: M3; return sh_ops_imm(H8_shll, aux_long, 4, true ); // SHLL.L #4
    case 0x1078: M3; return sh_ops_imm(H8_shll, aux_long, 8, true ); // SHLL.L #8
    case 0x10F8: M3; return sh_ops_imm(H8_shll, aux_long, 16, true); // SHLL.L #16

    case 0x1100: M1; return sh_ops_imm(H8_shlr, aux_byte, 1, false); // SHLR.B
    case 0x1140: M1; return sh_ops_imm(H8_shlr, aux_byte, 2, true ); // SHLR.B #2
    case 0x11A0: M1; return sh_ops_imm(H8_shlr, aux_byte, 4, true ); // SHLR.B #4
    case 0x1110: M2; return sh_ops_imm(H8_shlr, aux_word, 1, false); // SHLR.W
    case 0x1150: M2; return sh_ops_imm(H8_shlr, aux_word, 2, true ); // SHLR.W #2
    case 0x1120: M2; return sh_ops_imm(H8_shlr, aux_word, 4, true ); // SHLR.W #4
    case 0x1160: M2; return sh_ops_imm(H8_shlr, aux_word, 8, true ); // SHLR.W #8
    case 0x1130: M3; return sh_ops_imm(H8_shlr, aux_long, 1, false); // SHLR.L
    case 0x1170: M3; return sh_ops_imm(H8_shlr, aux_long, 2, true ); // SHLR.L #2
    case 0x1138: M3; return sh_ops_imm(H8_shlr, aux_long, 4, true ); // SHLR.L #4
    case 0x1178: M3; return sh_ops_imm(H8_shlr, aux_long, 8, true ); // SHLR.L #8
    case 0x11F8: M3; return sh_ops_imm(H8_shlr, aux_long, 16, true); // SHLR.L #16

    case 0x1080: M1; return sh_ops_imm(H8_shal, aux_byte, 1, false); // SHAL.B
    case 0x10C0: M1; return sh_ops_imm(H8_shal, aux_byte, 2, true ); // SHAL.B #2
    case 0x1090: M2; return sh_ops_imm(H8_shal, aux_word, 1, false); // SHAL.W
    case 0x10D0: M2; return sh_ops_imm(H8_shal, aux_word, 2, true ); // SHAL.W #2
    case 0x10B0: M3; return sh_ops_imm(H8_shal, aux_long, 1, false); // SHAL.L
    case 0x10F0: M3; return sh_ops_imm(H8_shal, aux_long, 2, true ); // SHAL.L #2

    case 0x1180: M1; return sh_ops_imm(H8_shar, aux_byte, 1, false); // SHAR.B
    case 0x11C0: M1; return sh_ops_imm(H8_shar, aux_byte, 2, true ); // SHAR.B #2
    case 0x1190: M2; return sh_ops_imm(H8_shar, aux_word, 1, false); // SHAR.W
    case 0x11D0: M2; return sh_ops_imm(H8_shar, aux_word, 2, true ); // SHAR.W #2
    case 0x11B0: M3; return sh_ops_imm(H8_shar, aux_long, 1, false); // SHAR.L
    case 0x11F0: M3; return sh_ops_imm(H8_shar, aux_long, 2, true ); // SHAR.L #2

    case 0x1280: M1; return sh_ops_imm(H8_rotl, aux_byte, 1, false); // ROTL.B
    case 0x12C0: M1; return sh_ops_imm(H8_rotl, aux_byte, 2, true ); // ROTL.B #2
    case 0x1290: M2; return sh_ops_imm(H8_rotl, aux_word, 1, false); // ROTL.W
    case 0x12D0: M2; return sh_ops_imm(H8_rotl, aux_word, 2, true ); // ROTL.W #2
    case 0x12B0: M3; return sh_ops_imm(H8_rotl, aux_long, 1, false); // ROTL.L
    case 0x12F0: M3; return sh_ops_imm(H8_rotl, aux_long, 2, true ); // ROTL.L #2

    case 0x1380: M1; return sh_ops_imm(H8_rotr, aux_byte, 1, false); // ROTR.B
    case 0x13C0: M1; return sh_ops_imm(H8_rotr, aux_byte, 2, true ); // ROTR.B #2
    case 0x1390: M2; return sh_ops_imm(H8_rotr, aux_word, 1, false); // ROTR.W
    case 0x13D0: M2; return sh_ops_imm(H8_rotr, aux_word, 2, true ); // ROTR.W #2
    case 0x13B0: M3; return sh_ops_imm(H8_rotr, aux_long, 1, false); // ROTR.L
    case 0x13F0: M3; return sh_ops_imm(H8_rotr, aux_long, 2, true ); // ROTR.L #2

    case 0x1200: M1; return sh_ops_imm(H8_rotxl, aux_byte, 1, false); // ROTXL.B
    case 0x1240: M1; return sh_ops_imm(H8_rotxl, aux_byte, 2, true ); // ROTXL.B #2
    case 0x1210: M2; return sh_ops_imm(H8_rotxl, aux_word, 1, false); // ROTXL.W
    case 0x1250: M2; return sh_ops_imm(H8_rotxl, aux_word, 2, true ); // ROTXL.W #2
    case 0x1230: M3; return sh_ops_imm(H8_rotxl, aux_long, 1, false); // ROTXL.L
    case 0x1270: M3; return sh_ops_imm(H8_rotxl, aux_long, 2, true ); // ROTXL.L #2

    case 0x1300: M1; return sh_ops_imm(H8_rotxr, aux_byte, 1, false); // ROTXR.B
    case 0x1340: M1; return sh_ops_imm(H8_rotxr, aux_byte, 2, true ); // ROTXR.B #2
    case 0x1310: M2; return sh_ops_imm(H8_rotxr, aux_word, 1, false); // ROTXR.W
    case 0x1350: M2; return sh_ops_imm(H8_rotxr, aux_word, 2, true ); // ROTXR.W #2
    case 0x1330: M3; return sh_ops_imm(H8_rotxr, aux_long, 1, false); // ROTXR.L
    case 0x1370: M3; return sh_ops_imm(H8_rotxr, aux_long, 2, true ); // ROTXR.L #2

    case 0x17D0: M2; return sh_ops_imm(H8_exts, aux_word, 1, false); // EXTS.W
    case 0x17F0: M3; return sh_ops_imm(H8_exts, aux_long, 1, false); // EXTS.L
    case 0x17E0: M3; return sh_ops_imm(H8_exts, aux_long, 2, true ); // EXTS.L #2

    case 0x1750: M2; return sh_ops_imm(H8_extu, aux_word, 1, false); // EXTU.W
    case 0x1770: M3; return sh_ops_imm(H8_extu, aux_long, 1, false); // EXTU.L
    case 0x1760: M3; return sh_ops_imm(H8_extu, aux_long, 2, true ); // EXTU.L #2

    case 0x1700: M1; cmd.itype = H8_not; cmd.auxpref = aux_byte; return true; // NOT.B
    case 0x1710: M2; cmd.itype = H8_not; cmd.auxpref = aux_word; return true; // NOT.W
    case 0x1730: M3; cmd.itype = H8_not; cmd.auxpref = aux_long; return true; // NOT.L

    case 0x1780: M1; cmd.itype = H8_neg; cmd.auxpref = aux_byte; return true; // NEG.B
    case 0x1790: M2; cmd.itype = H8_neg; cmd.auxpref = aux_word; return true; // NEG.W
    case 0x17B0: M3; cmd.itype = H8_neg; cmd.auxpref = aux_long; return true; // NEG.L
  }

  return false;
}

//--------------------------------------------------------------------------
static bool insn_addcmp(uint8 bt)
{
  switch ( bt >> 4 )
  {
    case 0x1: cmd.itype = H8_add; break;
    case 0x2: cmd.itype = H8_cmp; break;
    case 0x3: cmd.itype = H8_sub; break;
    case 0x4: cmd.itype = H8_or ; break;
    case 0x5: cmd.itype = H8_xor; break;
    case 0x6: cmd.itype = H8_and; break;
    default: return false;
  }
  return true;
}

//--------------------------------------------------------------------------
static bool insn_addcmp_reg(uint8 byte2, uint8 byte3, bool swap, uint16 mask)
{
  switch ( byte2 )
  {
    case 0x08: M1; cmd.auxpref = aux_byte; cmd.itype = H8_add; break; // ADD.B
    case 0x09: M2; cmd.auxpref = aux_word; cmd.itype = H8_add; break; // ADD.W
    case 0x18: M1; cmd.auxpref = aux_byte; cmd.itype = H8_sub; break; // SUB.B
    case 0x19: M2; cmd.auxpref = aux_word; cmd.itype = H8_sub; break; // SUB.W
    case 0x1C: M1; cmd.auxpref = aux_byte; cmd.itype = H8_cmp; break; // CMP.B
    case 0x1D: M2; cmd.auxpref = aux_word; cmd.itype = H8_cmp; break; // CMP.W
    case 0x14: M1; cmd.auxpref = aux_byte; cmd.itype = H8_or ; break; // OR.B
    case 0x64: M2; cmd.auxpref = aux_word; cmd.itype = H8_or ; break; // OR.W
    case 0x15: M1; cmd.auxpref = aux_byte; cmd.itype = H8_xor; break; // XOR.B
    case 0x65: M2; cmd.auxpref = aux_word; cmd.itype = H8_xor; break; // XOR.W
    case 0x16: M1; cmd.auxpref = aux_byte; cmd.itype = H8_and; break; // AND.B
    case 0x66: M2; cmd.auxpref = aux_word; cmd.itype = H8_and; break; // AND.W
    default: return false;
  }

  bool res;
  if ( swap )
  {
    shift_Op1();
    res = op_reg(cmd.Op1, byte3, rH | zL);
  }
  else
  {
    res = op_reg(cmd.Op2, byte3, rL | zH);
  }
  return res;
}

//--------------------------------------------------------------------------
static bool insn_addcmp_i3(uint8 byte2, uint8 byte3)
{
  if ( byte3 & 0x8F )
    return 0;

  switch ( byte2 )
  {
    case 0x0A: cmd.auxpref = aux_word; cmd.itype = H8_add; break; // ADD.W #xx:3
    case 0x1A: cmd.auxpref = aux_word; cmd.itype = H8_sub; break; // SUB.W #xx:3
    case 0x1F: cmd.auxpref = aux_word; cmd.itype = H8_cmp; break; // CMP.W #xx:3
    default: return false;
  }

  shift_Op1();
  op_imm_3(cmd.Op1, byte3);
  return true;
}

//--------------------------------------------------------------------------
static bool insn_addcmp_i8(uint8 byte4, uint8 byte5)
{
  switch ( byte4 )
  {
    case 0x80: cmd.itype = H8_add; break;
    case 0xA0: cmd.itype = H8_cmp; break;
    case 0xA1: cmd.itype = H8_sub; break;
    case 0xC0: cmd.itype = H8_or;  break;
    case 0xD0: cmd.itype = H8_xor; break;
    case 0xE0: cmd.itype = H8_and; break;
    default: return false;
  }

  shift_Op1();

  cmd.auxpref = aux_byte;
  cmd.Op1.type  = o_imm;
  cmd.Op1.dtyp  = dt_byte;
  cmd.Op1.value = byte5;
  return true;
}

//--------------------------------------------------------------------------
static bool insn_addx_reg(op_t &x, uint8 byte2, uint8 byte3, uint16 mask, ushort place)
{
  switch ( byte2 )
  {
    case 0x0E: // ADDX.B
      M1;
      cmd.auxpref = aux_byte;
      cmd.itype = H8_addx;
      break;
    case 0x1E: // SUBX.B
      M1;
      cmd.auxpref = aux_byte;
      cmd.itype = H8_subx;
      break;

    case 0x09: // ADDX.W
      M2;
      cmd.auxpref = aux_word;
      cmd.itype = H8_addx;
      break;
    case 0x19: // SUBX.W
      M2;
      cmd.auxpref = aux_word;
      cmd.itype = H8_subx;
      break;

    case 0x0A: // ADDX.L
      cmd.itype = H8_addx;
      goto ADDXL;
    case 0x1A: // SUBX.L
      cmd.itype = H8_subx;
ADDXL:
      M3;
      if ( (byte3 & 0x80) != 0x80 )
        return false;
      byte3 &= ~0x80;
      cmd.auxpref = aux_long;
      break;

    default:
      return false;
  }
  return op_reg(x, byte3, place);
}

//--------------------------------------------------------------------------
static bool insn_addx_reg_Op1(uint8 byte2, uint8 byte3, uint16 mask, ushort place)
{
  op_t op;
  memset(&op, 0, sizeof(op));
  if ( !insn_addx_reg(op, byte2, byte3, mask, place ) )
    return false;
  shift_Op1();
  cmd.Op1.type = op.type;
  cmd.Op1.reg = op.reg;
  cmd.Op1.dtyp = op.dtyp;
  return true;
}

//--------------------------------------------------------------------------
static bool insn_addx_imm(op_t &x, uint8 byte2, uint8 byte3, uint16 mask, bool check_byte3)
{
  if ( check_byte3 && (byte3 & 0x0F) != 0 )
    return false;

  switch ( byte3 & 0xF0 )
  {
    case 0x10:
      cmd.itype = H8_addx;
      break;
    case 0x30:
      cmd.itype = H8_subx;
      break;
    default:
      return false;
  }

  switch ( byte2 )
  {
    case 0x79:  // .W
      M2;
      cmd.auxpref = aux_word;
      return read_operand(x, i16);
    case 0x7A:  // .L
      M3;
      cmd.auxpref = aux_long;
      return read_operand(x, i32);
  }
  return false;
}

//--------------------------------------------------------------------------
static bool insn_addx_i8(uint8 byte4, uint8 byte5)
{
  switch ( byte4 )
  {
    case 0x90:
      cmd.itype = H8_addx;
      break;
    case 0xB0:
      cmd.itype = H8_subx;
      break;
    default:
      return false;
  }

  shift_Op1();

  cmd.auxpref = aux_byte;
  cmd.Op1.type  = o_imm;
  cmd.Op1.dtyp  = dt_byte;
  cmd.Op1.value = byte5;
  return true;
}

//--------------------------------------------------------------------------
static bool insn_bit_reg(uint8 byte2, uint8 byte3, uint16 mask)
{
  switch ( byte2 )
  {
    case 0x60:
      MB2;
      switch ( byte3 & 0x0F )
      {
        case 0: cmd.itype = H8_bset;   break;
        case 6: cmd.itype = H8_bsetne; break;
        case 7: cmd.itype = H8_bseteq; break;
        default: return false;
      }
      break;
    case 0x61:
      MB2;
      if ( byte3 & 0x0F )
        return false;
      cmd.itype = H8_bnot;
      break;
    case 0x62:
      MB2;
      switch ( byte3 & 0x0F )
      {
        case 0: cmd.itype = H8_bclr;   break;
        case 6: cmd.itype = H8_bclrne; break;
        case 7: cmd.itype = H8_bclreq; break;
        default: return false;
      }
      break;

    case 0x63:
      MB1;
      if ( byte3 & 0x0F )
        return false;
      cmd.itype = H8_btst;
      break;
    default:
      return false;
  }

  shift_Op1();
  return op_reg(cmd.Op1, byte3, rH, aux_byte);
}

//--------------------------------------------------------------------------
static bool insn_bit_i3(uint8 byte2, uint8 byte3, uint16 mask)
{
  switch ( byte2 )
  {
    case 0x67:
      MB2;
      switch ( byte3 & 0x8F )
      {
        case 0x00: cmd.itype = H8_bst;   break;
        case 0x07: cmd.itype = H8_bstz;  break;
        case 0x80: cmd.itype = H8_bist;  break;
        case 0x87: cmd.itype = H8_bistz; break;
        default: return false;
      }
      break;
    case 0x70:
      MB2;
      switch ( byte3 & 0x8F )
      {
        case 0x00: cmd.itype = H8_bset;   break;
        case 0x06: cmd.itype = H8_bsetne; break;
        case 0x07: cmd.itype = H8_bseteq; break;
        default: return false;
      }
      break;
    case 0x71:
      MB2;
      if ( byte3 & 0x8F )
        return false;
      cmd.itype = H8_bnot;
      break;
    case 0x72:
      MB2;
      switch ( byte3 & 0x8F )
      {
        case 0x00: cmd.itype = H8_bclr;   break;
        case 0x06: cmd.itype = H8_bclrne; break;
        case 0x07: cmd.itype = H8_bclreq; break;
        default: return false;
      }
      break;

    case 0x73:
      MB1;
      if ( byte3 & 0x8F )
        return false;
      cmd.itype = H8_btst;
      break;
    case 0x74:
      MB1;
      if ( byte3 & 0x0F )
        return false;
      cmd.itype = byte3 & 0x80 ? H8_bior : H8_bor;
      break;
    case 0x75:
      MB1;
      if ( byte3 & 0x0F )
        return false;
      cmd.itype = byte3 & 0x80 ? H8_bixor : H8_bxor;
      break;
    case 0x76:
      MB1;
      if ( byte3 & 0x0F )
        return false;
      cmd.itype = byte3 & 0x80 ? H8_biand : H8_band;
      break;
    case 0x77:
      MB1;
      if ( byte3 & 0x0F )
        return false;
      cmd.itype = byte3 & 0x80 ? H8_bild : H8_bld;
      break;
    default:
      return false;
  }
  shift_Op1();
  op_imm_3(cmd.Op1, byte3);
  return true;
}

//--------------------------------------------------------------------------
static bool insn_bit(uint8 byte2, uint8 byte3, uint16 mask)
{
  return insn_bit_reg(byte2, byte3, mask) || insn_bit_i3(byte2, byte3, mask);
}

//--------------------------------------------------------------------------
static bool insn_bra(uint8 byte2, uint8 byte3)
{
  if ( (byte2 & 0xF0) == 0x40 )
  {
    if ( byte3 & 1 )
      return 0;
    cmd.itype = byte2 & 8 ? H8_brabs : H8_brabc;
    shift_Op1();
    op_imm_8(cmd.Op1, byte2 & 7);
    cmd.Op3.type = o_near;
    cmd.Op3.dtyp = dt_code;
    cmd.Op3.offb = (uchar)cmd.size - 1;
    signed char disp = byte3;
    cmd.Op3.addr = cmd.ip + cmd.size + disp;
    cmd.Op3.addr &= ~1;
    return cmd.size != 0;
  }

  if ( byte2 == 0x58 )
    cmd.itype = byte3 & 0x80 ? H8_brabs : H8_brabc;
  else if ( byte2 == 0x5C )
    cmd.itype = byte3 & 0x80 ? H8_bsrbs : H8_bsrbc;
  else
    return false;

  if ( byte3 & 0x0F )
    return false;
  shift_Op1();
  op_imm_8(cmd.Op1, (byte3 >> 4) & 7);
  return read_operand(cmd.Op3, j16);
}

//--------------------------------------------------------------------------
static bool insn_bfld_bfst(uint8 byte2, uint8 byte3, bool is_bfld)
{
  if ( (byte2 & 0xF0) != 0xF0 )
    return false;

  if ( is_bfld )
  {
    cmd.itype = H8_bfld;
    shift_Op1();
    op_imm_8(cmd.Op1, byte3);
    code = byte2;
    return read_operand(cmd.Op3, rLB);
  }
  else
  {
    cmd.itype = H8_bfst;
    cmd.Op3 = cmd.Op1; cmd.Op3.n = 2;
    code = byte2;
    op_imm_8(cmd.Op2, byte3);
    return read_operand(cmd.Op1, rLB);
  }
}

//--------------------------------------------------------------------------
static bool use_leaf_map(const map_t *m, uint8 idx)
{
  m += idx;
  if ( (m->proc & ptype) == 0
    || m->itype == H8_null
    || m->itype >= H8_last )
  {
    return false;
  }
  cmd.itype = m->itype;
  if ( (m->op1 & X) == 0 ) switch ( m->op1 & CMD_SIZE )
  {
    case B: cmd.auxpref = aux_byte; break;
    case W: cmd.auxpref = aux_word; break;
    case L: cmd.auxpref = aux_long; break;
    case V: cmd.auxpref = advanced() ? aux_long : aux_word; break;
  }

  return read_operand(cmd.Op1, m->op1)
      && read_operand(cmd.Op2, m->op2);
}

//--------------------------------------------------------------------------
static bool op_from_byte(op_t &x, uint8 byte2)
{
#ifndef NDEBUG
  QASSERT(10001, cmd.auxpref != aux_none);
#endif

  uint8 hiNi = hi_ni(byte2);
  uint8 loNi = byte2 & 0x0F;

  switch ( hiNi )
  {
    case 0x0:
    case 0x1:
    case 0x2:
    case 0x3:
      return op_phrase_displ2(x, loNi, hiNi);
    case 0x4:
      return loNi == 0 ? read_operand(x, aa16)
           : loNi == 8 ? read_operand(x, aa32) : false;
    case 0x8:
    case 0x9:
    case 0xA:
    case 0xB:
      return op_phrase_prepost(x, loNi, hiNi);
    case 0xC:
    case 0xD:
    case 0xE:
    case 0xF:
      return op_displ_regidx(x, hiNi, (loNi & 8) != 0, loNi & ~8);
  }
  return false;
}

//--------------------------------------------------------------------------
static bool read_1st_op(uint8 byte2, uint8 byte3_hiNi)
{
  uint8 code_2bits = code & 3;
  switch ( byte2 )
  {
    case 0x68:
      return 0x71 <= code && code <= 0x77
           ? op_phrase_displ2(cmd.Op1, byte3_hiNi, code_2bits) : false;
    case 0x69:
      return op_phrase_displ2(cmd.Op1, byte3_hiNi, code_2bits);
    case 0x6B:
      if ( code_2bits != 0 )
        return false;
      if ( !(byte3_hiNi == 0 || byte3_hiNi == 2) )
        return false;
      return read_operand(cmd.Op1, byte3_hiNi == 0 ? aa16 | L : aa32 | L);
    case 0x6C:
      if ( (code & 0xF0) != 0x70 )
        return false;
      // no break;
    case 0x6D:
      return op_phrase_prepost(cmd.Op1, byte3_hiNi, code_2bits);
    case 0x6E:
      if ( (code & 0xF0) != 0x70 )
        return false;
      // no break;
    case 0x6F:
      return op_displ_regidx(cmd.Op1, code, false, byte3_hiNi);
  }
  return false;
}

//--------------------------------------------------------------------------
static bool op_reg(op_t &x, uint8 reg, ushort place, uint16 aux_assumed)
{
#ifndef NDEBUG
  QASSERT(10001, (place & OPTYPE) == rH || (place & OPTYPE) == rL);
  QASSERT(10002, cmd.auxpref != aux_none || aux_assumed != aux_none);
#endif

  static const regnum_t base_reg[] = { regnum_t(-1), R0H, R0, ER0 };

  if ( place & zH && reg & 0xF0
    || place & zL && reg & 0x0F )
  {
    return false;
  }

  if ( (place & OPTYPE) == rH )
    reg >>= 4;
  reg &= 0x0F;
  if ( cmd.auxpref == aux_long && reg & 8 )
    return false;

  x.type = o_reg;
  if ( cmd.auxpref != aux_none )
  {
    x.reg  = base_reg[cmd.auxpref] + reg;
    x.dtyp = dtyp_by_auxpref();
  }
  else
  {
    x.reg = base_reg[aux_assumed] + reg;
    x.dtyp = aux_assumed - 1;
  }
  return true;
}

//--------------------------------------------------------------------------
static bool op_phrase(op_t &x, uint8 reg, int pht, char dtyp)
{
#ifndef NDEBUG
  QASSERT(10003, cmd.auxpref != aux_none || dtyp != aux_byte);
#endif
  if ( reg & 8 )
   return false;
  x.type = o_phrase;
  x.dtyp = cmd.auxpref != aux_none ? dtyp_by_auxpref() : dtyp;
  x.reg  = r0() + reg;
  x.phtype = pht;
  return true;
}

//--------------------------------------------------------------------------
static bool op_phrase_prepost(op_t &x, uint8 reg, uint8 selector)
{
  selector &= 3;
  char dtyp = selector == 0 ? ph_post_inc
    : selector == 1 ? ph_pre_inc
    : selector == 2 ? ph_post_dec : ph_pre_dec;
  return op_phrase(x, reg, dtyp);
}

//--------------------------------------------------------------------------
static bool op_phrase_displ2(op_t &x, uint8 reg, uint8 displ)
{
#ifndef NDEBUG
  QASSERT(10004, cmd.auxpref != aux_none);
#endif
  if ( reg & 8 )
    return false;
  if ( displ == 0 )
  {
    return op_phrase(x, reg, ph_normal);
  }
  x.type = o_displ;
  x.dtyp = dtyp_by_auxpref();
  x.reg  = ER0 + reg;
  x.addr = cmd.auxpref == aux_long ? displ << 2 :
           cmd.auxpref == aux_word ? displ << 1 : displ;
  x.szfl |= disp_2;
  return true;
}

//--------------------------------------------------------------------------
static void op_imm(op_t &x, uval_t val)
{
  x.type = o_imm;
  x.value = val;
  x.dtyp = dtyp_by_auxpref();
}

//--------------------------------------------------------------------------
static void op_imm_8(op_t &x, uint8 val)
{
  x.type = o_imm;
  x.dtyp = dt_byte;
  x.value = val;
}

//--------------------------------------------------------------------------
static void op_imm_3(op_t &x, uint8 val)
{
  x.type = o_imm;
  x.dtyp = dt_byte;
  x.value = (val >> 4) & 7;
}

//--------------------------------------------------------------------------
static bool op_displ_regidx(op_t &x, uint8 selector, bool is_32, uint8 reg)
{
  if ( reg & 8 )
    return false;

  regnum_t r;
  switch ( selector & 3 )
  {
    case 0:
      r = ER0;
      break;
    case 1:
      x.displtype = dt_regidx;
      r = R0L;
      x.szfl |= idx_byte;
      break;
    case 2:
      x.displtype = dt_regidx;
      r = R0;
      x.szfl |= idx_word;
      break;
    case 3:
      x.displtype = dt_regidx;
      r = ER0;
      x.szfl |= idx_long;
      break;
  }
  (is_32 ? opdsp32 : opdsp16)(x, dtyp_by_auxpref());
  x.reg  = r + reg;
  return true;
}

//--------------------------------------------------------------------------
static bool op_aa_8(op_t &x, uint8 val, char dtyp)
{
  x.type = o_mem;
  x.offb = (uchar)cmd.size - sizeof(val);
  x.dtyp = dtyp;
  x.addr = val;
  x.memtype = mem_sbr;
  return true;
}

//--------------------------------------------------------------------------
static bool op_reglist(op_t &x, uint8 reg, uint8 delta, bool is_inc)
{
  x.type  = o_reglist;
  x.dtyp  = dt_dword;
  x.nregs = delta + 1;
  if ( is_inc && reg >= delta )
    x.reg = ER0 + reg - delta;
  else if ( !is_inc && reg + delta <= 7 )
    x.reg = ER0 + reg;
  else
    return false;
  return true;
}
