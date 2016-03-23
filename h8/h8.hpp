/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#ifndef _H8_HPP
#define _H8_HPP

#include "../idaidp.hpp"
#include "ins.hpp"
#include <typeinf.hpp>

//---------------------------------
// Operand types:

/*
o_reg     1 Register direct
            Rn
            x.reg
o_phrase  2 Register indirect
            @ERn
            x.phrase contains register number
            x.phtype contains phrase type (normal, post, pre)
o_displ   3 Register indirect with displacement
            @(d:2,ERn)/@(d:16,ERn)/@(d:32,ERn)
            x.reg, x.addr, disp_16, disp_32, disp_2
o_displ   4 Index register indirect with displacement
            @(d:16, RnL.B)/@(d:16,Rn.W)/@(d:16,ERn.L)
            @(d:32, RnL.B)/@(d:32,Rn.W)/@(d:32,ERn.L)
            x.displtype = dt_regidx,
            x.reg,
            x.addr - disp_16, disp_32, idx_byte/word/long
o_phrase  5 Register indirect with post-inc/pre-dec/pre-inc/post-dec
            @ERn+/@-ERn/@+ERn/@ERn-
o_mem     6 Absolute address
            @aa:8/@aa:16/@aa:24/@aa:32
            x.memtype = @aa:8 ? mem_sbr : mem_direct
            x.addr
o_imm     7 Immediate
            #x:2/#xx:3/#xx:4/#xx:5/#xx:8/#xx:16/#xx:32
            #1/#2/#4/#8/#16
            x.value
o_near    8 Program-counter relative
            @(d:8,PC)/@(d:16,PC)
o_pcidx   9 Program-counter relative with index register
            @(RnL.B,PC)/@(Rn.W,PC)/@(ERn.L,PC)
            x.reg
o_mem    10 Memory indirect
            @@aa:8
            x.memtype = mem_ind
            x.addr
o_mem    11 Extended memory indirect
            @@vec:7
            x.memtype = mem_vec7
            x.addr
o_reglist   Register list
            x.reg, x.nregs
o_displ     first operand of MOVA insn
            @(d16,<EA>.[BW])/@(d32:<EA>.[BW])
            x.displtype = dt_movaop1,
            x.addr,
            x.szfl - disp_16/disp_32/idx_byte/idx_word
            x.idxt - <EA> type
            <EA> type:
            o_reg - x.reg EQ to o_regidx
            o_phrase - x.phrase,x.idxdt
            o_displ - x.reg,x.value,x.idxsz,x.idxdt
            o_regidx - x.reg,x.value,x.idxsz,x.idxdt
            o_mem - x.value,x.idsz,x.idxdt
*/

#define o_reglist       o_idpspec0
#define o_pcidx         o_idpspec1

#define phtype          specflag1       // phrase type:
const int ph_normal     = 0;            // just simple indirection
const int ph_pre_dec    = 0x10;         // -@Rn ^ 3 -> @Rn+
const int ph_post_inc   = 0x13;         // @Rn+
const int ph_pre_inc    = 0x11;         // +@ERn
const int ph_post_dec   = 0x12;         // @ERn-

#define displtype       specflag1       // displ type:
const int dt_normal     = 0;            // Register indirect with displacement
const int dt_regidx     = 1;            // Index register indirect with displacement
const int dt_movaop1    = 2;            // first operand of MOVA insn

#define szfl            specflag2       // various operand size flags
                                        // index target
const int idx_byte      = 0x01;         // .b
const int idx_word      = 0x02;         // .w
const int idx_long      = 0x04;         // .l
                                        // size of operand displ
const int disp_16       = 0x10;         // 16bit displacement
const int disp_24       = 0x20;         // 24bit displacement
const int disp_32       = 0x40;         // 32bit displacement
const int disp_2        = 0x80;         //  2bit displacement

#define memtype         specflag1       // mem type:
const int mem_direct    = 0;            // x.addr - direct memory ref
const int mem_sbr       = 1;            // SBR based @aa:8
const int mem_vec7      = 2;            // @@vec:7
const int mem_ind       = 3;            // @@aa:8

#define nregs           specflag1       // o_reglist: number of registers

// MOVA Op1 store
#define idxt            specflag3       // MOVA: optype_t of index
#define idxsz           specflag4       // MOVA: size of index
#define idxdt           specval         // MOVA: index phtype,displtype,memtype

//------------------------------------------------------------------
const uint16 aux_none = 0;              // no postfix
const uint16 aux_byte = 1;              // .b postfix
const uint16 aux_word = 2;              // .w postfix
const uint16 aux_long = 3;              // .l postfix

//------------------------------------------------------------------
#ifdef _MSC_VER
#define ENUM8BIT : uint8
#else
#define ENUM8BIT
#endif
enum regnum_t ENUM8BIT
{
  R0,    R1,    R2,    R3,    R4,    R5,    R6,    R7, SP=R7,
  E0,    E1,    E2,    E3,    E4,    E5,    E6,    E7,
  R0H,   R1H,   R2H,   R3H,   R4H,   R5H,   R6H,   R7H,
  R0L,   R1L,   R2L,   R3L,   R4L,   R5L,   R6L,   R7L,
  ER0,   ER1,   ER2,   ER3,   ER4,   ER5,   ER6,   ER7,
  // don't change registers order above this line
  MACL, MACH,
  PC,
  CCR, EXR,
  rVcs, rVds,   // virtual registers for code and data segments
  VBR, SBR,     // base or segment registers
};

//------------------------------------------------------------------
// processor types

typedef uint16 proctype_t;

static const proctype_t none  = 0;
static const proctype_t P300  = 0x0001;     // H8/300, H8/300H
static const proctype_t P2000 = 0x0002;     // H8S/2000
static const proctype_t P2600 = 0x0004;     // H8S/2600
static const proctype_t PSX   = 0x0008;     // H8SX

// assume 'Normal mode' as the default
static const proctype_t MODE_MASK= 0xF000;
static const proctype_t MODE_MID = 0x1000;  // H8SX
static const proctype_t MODE_ADV = 0x2000;  // H8/300H (!), H8S, H8SX
static const proctype_t MODE_MAX = 0x3000;  // H8SX

static const proctype_t P30A = P300  | MODE_ADV;
static const proctype_t P26A = P2600 | MODE_ADV;

extern proctype_t ptype;        // contains all bits which correspond
                                // to the supported processors set

inline bool advanced(void) { return (ptype & MODE_MASK) != 0; }
inline bool is_h8s(void)   { return (ptype & (P2000|P2600)) != 0; }
inline bool is_h8sx(void)  { return (ptype & PSX) != 0; }

//------------------------------------------------------------------
#define UAS_HEW         0x0001  // HEW assembler

inline bool is_hew_asm(void)
{
  return (ash.uflag & UAS_HEW) != 0;
}

//------------------------------------------------------------------
extern netnode helper;

ea_t trim_ea_branch(ea_t ea);         // trim address according to proc mode
ea_t calc_mem(ea_t ea);               // map virtual to physical ea
ea_t calc_mem_sbr_based(ea_t ea);     // map virtual @aa:8 physical ea
const char *find_sym(ea_t address);

void idaapi header(void);
void idaapi footer(void);

void idaapi segstart(ea_t ea);
void idaapi segend(ea_t ea);
void idaapi assumes(ea_t ea);

void idaapi out(void);
int  idaapi outspec(ea_t ea,uchar segtype);

int  idaapi ana(void);
int  idaapi emu(void);
bool idaapi outop(op_t &op);
void idaapi data(ea_t ea);

int  idaapi h8_is_align_insn(ea_t ea);
bool idaapi create_func_frame(func_t *pfn);
int  idaapi is_sp_based(const op_t &x);
bool idaapi is_return_insn(void);

int idaapi h8_get_frame_retsize(func_t *);
int is_jump_func(const func_t *pfn, ea_t *jump_target);
int may_be_func(void);           // can a function start here?
int get_displ_outf(const op_t &x);
int is_sane_insn(int nocrefs);
bool idaapi h8_is_switch(switch_info_ex_t *si);
void idaapi h8_gen_stkvar_def(char *buf, size_t bufsize, const member_t *mptr, sval_t v);


// type system functions
int h8_calc_arglocs(const type_t *type, cm_t cc, varloc_t *arglocs);
bool h8_use_stkvar_type(ea_t ea, const type_t *type, const char *name);
int h8_use_arg_types(ea_t caller,
                     const type_t * const *types,
                     const char * const *names,
                     const varloc_t *arglocs,
                     int n,
                     const type_t **rtypes,
                     const char **rnames,
                     uint32 *rlocs,
                     int rn);
int h8_use_regvar_type(ea_t ea,
                       const type_t * const *types,
                       const char * const *names,
                       const uint32 *regs,
                       int n);

#endif // _H8_HPP
