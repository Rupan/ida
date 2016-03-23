/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "h8.hpp"
#include <frame.hpp>
#include <srarea.hpp>

static bool flow;
static bool check_for_table_jump(void);
static bool check_for_generic_indirect_jump(void);
static bool check_for_generic_indirect_call(void);
//------------------------------------------------------------------------
static void process_immediate_number(int n)
{
  doImmd(cmd.ea);
  if ( isDefArg(uFlag,n) )
    return;
  switch ( cmd.itype )
  {
    case H8_shal:
    case H8_shar:
    case H8_shll:
    case H8_shlr:
    case H8_rotl:
    case H8_rotr:
    case H8_rotxl:
    case H8_rotxr:
      if ( n == 0 )
        op_dec(cmd.ea, n);
      break;
    case H8_and:
    case H8_or:
    case H8_xor:
      op_num(cmd.ea, n);
      break;
  }
}

//----------------------------------------------------------------------
inline bool issp(int x)
{
  return x == R7 || x == ER7;
}

inline bool isbp(int x)
{
  return x == R6 || x == ER6;
}

//----------------------------------------------------------------------
int idaapi is_sp_based(const op_t &x)
{
  return OP_SP_ADD
       | ((x.type == o_displ || x.type == o_phrase) && issp(x.phrase)
        ? OP_SP_BASED
        : OP_FP_BASED);
}

//----------------------------------------------------------------------
static void add_stkpnt(ssize_t value)
{
  func_t *pfn = get_func(cmd.ea);
  if ( pfn == NULL )
    return;

  if ( value & 1 )
    value++;

  add_auto_stkpnt2(pfn, cmd.ea+cmd.size, value);
}

//----------------------------------------------------------------------
// Does the instruction in 'cmd' spoil any register from 'regs'?
// Only o_phrase operand with not ph_normal types are consulted
static bool is_reg_spoiled_by_phrase(const uint32 *regs, size_t n)
{
  for ( size_t i=0; i < UA_MAXOP; i++ )
  {
    if ( cmd.Operands[i].type == o_phrase
      && cmd.Operands[i].phtype != ph_normal
      && (cmd.get_canon_feature() & (CF_USE1<<i)) != 0 )
    {
      for ( size_t j=0; j < n; j++ )
        if ( cmd.Operands[i].phrase == regs[j] )
          return true;
    }
  }
  return false;
}

//----------------------------------------------------------------------
// Is instruction in cmd too complex to check for reg spoil
static bool is_complex_insn(uint16 reg)
{
  if ( (Instructions[cmd.itype].feature & (CF_CALL|CF_STOP)) != 0 )
    return true;

  switch ( cmd.itype )
  {
    case H8_eepmov:
      // R4L, ER5, ER6
    case H8_ldm:
    case H8_movmd:
      // R4, ER5, ER6
    case H8_movsd:
      // R4, ER5, ER6
    case H8_pop:
      if ( (reg & 7) != R7 )
        break;
    case H8_push:
      if ( (reg & 7) != R7 )
        break;
    case H8_stm:
    // skip MACL, MACH manupulations
      return true;
  }

  return false;
}

//----------------------------------------------------------------------
static const uint32 reg_relative[][5] =
{
  { R0, E0, R0H, R0L, ER0 },
  { R1, E1, R1H, R1L, ER1 },
  { R2, E2, R2H, R2L, ER2 },
  { R3, E3, R3H, R3L, ER3 },
  { R4, E4, R4H, R4L, ER4 },
  { R5, E5, R5H, R5L, ER5 },
  { R6, E6, R6H, R6L, ER6 },
  { R7, E7, R7H, R7L, ER7 },
};

inline uint16 reg_toR0(uint16 reg)
{
  return uint16(reg_relative[reg & 7][0]);
}

inline uint16 reg_toR0L(uint16 reg)
{
  return uint16(reg_relative[reg & 7][3]);
}

static bool is_reg_spoiled(uint16 reg)
{
#ifdef __LINUX__
  // other compilers are not smart enough
  CASSERT(reg_toR0(ER7) == R7 && reg_relative[R6L & 7][1] == E6);
#endif
#ifndef NDEBUG
  QASSERT(10101, reg <= SBR);
#endif
  static uint32 specreg[1];

  const uint32 *spoil_list;
  size_t spoil_sz;
  if ( reg <= ER7 )
  {
    spoil_list = &reg_relative[reg & 7][0];
    spoil_sz = qnumber(reg_relative[0]);
  }
  else
  {
    specreg[0] = reg;
    spoil_list = &specreg[0];
    spoil_sz = 1;
  }

  int spoiled_idx = get_spoiled_reg(spoil_list, spoil_sz);
  return spoiled_idx >= 0
      || is_reg_spoiled_by_phrase(spoil_list, spoil_sz)
      || is_complex_insn(reg);
}

//----------------------------------------------------------------------
static bool get_op_value(const op_t &x, uval_t *value, ea_t *base_addr = NULL)
{
  if ( base_addr != NULL )
    *base_addr = 0;

  if ( x.type == o_imm )
  {
    *value = x.value;
    return true;
  }

  if ( x.type != o_reg
    && (x.type != o_displ
     || x.displtype != dt_normal && x.displtype != dt_regidx)
    && x.type != o_phrase
    && x.type != o_pcidx )
  {
    return false;
  }
  uint16 reg = x.reg;

  bool ok = false;
  insn_t saved = cmd;
  ea_t next_ea = cmd.ea;
  while ( (!hasRef(get_flags_novalue(next_ea)) || get_first_cref_to(next_ea) == BADADDR)
       && decode_prev_insn(cmd.ea) != BADADDR )
  {
    if ( cmd.itype == H8_mov
      && cmd.Op1.type == o_imm
      && cmd.Op2.type == o_reg
      && cmd.Op2.reg  == reg )
    {
      *value = cmd.Op1.value;
      ok = true;
      break;
    }

    if ( is_reg_spoiled(reg) )
      break;

    next_ea = cmd.ea;
  }
  cmd = saved;

  if ( ok )
  {
    if ( x.type == o_phrase )
    {
      if ( x.phtype == ph_pre_inc )
        *value += 1;
      else if ( x.phtype == ph_pre_dec )
        *value -= 1;
    }
    else if ( x.type == o_displ )
    {
      if ( x.displtype == dt_regidx )
      {
        if ( (cmd.auxpref == aux_long) != 0 )
          *value <<= 2;
        else if ( (cmd.auxpref == aux_word) != 0 )
          *value <<= 1;
      }
      // if the offset from the base is greater than the base address
      // then they are most likely swapped around, so swap them back here
      if ( base_addr != NULL )
        *base_addr = x.addr > *value ? x.addr : *value;
      *value += x.addr;
    }
  }
  else
  {
    if ( x.type == o_displ )
    {
      *value = x.addr;
      ok = true;
    }
  }

  return ok;
}

//----------------------------------------------------------------------
static void trace_sp(void)
{
  // @sp++
  if ( cmd.Op1.type == o_phrase
    && issp(cmd.Op1.reg)
    && cmd.Op1.phtype == ph_post_inc )
  {
    ssize_t size = get_dtyp_size(cmd.Op2.dtyp);
    if ( cmd.Op2.type == o_reglist )
      size *= cmd.Op2.nregs;
    add_stkpnt(size);
    return;
  }

  // @--sp
  if ( cmd.Op2.type == o_phrase
    && issp(cmd.Op2.reg)
    && cmd.Op2.phtype == ph_pre_dec )
  {
    ssize_t size = get_dtyp_size(cmd.Op1.dtyp);
    if ( cmd.Op1.type == o_reglist )
      size *= cmd.Op1.nregs;
    add_stkpnt(-size);
    return;
  }

  uval_t v;
  switch ( cmd.itype )
  {
    case H8_add:
    case H8_adds:
      if ( !issp(cmd.Op2.reg) )
        break;
      if ( get_op_value(cmd.Op1, &v) )
        add_stkpnt(v);
      break;
    case H8_sub:
    case H8_subs:
      if ( !issp(cmd.Op2.reg) )
        break;
      if ( get_op_value(cmd.Op1, &v) )
        add_stkpnt(0-v);
      break;
    case H8_push:
      add_stkpnt(0-get_dtyp_size(cmd.Op1.dtyp));
      break;
    case H8_pop:
      add_stkpnt( get_dtyp_size(cmd.Op1.dtyp));
      break;
  }
}

//----------------------------------------------------------------------
static void add_code_xref(const op_t &x, ea_t ea)
{
  cref_t ftype = fl_JN;
  if ( InstrIsSet(cmd.itype, CF_CALL) )
  {
    if ( !func_does_return(ea) )
      flow = false;
    ftype = fl_CN;
  }
  ua_add_cref(x.offb, ea, ftype);
}

//----------------------------------------------------------------------
static void handle_operand(const op_t &x, bool is_forced, bool isload)
{
  uval_t op_value;

  switch ( x.type )
  {
    case o_reg:
    case o_reglist:
      return;

    case o_imm:
      QASSERT(10094, isload);
      process_immediate_number(x.n);
      if ( op_adds_xrefs(uFlag, x.n) )
        ua_add_off_drefs2(x, dr_O, OOFS_IFSIGN|OOFW_IMM);
      break;

    case o_phrase:
      if ( is_forced )
        break;
      if ( !isDefArg(uFlag,x.n) && get_op_value(x, &op_value) )
      {
        op_offset(cmd.ea, x.n, REF_OFF32, op_value);
      }
      if ( op_adds_xrefs(uFlag, x.n) )
      {
        ea_t ea = ua_add_off_drefs2(x, isload ? dr_R : dr_W, get_displ_outf(x));
        if ( ea != BADADDR )
        {
          ua_dodata2(x.offb, ea, x.dtyp);
          if ( !isload )
            doVar(ea);
        }
      }
      break;

    case o_displ:
      if ( is_forced )
        break;
      if ( op_adds_xrefs(uFlag, x.n) )
      {
        ea_t ea = ua_add_off_drefs2(x, isload ? dr_R : dr_W, get_displ_outf(x));
        if ( ea != BADADDR )
        {
          ua_dodata2(x.offb, ea, x.dtyp);
          if ( !isload )
            doVar(ea);
        }
        if ( (x.flags & OF_OUTER_DISP) != 0 )
        {
          ea = ua_add_off_drefs2(x, isload ? dr_R : dr_W, OOF_OUTER | OOF_SIGNED | OOFW_32);
          if ( ea != BADADDR )
          {
            ua_dodata2(x.offo, ea, x.szfl & idx_byte ? dt_byte : dt_word);
            if ( !isload )
              doVar(ea);
          }
        }
      }
      // create stack variables if required
      if ( may_create_stkvars() && !isDefArg(uFlag, x.n) )
      {
        func_t *pfn = get_func(cmd.ea);
        if ( pfn != NULL
          && (issp(x.phrase)
           || isbp(x.phrase) && (pfn->flags & FUNC_FRAME) != 0) )
        {
          if ( ua_stkvar2(x, x.addr, STKVAR_VALID_SIZE) )
            op_stkvar(cmd.ea, x.n);
        }
      }
      break;
    case o_near:
      add_code_xref(x, calc_mem(x.addr));
      break;
    case o_mem:
      {
        ea_t ea = x.memtype == mem_sbr ?
          calc_mem_sbr_based(x.addr) :
          calc_mem(x.addr);
        if ( !isEnabled(ea) && find_sym(ea) )
          break;    // address not here
        ua_add_dref(x.offb, ea, isload ? dr_R : dr_W);
        ua_dodata2(x.offb, ea, x.dtyp);
        if ( x.memtype == mem_ind || x.memtype == mem_vec7 )
        {
          ssize_t size = get_dtyp_size(x.dtyp);
          flags_t F = getFlags(ea);
          if ( (isWord(F) || isDwrd(F))
            && (!isDefArg0(F) || isOff0(F)) )
          {
            ea_t target = calc_mem(size == 2
                                ? get_word(ea)
                                : trim_ea_branch(get_long(ea)));
            if ( isEnabled(target) )
              add_code_xref(x, target);
            if ( !isOff0(F) )
              set_offset(ea, 0, calc_mem(0));
          }
          break;
        }
        if ( !isload )
          doVar(ea);
      }
      break;
    case o_pcidx:
      {
        uval_t value;
        bool ok = get_op_value(x, &value);
        if ( ok )
        {
          ea_t ea = cmd.ea + cmd.size + (value << 1);
          add_code_xref(x, ea);
        }
      }
      break;
    default:
      INTERR(10095);
  }
}


//----------------------------------------------------------------------
static void check_base_reg_change_value()
{
  if ( cmd.itype == H8_ldc
    && cmd.Op2.type == o_reg
    && (cmd.Op2.reg == SBR || cmd.Op2.reg == VBR) )
  {
    sel_t value = BADSEL;
    bool ok = get_op_value(cmd.Op1, &value);
    split_srarea(cmd.ea + cmd.size, cmd.Op2.reg, value, ok ? SR_autostart : SR_user);
  }
}

//----------------------------------------------------------------------
int idaapi emu(void)
{
  uint32 Feature = cmd.get_canon_feature();
  bool flag1 = is_forced_operand(cmd.ea, 0);
  bool flag2 = is_forced_operand(cmd.ea, 1);
  bool flag3 = is_forced_operand(cmd.ea, 2);

  flow = ((Feature & CF_STOP) == 0);

  if ( Feature & CF_USE1 ) handle_operand(cmd.Op1, flag1, true);
  if ( Feature & CF_USE2 ) handle_operand(cmd.Op2, flag2, true);
  if ( Feature & CF_USE3 ) handle_operand(cmd.Op3, flag3, true);

  if ( Feature & CF_CHG1 ) handle_operand(cmd.Op1, flag1, false);
  if ( Feature & CF_CHG2 ) handle_operand(cmd.Op2, flag2, false);
  if ( Feature & CF_CHG3 ) handle_operand(cmd.Op3, flag3, false);

//
//      Check for table and generic indirect jumps
//
  if ( cmd.itype == H8_jmp && cmd.Op1.type == o_phrase )
  {
    if ( !check_for_table_jump() )
      check_for_generic_indirect_jump();
  }

  if ( cmd.itype == H8_jsr && cmd.Op1.type == o_phrase )
  {
    check_for_generic_indirect_call();
  }

//
//      Check for SBR, VBR change value
//
  if ( is_h8sx() )
    check_base_reg_change_value();

//
//      Determine if the next instruction should be executed
//
  if ( segtype(cmd.ea) == SEG_XTRN )
    flow = false;
  if ( flow )
    ua_add_cref(0,cmd.ea+cmd.size,fl_F);


//
//      Handle SP modifications
//
  if ( may_trace_sp() )
  {
    if ( !flow )
      recalc_spd(cmd.ea);     // recalculate SP register for the next insn
    else
      trace_sp();
  }

  return 1;
}

//----------------------------------------------------------------------
int is_jump_func(const func_t * /*pfn*/, ea_t *jump_target)
{
  *jump_target = BADADDR;
  return 1; // means "no"
}

//----------------------------------------------------------------------
int may_be_func(void)           // can a function start here?
                                // arg: none, the instruction is in 'cmd'
                                // returns: probability 0..100
                                // 'cmd' structure is filled upon the entrace
                                // the idp module is allowed to modify 'cmd'
{
  if ( cmd.itype == H8_push && isbp(cmd.Op1.reg) )
    return 100;  // push.l er6
  if ( cmd.itype == H8_push && cmd.Op1.reg==ER3 )
    return 100;  // push.l er3
  if ( cmd.itype == H8_push && cmd.Op1.reg==R3 )
    return 100;  // push.w r3
  return 0;
}

//----------------------------------------------------------------------
int is_sane_insn(int /*nocrefs*/)
{
  if ( cmd.itype == H8_nop )
  {
    for ( int i=0; i < 8; i++ )
      if ( get_word(cmd.ea-i*2) != 0 )
        return 1;
    return 0; // too many nops in a row
  }
  return 1;
}

//----------------------------------------------------------------------
int idaapi h8_is_align_insn(ea_t ea)
{
  if ( !decode_insn(ea) )
    return 0;
  switch ( cmd.itype )
  {
    case H8_nop:
      break;
    case H8_mov:
    case H8_or:
      if ( cmd.Op1.type == cmd.Op2.type && cmd.Op1.reg == cmd.Op2.reg )
        break;
    default:
      return 0;
  }
  return cmd.size;
}

//----------------------------------------------------------------------
bool idaapi is_return_insn()
{
  return cmd.itype == H8_rte
      || cmd.itype == H8_rts
      || cmd.itype == H8_rtel
      || cmd.itype == H8_rtsl;
}

//----------------------------------------------------------------------
bool idaapi create_func_frame(func_t *pfn)
{
  int code = 0;
  if ( pfn->frame == BADNODE )
  {
    size_t regs = 0;
    ea_t ea = pfn->startEA;
    bool bpused = false;
    while ( ea < pfn->endEA )                 // skip all pushregs
    {                                         // (must test that ea is lower
                                              // than pfn->endEA)
      decode_insn(ea);
      ea += cmd.size;
      switch ( cmd.itype )
      {
        case H8_nop:
          continue;
        case H8_push:
          regs += get_dtyp_size(cmd.Op1.dtyp);
          continue;
        case H8_stm:
          if ( !issp(cmd.Op2.reg) )
            break;
          regs += cmd.Op1.nregs * get_dtyp_size(cmd.Op1.dtyp);
          continue;
        case H8_mov:  // mov.l er6, sp
          if ( cmd.Op1.type == o_reg && issp(cmd.Op1.reg)
            && cmd.Op2.type == o_reg && isbp(cmd.Op2.reg) )
              bpused = true;
          break;
        default:
          break;
      }
      break;
    }
    if ( regs != 0 || bpused )
    {
      setflag((uint32 &)pfn->flags, FUNC_FRAME, bpused);
      return add_frame(pfn, 0, (ushort)regs, 0);
    }
  }
  return code != 0;
}

//----------------------------------------------------------------------
int idaapi h8_get_frame_retsize(func_t *)
{
  return advanced() ? 4 : 2;
}

//----------------------------------------------------------------------
//      These are the recognized jump table sizing patterns
//0100                cmp.b   #7, r0l
//0102                bls     loc_108:8
//0104                bra     def_200:8
//0106      loc_108:  ; jump table lookup
//0200      def_200:  ; default jump target
//      Or
//0100                cmp.b   #7, r0l
//0102                bls     loc_108:8
//0104                jmp     def_2000:16
//0108      loc_108:  ; jump table lookup
//2000      def_2000: ; default jump target
//      Or
//0100                mov.w   #7, r3
//0104                cmp.w   r3, r0
//0106                bls     loc_10C:8
//0108                bra     def_200:8
//010A      loc_10C:  ; jump table lookup
//0200      def_200:  ; default jump target
//      Or
//0100                mov.w   #7, r3
//0104                cmp.w   r3, r0
//0106                bls     loc_10C:8
//0108                jmp     def_2000:16
//010C      loc_10C:  ; jump table lookup
//2000      def_2000: ; default jump target
//      Or
//0100                cmp.b   #7, r0l
//0102                bhi     def_200:8
//0104                ; jump table lookup
//0200      def_200:  ; default jump target
//      Or
//0100                mov.w   #7, r3
//0104                cmp.w   r3, r0
//0106                bhi     def_200:8
//0108                ; jump table lookup
//0200      def_200:  ; default jump target
//----------------------------------------------------------------------
static bool find_table_size(ea_t *defea, int *size, int rlx, ea_t code_ip)
{
  *defea = BADADDR;
  *size  = INT_MAX;
  if ( decode_prev_insn(cmd.ea) == BADADDR )
    return true;

  if ( cmd.itype == H8_bhi )                    // bhi default
  {
    *defea = cmd.Op1.addr;
  }
  else
  {
    if ( cmd.itype != H8_jmp                    // jmp default
      && cmd.itype != H8_bra )                  // bra default
    {
      return true;
    }
    *defea = cmd.Op1.addr;

    if ( decode_prev_insn(cmd.ea) == BADADDR
      || cmd.itype != H8_bls                    // bls code_ip
      || cmd.Op1.addr != code_ip )
    {
      return true;
    }
  }

  if ( decode_prev_insn(cmd.ea) == BADADDR
    || cmd.itype    != H8_cmp                   // cmp.b #size, rlx
    || cmd.Op2.type != o_reg )
  {
    return true;
  }
  if ( cmd.Op1.type == o_imm )
  {
    if ( cmd.auxpref != aux_byte
      || cmd.Op2.reg != rlx )
    {
      return true;
    }
  }
  else
  {
    if ( cmd.Op1.type != o_reg                  // cmp.w RX, rx
      || cmd.Op2.reg  != (rlx - 24) )
    {
      return true;
    }
    int rx = cmd.Op1.reg;
    if ( decode_prev_insn(cmd.ea) == BADADDR
      || cmd.itype    != H8_mov                 // mov.w #size, RX
      || cmd.Op2.type != o_reg
      || cmd.Op2.reg  != rx
      || cmd.Op1.type != o_imm )
    {
      return true;
    }
  }

  *size = int(cmd.Op1.value + 1);
  return true;
}

//----------------------------------------------------------------------
//      This is jump table pattern #1
//0100                sub.b   r0h, r0h
//0102                mov.b   @(jpt_10a:16,r0), r0l
//0106                add.b   #loc_10C & 0xFF, r0l
//0108                addx    #loc_10C >> 8, r0h
//010A                jmp     @r0
//010C      loc_10C:  ; base address of jump table
//      Or
//0100                mov.b   @(jpt_10a:16,r0), r0l
//0104                sub.b   r0h, r0h
//0106                add.b   #loc_10C & 0xFF, r0l
//0108                addx    #loc_10C >> 8, r0h
//010A                jmp     @r0
//010C      loc_10C:  ; base address of jump table
//----------------------------------------------------------------------
static bool is_jump_pattern1(ea_t *base, ea_t *table, ea_t *defea, int *size, int *elsize)
{
  int reg = cmd.Op1.phrase;
  int rh  = reg + 16;
  int rl  = rh  + 8;
  if ( decode_prev_insn(cmd.ea) == BADADDR
    || cmd.itype != H8_addx                     // addx #baseh, rh
    || cmd.Op1.type != o_imm
    || cmd.Op2.reg  != rh )
  {
    return false;
  }
  int baseh = (int)cmd.Op1.value;       // msb of base
  ea_t eah = cmd.ea;

  if ( decode_prev_insn(cmd.ea) == BADADDR
    || cmd.itype != H8_add                      // add.b #basel, rl
    || cmd.auxpref != aux_byte
    || cmd.Op1.type != o_imm
    || cmd.Op2.reg  != rl )
  {
    return false;
  }
  int basel = (int)cmd.Op1.value;       // lsb of base
  ea_t eal = cmd.ea;

  int rx, rhx, rlx;
  ea_t obase;
  if ( decode_prev_insn(cmd.ea) == BADADDR )
    return false;
  else
  {
    if ( cmd.itype == H8_mov )                     // mov.b @(table:16,rx), rl
    {
      if ( cmd.auxpref != aux_byte
        || cmd.Op1.type != o_displ
        || cmd.Op2.reg  != rl )
      {
        return false;
      }

      *table = cmd.Op1.addr;
      rx  = cmd.Op1.reg;
      rhx = rx + 16;
      rlx = rhx + 8;
      obase = toEA(cmd.cs, 0);
      set_offset(cmd.ea, 0, obase);

      if ( decode_prev_insn(cmd.ea) == BADADDR
        || (cmd.itype != H8_sub && cmd.itype != H8_xor) // sub.b rhx, rhx
        || cmd.auxpref != aux_byte
        || cmd.Op1.type != o_reg
        || cmd.Op2.type != o_reg
        || cmd.Op1.reg  != rhx
        || cmd.Op2.reg  != rhx )
      {
        return false;
      }
    }
    else if ( cmd.itype == H8_sub || cmd.itype == H8_xor )  // sub.b rhx, rhx
    {
      if ( cmd.auxpref != aux_byte
        || cmd.Op1.type != o_reg
        || cmd.Op2.type != o_reg
        || cmd.Op1.reg  != cmd.Op2.reg )
      {
        return false;
      }

      rhx = cmd.Op1.reg;
      rlx = rhx + 8;
      rx = rhx - 16;

      if ( decode_prev_insn(cmd.ea) == BADADDR
        || (cmd.itype != H8_mov)                     // mov.b @(table:16,rx), rl
        || cmd.auxpref != aux_byte
        || cmd.Op1.type != o_displ
        || cmd.Op2.reg  != rl
        || cmd.Op1.reg != rx )
      {
        return false;
      }

      *table  = cmd.Op1.addr;
      obase = toEA(cmd.cs, 0);
      set_offset(cmd.ea, 0, obase);
    }
    else
      return false;
  }

  *base = int(baseh<<8) | basel;
  ea_t bea = toEA(cmd.cs, *base);
  op_offset(eah, 0, REF_HIGH8, bea, obase);
  op_offset(eal, 0, REF_LOW8,  bea, obase);

  // the jump table is found, try to determine its size
  *elsize = 1;
  return find_table_size(defea, size, rlx, cmd.ip);
}

//----------------------------------------------------------------------
//      This is jump table pattern #2
//      (*1* may be omitted...IE, this logic is located above jump table sizing instructions)
//0100    *1*          sub.b   r0h, r0h
//0102                 add.w   r0, r0
//0104                 mov.w   @(jpt_108:16,r0), r0
//0108                 jmp     @r0
//----------------------------------------------------------------------
static bool is_jump_pattern2(ea_t *base, ea_t *table, ea_t *defea, int *size, int *elsize)
{
  int reg = cmd.Op1.phrase;
  if ( decode_prev_insn(cmd.ea) == BADADDR
    || cmd.itype != H8_mov                      // mov.w   @(table:16,r0), r0
    || cmd.auxpref != aux_word
    || cmd.Op1.type != o_displ
    || cmd.Op2.reg  != reg )
  {
    return false;
  }
  *table  = cmd.Op1.addr;
  int rx  = cmd.Op1.reg;
  *base   = 0;
  ea_t bea = toEA(cmd.cs, 0);
  set_offset(cmd.ea, 0, bea);

  if ( decode_prev_insn(cmd.ea) == BADADDR
    || cmd.itype != H8_add                      // add.w r0, r0
    || cmd.auxpref != aux_word
    || cmd.Op1.type != o_reg
    || cmd.Op1.reg  != rx
    || cmd.Op2.reg  != rx )
  {
    return false;
  }
  int rhx = rx + 16;
  int rlx = rhx + 8;

  ea_t oldea = cmd.ea;
  ea_t oldip = cmd.ip;
  if ( decode_prev_insn(cmd.ea) == BADADDR
    || (cmd.itype != H8_sub && cmd.itype != H8_xor) // sub.b rhx, rhx
    || cmd.auxpref != aux_byte
    || cmd.Op1.type != o_reg
    || cmd.Op2.type != o_reg
    || cmd.Op1.reg  != rhx
    || cmd.Op2.reg  != rhx )
  {
    cmd.ea = oldea; // forgive this...
    cmd.ip = oldip;
  }

  // the jump table is found, try to determine its size
  *elsize = 2;
  return find_table_size(defea, size, rlx, cmd.ip);
}

//----------------------------------------------------------------------
typedef bool h8_is_pattern_t(ea_t *base, ea_t *table, ea_t *defea, int *size, int *elsize);

static h8_is_pattern_t *const jump_patterns[] = { is_jump_pattern1, is_jump_pattern2 };

static bool check_for_table_jump(void)
{
  ea_t base = BADADDR, table = BADADDR, defea = BADADDR;
  int size = 0, elsize = 0;

  int i;
  bool ok = false;
  insn_t saved = cmd;
  for ( i=0; !ok && i < qnumber(jump_patterns); i++ )
  {
    ok = jump_patterns[i](&base, &table, &defea, &size, &elsize);
    cmd = saved;
  }
  if ( !ok )
    return false;

  if ( table != BADADDR )
    table = toEA(cmd.cs, table);
  if ( base != BADADDR )
    base = toEA(cmd.cs, base);
  if ( defea != BADADDR )
    defea = toEA(cmd.cs, defea);

  // check the table contents
  int oldsize = size;
  segment_t *s = getseg(table);
  if ( s == NULL )
    return false;
  int maxsize = int(s->endEA - table);
  if ( size > maxsize )
    size = maxsize;

  for ( i=0; i < size; i++ )
  {
    ea_t ea = table+i*elsize;
    flags_t F = getFlags(ea);
    if ( !hasValue(F) || (i && (has_any_name(F) || hasRef(F))) )
      break;
    int el = elsize == 1 ? get_byte(ea) : get_word(ea);
    flags_t F2 = get_flags_novalue(base+el);
    if ( isTail(F2)
      || isData(F2)
      || (!isCode(F2) && !decode_insn(base+el)) )
    {
      break;
    }
  }
  cmd = saved;
  size = i;
  if ( size != oldsize )
    msg("Warning: jpt_%04a calculated size of %d forced to %d!\n",
                                      cmd.ip, oldsize, size);

  // create the table
  if ( size == 0 )
    return false;
  for ( i=0; i < size; i++ )
  {
    ea_t ea = table + i*elsize;
    (elsize == 1 ? doByte : doWord)(ea, elsize);
    op_offset(ea, 0, elsize == 1 ? REF_OFF8 : REF_OFF16, BADADDR, base);
    ua_add_cref(0, base + (elsize==1?get_byte(ea):get_word(ea)), fl_JN);
  }
  char buf[MAXSTR];
  qsnprintf(buf, sizeof(buf), "def_%a", cmd.ip);
//  set_name(defea, buf, SN_NOWARN|SN_LOCAL);         // temporary kernel bug workaround
  set_name(defea, buf, SN_NOWARN);
  qsnprintf(buf, sizeof(buf), "jpt_%a", cmd.ip);
  set_name(table, buf, SN_NOWARN);
  return true;
}

//----------------------------------------------------------------------
static bool check_for_generic_indirect_jump(void)
{
  // Add code to handle the indirect jumps here
  // Ilfak, I don't have any of these... :)
  return false;
}

//----------------------------------------------------------------------
static bool check_for_generic_indirect_call(void)
{
  // Add code to handle the indirect calls here
  // However, I do have plenty of these... :(
  return false;
}

//----------------------------------------------------------------------
#define SKIP_NOPPC_FUNCTIONS
#include "../jptcmn.cpp"

//  ----------
//  Normalize switch var type
//  byte -> word; word, long - no need
//
// 11 extu.w r1  | exts.w r1
//
//  ----------
//  Normalize switch var value
//  in: er1
//
//  is_var_word == true (r1)
// 10 dec.w   #1|#2, r1 | sub.w #baseval, r1
//  is_var_word == false (er1)
// 10 dec.l   #1|#2, er1 | sub.l #baseval, er1
//
//  ----------
//  Default or end of switch jump
//  in: er1
//
//  is_var_word == true (r1)
//  9 cmp.w   #maxval, r1
//  is_var_word == false (er1)
//  9 cmp.l   #maxval, er1
//
//  8 bhi     default
//
//  is_var_word == true (r1)
//  7 mov.w   r1, r2            (optional) else r[r1] = r[r2]
//  is_var_word == false (er1)
//  7 mov.l   er1, er2          (optional) else r[r1] = r[r2]
//
//  ----------
//  Case offset load:
//  in : er2 - switch var value
//  out: er0 - case label offset
//       is_var_word set
//
//  is_var_word == true (r1)
//    if is_jtsz_byte
//  4   mov.b   @(bytesz_offsets:32,r2.w),r0l
//    else
//  4   mov.w   @(wordsz_offsets:32,r2.w),r0
//
//  6 extu.l  er2
//    if is_jtsz_byte
//  4   mov.b   @(bytesz_offsets:32,er2),r0l
//    else
//  5   add.l   er2, er2 | shll.l er2
//  4   mov.w   @(wordsz_offsets:32,er2),r0
//
//  is_var_word == false (er1)
//    if is_jtsz_byte
//  4   mov.b   @(bytesz_offsets:32,er2.l),r0l
//    else
//  4   mov.w   @(wordsz_offsets:32,er2.l),r0
//
//    if is_jtsz_byte
//  4   mov.b   @(bytesz_offsets:32,er2),r0l
//    else
//  5   add.l   er2, er2 | shll.l er2
//  4   mov.w   @(wordsz_offsets:32,er2),r0
//
//  ----------
//  Jump block:
//  in : er0 - case label offset
//  out: is_jtsz_byte set
//
//  is_jtsz_byte == true (r0l)
//  3 extu.w  r0
//  2 extu.l  er0
//  1 add.l   #base_offsets,er0
//  0 jmp     @er0
//
//  3
//  2 extu.l  #2, er0
//  1 add.l   #base_offsets,er0
//  0 jmp     @er0
//
//  3
//  2
//  1 shlr.b  r0l
//  0 bra     r0l.b
//
//  is_jtsz_byte == false (r0)
//  3
//  2 extu.l  er0
//  1 add.l   #base_offsets,er0
//  0 jmp     @er0
//
//  3
//  2
//  1 shlr.w  r0
//  0 bra     r0.w
//
//  0 -> 1 -> 2 -> 3 -> 4 -> 5 -> 6 -> 7 -> 8 -> 9 -> 10 -> 11

static const char roots_hew_jmp[] = { 1, 0 };
static const char depends_hew_jmp[][2] =
{
  {   1 },    //  0
  {   2 },    //  1
  {   3 },    //  2
  {   4 },    //  3
  {   5 },    //  4
  {   6 },    //  5
  {   7 },    //  6
  {   8 },    //  7
  {   9 },    //  8
  { -10 },    //  9
  { -11 },    // 10
  {   0 },    // 11
};

class hew_jmp_pattern_t : public jump_pattern_t
{
protected:
  enum { er0 = 1, er1, er2 };
  bool is_jtsz_byte;    // is jump table byte or word size
  bool is_var_word;     // is switch var word or long
  bool is_bra;          // bra or jump switch

  hew_jmp_pattern_t(const char *_roots, const char (*_depends)[2], switch_info_ex_t &_si)
    : jump_pattern_t(_roots, _depends, _si)
  {
    allow_noflows = false;
    is_jtsz_byte = false;
    is_var_word = false;
    is_bra = false;
  }

public:
  virtual void check_spoiled(void);
  hew_jmp_pattern_t(switch_info_ex_t &_si) : jump_pattern_t(roots_hew_jmp, depends_hew_jmp, _si)
  {
    allow_noflows = false;
    is_jtsz_byte = false;
    is_var_word = false;
    is_bra = false;
  }

  virtual bool jpib(void);
  virtual bool jpia(void);
  virtual bool jpi9(void);
  virtual bool jpi8(void);
  virtual bool jpi7(void);
  virtual bool jpi6(void);
  virtual bool jpi5(void);
  virtual bool jpi4(void);
  virtual bool jpi3(void);
  virtual bool jpi2(void);
  virtual bool jpi1(void);
  virtual bool jpi0(void);
};

//--------------------------------------------------------------------------
void hew_jmp_pattern_t::check_spoiled(void)
{
  if ( r[er0] != -1 && is_reg_spoiled(r[er0]) )
    spoiled[er0] = true;
  if ( r[er1] != -1 && is_reg_spoiled(r[er1]) )
    spoiled[er1] = true;
  if ( r[er2] != -1 && is_reg_spoiled(r[er2]) )
    spoiled[er2] = true;
}

//--------------------------------------------------------------------------
bool hew_jmp_pattern_t::jpib()
{
  if ( (cmd.itype == H8_extu || cmd.itype == H8_exts)
    && cmd.Op2.is_reg(r[er1]) )
  {
    si.startea = cmd.ea;
    return true;
  }
  return false;
}

//--------------------------------------------------------------------------
bool hew_jmp_pattern_t::jpia()
{
  if ( (cmd.itype == H8_dec || cmd.itype == H8_sub)
    && (is_var_word && cmd.auxpref == aux_word || cmd.auxpref == aux_long)
    && cmd.Op1.type == o_imm
    && cmd.Op2.is_reg(r[er1]) )
  {
    si.lowcase = cmd.Op1.value;
    si.startea = cmd.ea;
    return true;
  }

  return false;
}

//--------------------------------------------------------------------------
bool hew_jmp_pattern_t::jpi9(void)
{
  if ( cmd.itype != H8_cmp
    || (!is_var_word || cmd.auxpref != aux_word) && cmd.auxpref != aux_long
    || cmd.Op1.type != o_imm
    || !cmd.Op2.is_reg(r[er1]) )
  {
    return false;
  }

  si.ncases = cmd.Op1.value + 1;
  si.set_expr(cmd.Op2.reg, cmd.Op2.dtyp);
  si.lowcase = 0;
  si.startea = cmd.ea;

  // return true;
  // otherwise we can eat all up to the other switch
  skip[10] = true;
  skip[11] = true;

  insn_t saved = cmd;
  if ( decode_prev_insn(cmd.ea) != BADADDR
    && jpia() )
  {
    eas[10] = cmd.ea;
    if ( decode_prev_insn(cmd.ea) != BADADDR
      && jpib() )
    {
      eas[11] = cmd.ea;
    }
  }
  cmd = saved;
  return true;
}

//--------------------------------------------------------------------------
bool hew_jmp_pattern_t::jpi8(void)
{
  if ( cmd.itype != H8_bhi || cmd.Op1.type != o_near )
    return false;

  si.defjump = toEA(cmd.cs, cmd.Op1.addr);
  si.flags |= SWI_DEFAULT;
  return true;
}

//--------------------------------------------------------------------------
bool hew_jmp_pattern_t::jpi7(void)
{
  if ( cmd.itype == H8_mov
    && (is_var_word && cmd.auxpref == aux_word || cmd.auxpref == aux_long)
    && cmd.Op1.type == o_reg
    && (cmd.auxpref == aux_long && cmd.Op2.is_reg(r[er2])
     || cmd.auxpref == aux_word && cmd.Op2.is_reg(reg_toR0(r[er2]))) )
  {
    r[er1] = cmd.Op1.reg;
    return true;
  }

  if ( jpi8() )
  {
    r[er1] = r[er2];
    skip[8] = true;
    return true;
  }
  return false;
}

//--------------------------------------------------------------------------
bool hew_jmp_pattern_t::jpi6(void)
{
  if ( cmd.itype == H8_extu
    && cmd.auxpref == aux_long
    && !cmd.Op1.shown()
    && cmd.Op2.is_reg(r[er2]) )
  {
    is_var_word = true;
    return true;
  }

  if ( jpi7() )
  {
    skip[7] = true;
    return true;
  }
  return false;
}

//--------------------------------------------------------------------------
bool hew_jmp_pattern_t::jpi5(void)
{
  return cmd.auxpref == aux_long
      && cmd.Op2.is_reg(r[er2])
      && (cmd.itype == H8_add && cmd.Op1.is_reg(r[er2])
       || cmd.itype == H8_shll);
}

//--------------------------------------------------------------------------
bool hew_jmp_pattern_t::jpi4(void)
{
  if ( !(cmd.itype == H8_mov
      && (is_jtsz_byte && cmd.auxpref == aux_byte || cmd.auxpref == aux_word)
      && cmd.Op1.type == o_displ
      && (cmd.Op1.displtype == dt_normal
       || cmd.Op1.displtype == dt_regidx && (cmd.Op1.szfl & (idx_word | idx_long)) != 0)
      && (cmd.Op1.szfl & disp_32) != 0
      && cmd.Op2.type == o_reg
      && (is_jtsz_byte && cmd.Op2.reg == reg_toR0L(r[er0])
       || cmd.Op2.reg == reg_toR0(r[er0]))) )
  {
    return false;
  }

  if ( !isDefArg(uFlag,cmd.Op1.n) )
    op_offset(cmd.ea, cmd.Op1.n, REF_OFF32, calc_mem(cmd.Op1.addr));

  si.jumps = cmd.Op1.addr;
  r[er2] = cmd.Op1.reg;

  if ( is_jtsz_byte )
  {
    skip[5] = true;
    si.set_jtable_element_size(1);
  }
  else
  {
    si.set_jtable_element_size(2);
  }

  if ( cmd.Op1.displtype == dt_regidx )
  {
    is_var_word = (cmd.Op1.szfl & idx_word) != 0;
    skip[5] = true;
    skip[6] = true;
    return true;
  }

  return true;
}

//--------------------------------------------------------------------------
bool hew_jmp_pattern_t::jpi3(void)
{
  if ( cmd.itype == H8_extu
    && cmd.auxpref == aux_word
    && cmd.Op2.type == o_reg
    && cmd.Op2.reg == reg_toR0(r[er0]) )
  {
    is_jtsz_byte = true;
    return true;
  }

  if ( jpi4() )
  {
    skip[4] = true;
    return true;
  }
  return false;
}

//--------------------------------------------------------------------------
bool hew_jmp_pattern_t::jpi2(void)
{
  if ( !(cmd.itype == H8_extu
      && cmd.auxpref == aux_long
      && cmd.Op2.type == o_reg
      && cmd.Op2.reg == r[er0]) )
  {
    return false;
  }

  if ( cmd.Op1.shown()
    && cmd.Op1.value == 2 )
  {
    is_jtsz_byte = true;
    skip[3] = true;
  }
  return true;
}

//--------------------------------------------------------------------------
bool hew_jmp_pattern_t::jpi1(void)
{
  if ( is_bra )
  {
    skip[2] = true;
    skip[3] = true;
    return cmd.itype == H8_shlr
        && (is_jtsz_byte && cmd.auxpref == aux_byte || cmd.auxpref == aux_word)
        && cmd.Op2.is_reg(r[er0]);
  }

  if ( cmd.itype == H8_add
    && cmd.auxpref == aux_long
    && cmd.Op1.type == o_imm
    && cmd.Op2.is_reg(r[er0]) )
  {
    si.elbase = toEA(cmd.cs, cmd.Op1.value);
    si.flags |= SWI_ELBASE;
    return true;
  }
  return false;
}

//--------------------------------------------------------------------------
bool hew_jmp_pattern_t::jpi0(void)
{
  if ( cmd.itype == H8_jmp
    && cmd.Op1.type == o_phrase
    && cmd.Op1.phtype == ph_normal )
  {
    is_bra = false;
    r[er0] = cmd.Op1.reg;
    return true;
  }
  else if ( cmd.itype == H8_bra
         && cmd.Op1.type == o_pcidx
         && (cmd.Op1.szfl & idx_long) == 0 )
  {
    is_bra = true;
    si.elbase = cmd.ea + cmd.size;
    si.flags |= SWI_ELBASE;
    r[er0] = cmd.Op1.reg;
    is_jtsz_byte = (cmd.Op1.szfl & idx_byte) != 0;
    si.set_jtable_element_size(is_jtsz_byte ? 1 : 2);
    return true;
  }
  return false;
}

//----------------------------------------------------------------------
static jump_table_type_t is_hew_pattern(switch_info_ex_t &si)
{
  hew_jmp_pattern_t jp(si);
  return jp.match(cmd.ea) ? JT_FLAT32 : JT_NONE;
}

//----------------------------------------------------------------------
static bool check_for_jump1(switch_info_ex_t &si)
{
  static is_pattern_t *const h8_patterns[] = { is_hew_pattern };
  return check_for_table_jump2(h8_patterns, qnumber(h8_patterns), NULL, si);
}

//----------------------------------------------------------------------
bool idaapi h8_is_switch(switch_info_ex_t *si)
{
  if ( cmd.itype != H8_jmp && cmd.itype != H8_bra )
    return false;

  insn_t saved = cmd;
  bool found = check_for_jump1(*si);
  cmd = saved;
  return found;
}

// Purpose: calculate function argument locations
// Arguments:
//   type    : points to the return type of the function type string
//   cc      : calling convention
//   arglocs : the result array
// returns: 1-not implemented, 2-ok, -1-error
// ==================================================================
// calc_arglocs should fill the 'arglocs' array with the argument
// location information. The hppa module does it by calling the
// set_reg1 and set_stkoff functions.
// See hppa_calc_arglocs for an example
// ==================================================================
// See rej10b0161_h8s.pdf, section 9.3.2 - Function Calling Interface
int h8_calc_arglocs(const type_t *type, cm_t /*cc*/, varloc_t *arglocs)
{
  return -1;
}

// Purpose: use information about a stack argument
// Arguments:
//   ea   : address of the push instruction which
//          pushes the function argument into the stack
//   type : the function argument type
//   name : the function argument name. may be NULL
// returns: true - ok, false - failed
// ==================================================================
// use_stkarg_type gives the processor module the opportunity to
// attach a comment to the push instruction or otherwise improve
// the listing. Since hppa does not use push to prepare arguments,
// this callback is not implemented for it. If you wish, you could
// call a function similar to hppa_set_op_type() in your
// implementation of the use_stkarg_type callback. BTW, I checked
// all processor modules, it is implemented only for x86.
bool h8_use_stkvar_type(ea_t ea, const type_t *type, const char *name)
{
  return false;
}
