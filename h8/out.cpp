/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "h8.hpp"
#include <srarea.hpp>
#include <struct.hpp>

//----------------------------------------------------------------------
int get_displ_outf(const op_t &x)
{
  return OOF_ADDR|OOFS_IFSIGN|OOF_SIGNED
       | ((isStkvar(uFlag,x.n) || (x.szfl & disp_32) || advanced()) ? OOFW_32 : OOFW_16);
}

//----------------------------------------------------------------------
static void out_bad_address(ea_t addr)
{
  const char *name = find_sym(addr);
  if ( name != NULL )
  {
    out_line(name, COLOR_IMPNAME);
  }
  else
  {
    out_tagon(COLOR_ERROR);
    OutLong(addr, 16);
    out_tagoff(COLOR_ERROR);
    QueueSet(Q_noName, cmd.ea);
  }
}

//----------------------------------------------------------------------
inline void outreg(int r)
{
  out_register(ph.regNames[r]);
}

//----------------------------------------------------------------------
ea_t trim_ea_branch(ea_t ea)
{
  switch ( ptype & MODE_MASK )
  {
    case MODE_MID:
    case MODE_ADV:
      return ea & 0x00FFFFFF;
    case MODE_MAX:
      return ea;
  }
  return ea & 0x0000FFFF;
}

//----------------------------------------------------------------------
ea_t calc_mem(ea_t ea)
{
  return toEA(cmd.cs, ea);
}

//----------------------------------------------------------------------
ea_t calc_mem_sbr_based(ea_t ea)
{
  sel_t base = get_segreg(cmd.ea, SBR);
  return (base & 0xFFFFFF00) | (ea & 0x000000FF);
}

//----------------------------------------------------------------------
static void out_sizer(char szfl)
{
  static char show_sizer = -1;
  if ( show_sizer == -1 )
    show_sizer = !qgetenv("H8_NOSIZER");
  if ( !show_sizer )
    return;

  if ( szfl & disp_2 )
    return;
  int size = (szfl & disp_32) ? 32 :
             (szfl & disp_24) ? 24 :
             (szfl & disp_16) ? 16 : 8;
  out_symbol(':');
  out_long(size, 10);
}

//----------------------------------------------------------------------
static void attach_name_comment(const op_t &x, ea_t v)
{
  char buf[MAXSTR];
  if ( get_name_expr(cmd.ea, x.n, v, BADADDR, buf, sizeof(buf)) > 0
    && !has_cmt(get_flags_novalue(cmd.ea)) )
  {
    set_cmt(cmd.ea, buf, false);
  }
}

//----------------------------------------------------------------------
static ea_t get_data_ref(ea_t ea)
{
  ea_t to = BADADDR;
  xrefblk_t xb;
  for ( bool ok=xb.first_from(ea, XREF_DATA); ok; ok=xb.next_from() )
  {
    if ( xb.type == dr_O )
      return xb.to;
  }
  return to;
}

//----------------------------------------------------------------------
//lint -esym(1764,x)
bool idaapi outop(op_t &x)
{
  switch ( x.type )
  {

    case o_void:
      return 0;

    case o_reg:
      outreg(x.reg);
      break;

    case o_reglist:
      if ( is_hew_asm() )
        out_symbol('(');
      outreg(x.reg);
      out_symbol('-');
      outreg(x.reg+x.nregs-1);
      if ( is_hew_asm() )
        out_symbol(')');
      break;

    case o_imm:
      out_symbol('#');
      OutValue(x, OOFS_IFSIGN|OOFW_IMM);
      break;

    case o_mem:
      out_symbol('@');
      if ( x.memtype == mem_vec7 || x.memtype == mem_ind )
        out_symbol('@');
      // no break
    case o_near:
      {
        ea_t ea = x.memtype == mem_sbr ?
          calc_mem_sbr_based(x.addr) :
          calc_mem(x.addr);
        if ( is_hew_asm() && (x.szfl & disp_24) )
          out_symbol('@');
        out_addr_tag(ea);
        if ( x.memtype == mem_sbr
          || !out_name_expr(x, ea, x.addr) )
        {
          out_bad_address(x.addr);
          if ( x.memtype == mem_sbr )
            attach_name_comment(x, ea);
        }
        if ( x.memtype != mem_vec7 )
          out_sizer(x.szfl);
      }
      break;

    case o_phrase:
      out_symbol('@');

      if ( x.phtype == ph_pre_dec )
        out_symbol('-');
      else if ( x.phtype == ph_pre_inc )
        out_symbol('+');

      outreg(x.phrase);

      if ( x.phtype == ph_post_inc )
        out_symbol('+');
      else if ( x.phtype == ph_post_dec )
        out_symbol('-');

      {
        ea_t ea = get_data_ref(cmd.ea);
        if ( ea != BADADDR )
          attach_name_comment(x, ea);
      }
      break;

    case o_displ:
      out_symbol('@');
      out_symbol('(');
      OutValue(x, get_displ_outf(x));
      out_sizer(x.szfl);
      out_symbol(',');
      if ( x.displtype == dt_movaop1 )
      {
        op_t ea;
        memset(&ea, 0, sizeof(ea));
        ea.offb   = cmd.Op1.offo;
        ea.type   = cmd.Op1.idxt;
        ea.phrase = cmd.Op1.phrase;
        ea.phtype = cmd.Op1.idxdt;
        ea.addr   = cmd.Op1.value;
        ea.szfl   = cmd.Op1.idxsz;
        outop(ea);
        out_symbol('.');
        out_symbol(x.szfl & idx_byte ? 'b' :
                   x.szfl & idx_word ? 'w' : 'l');
      }
      else if ( x.displtype == dt_regidx )
      {
        outreg(x.reg);
        out_symbol('.');
        out_symbol(x.szfl & idx_byte ? 'b' :
                   x.szfl & idx_word ? 'w' : 'l');
      }
      else
      {
        outreg(x.reg);
      }
      out_symbol(')');
      break;

    case o_pcidx:
      outreg(x.reg);
      break;

    default:
      INTERR(10096);
  }
  return 1;
}

//----------------------------------------------------------------------
void idaapi out(void)
{
  static const char *const postfixes[] = { NULL, ".b", ".w", ".l" };
  char buf[MAXSTR];
  init_output_buffer(buf, sizeof(buf));

  const char *postfix = postfixes[cmd.auxpref];
  OutMnem(8, postfix);

  bool showOp1 = cmd.Op1.shown();
  if ( showOp1 )
    out_one_operand(0);
  if ( cmd.Op2.type != o_void )
  {
    if ( showOp1 )
    {
      out_symbol(',');
      OutChar(' ');
    }
    out_one_operand(1);
  }
  if ( cmd.Op3.type != o_void )
  {
    out_symbol(',');
    OutChar(' ');
    out_one_operand(2);
  }

  for ( int i=0; i < 3; i++ )
    if ( isVoid(cmd.ea, uFlag, i) )
      OutImmChar(cmd.Operands[i]);

  term_output_buffer();
  gl_comm = 1;
  MakeLine(buf);
}

//--------------------------------------------------------------------------
void idaapi segstart(ea_t ea)
{
  const char *predefined[] =
  {
    ".text",    // Text section
    ".rdata",   // Read-only data section
    ".data",    // Data sections
    ".lit8",    // Data sections
    ".lit4",    // Data sections
    ".sdata",   // Small data section, addressed through register $gp
    ".sbss",    // Small bss section, addressed through register $gp
  };

  segment_t *Sarea = getseg(ea);
  if ( Sarea == NULL || is_spec_segm(Sarea->type) )
    return;

  char sname[MAXNAMELEN];
  char sclas[MAXNAMELEN];
  get_true_segm_name(Sarea, sname, sizeof(sname));
  get_segm_class(Sarea, sclas, sizeof(sclas));

  int i;
  for ( i=0; i < qnumber(predefined); i++ )
    if ( strcmp(sname, predefined[i]) == 0 )
      break;
  if ( i != qnumber(predefined) )
    printf_line(inf.indent, COLSTR("%s", SCOLOR_ASMDIR), sname);
  else
    printf_line(inf.indent, COLSTR("%s", SCOLOR_ASMDIR) "" COLSTR("%s %s", SCOLOR_AUTOCMT),
                 strcmp(sclas,"CODE") == 0 ? ".text" : ".data",
                 ash.cmnt,
                 sname);
}

//--------------------------------------------------------------------------
void idaapi segend(ea_t)
{
#if 0
  segment_t *s = getseg(ea-1);
  if ( !is_spec_segm(s->type) )
    printf_line(0,COLSTR(";%-*s ends",SCOLOR_AUTOCMT),inf.indent-2,get_segm_name(s));
#endif
}

//--------------------------------------------------------------------------
void idaapi assumes(ea_t ea)
{
  segment_t *seg = getseg(ea);
  if ( !inf.s_assume || seg == NULL )
    return;
  bool seg_started = (ea == seg->startEA);

  for ( int i = ph.regFirstSreg; i <= ph.regLastSreg; i++ )
  {
    if ( i == ph.regCodeSreg || i == ph.regDataSreg )
      continue;
    segreg_area_t sra;
    if ( !get_srarea2(&sra, ea, i) )
      continue;
    bool show = sra.startEA == ea;
    if ( show )
    {
      segreg_area_t prev_sra;
      if ( get_prev_srarea(&prev_sra, ea, i) )
        show = sra.val != prev_sra.val;
    }
    if ( seg_started || show )
      gen_cmt_line("%-*s assume %s: %a", int(inf.indent-strlen(ash.cmnt)-2), "", ph.regNames[i], sra.val);
  }
}

//--------------------------------------------------------------------------
//  Generate stack variable definition line
//  If this function is NULL, then the kernel will create the line itself.
void idaapi h8_gen_stkvar_def(char *buf, size_t bufsize, const member_t *mptr, sval_t v)
{
  char sign = ' ';
  if ( v < 0 )
  {
    v = -v;
    sign = '-';
  }

  char num[MAX_NUMBUF];
  btoa(num, sizeof(num), v);

  qstring name = get_member_name2(mptr->id);
  if ( is_hew_asm() )
  {
    qsnprintf(buf, bufsize,
              COLSTR("%s", SCOLOR_LOCNAME)
              COLSTR(": ", SCOLOR_SYMBOL)
              COLSTR(".assign", SCOLOR_ASMDIR)
              COLSTR(" %c", SCOLOR_SYMBOL)
              COLSTR("%s", SCOLOR_DNUM),
              name.c_str(), sign, num);
  }
  else
  {
    qsnprintf(buf, bufsize,
              COLSTR("%-*s", SCOLOR_LOCNAME)
              COLSTR("= %c", SCOLOR_SYMBOL)
              COLSTR("%s", SCOLOR_DNUM), inf.indent, name.c_str(), sign, num);
  }
}

//--------------------------------------------------------------------------
void idaapi header(void)
{
  gen_header(GH_PRINT_ALL);

  if ( ptype == P300 )
    return;
  char procdir[MAXSTR];
  qsnprintf(procdir, MAXSTR, ".h8300%s%s",
            is_h8sx() ? "sx" : is_h8s() ? "s" : "h",
            advanced() ? "" : "n");
  MakeNull();
  printf_line(inf.indent, "%s", procdir);
}

//--------------------------------------------------------------------------
void idaapi footer(void)
{
  qstring nbuf = get_colored_name(inf.beginEA);
  const char *name = nbuf.c_str();
  const char *end = ash.end;
  if ( end == NULL )
    printf_line(inf.indent, COLSTR("%s end %s",SCOLOR_AUTOCMT), ash.cmnt, name);
  else
    printf_line(inf.indent,
                COLSTR("%s",SCOLOR_ASMDIR) " " COLSTR("%s %s",SCOLOR_AUTOCMT),
                ash.end,
                ash.cmnt,
                name);
}
