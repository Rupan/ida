/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2001 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              FIDO:   2:5020/209
 *                              E-mail: ig@datarescue.com
 *
 */

#include "h8.hpp"
#include <diskio.hpp>
#include <frame.hpp>
#include <srarea.hpp>

#include <ieee.h>

//--------------------------------------------------------------------------
static const char *register_names[] =
{
  "r0",   "r1",   "r2",  "r3",  "r4",  "r5",  "r6",  "r7",
  "e0",   "e1",   "e2",  "e3",  "e4",  "e5",  "e6",  "e7",
  "r0h",  "r1h",  "r2h", "r3h", "r4h", "r5h", "r6h", "r7h",
  "r0l",  "r1l",  "r2l", "r3l", "r4l", "r5l", "r6l", "r7l",
  "er0",  "er1",  "er2", "er3", "er4", "er5", "er6", "er7",
  "macl", "mach",
  "pc",
  "ccr", "exr",
  "cs","ds",       // virtual registers for code and data segments
  "vbr", "sbr",
};

//--------------------------------------------------------------------------
static const uchar startcode_0[] = { 0x01, 0x00, 0x6D, 0xF3 };  // push.l  er3
static const uchar startcode_1[] = { 0x6D, 0xF3 };              // push.w  r3

static const bytes_t startcodes[] =
{
  { sizeof(startcode_0), startcode_0 },
  { sizeof(startcode_1), startcode_1 },
  { 0, NULL }
};

//-----------------------------------------------------------------------
//      GNU ASM
//-----------------------------------------------------------------------
static const asm_t gas =
{
  AS_ASCIIC|AS_ALIGN2|ASH_HEXF3|ASD_DECF0|ASB_BINF3|ASO_OCTF1|AS_COLON|AS_N2CHR|AS_NCMAS|AS_ONEDUP,
  0,
  "GNU assembler",
  0,
  NULL,         // header lines
  NULL,         // no bad instructions
  ".org",       // org
  NULL,         // end

  ";",          // comment string
  '"',          // string delimiter
  '"',          // char delimiter
  "\"",         // special symbols in char and string constants

  ".ascii",     // ascii string directive
  ".byte",      // byte directive
  ".word",      // word directive
  ".long",      // double words
  NULL,         // qwords
  NULL,         // oword  (16 bytes)
  ".float",     // float  (4 bytes)
  ".double",    // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  NULL,         // arrays (#h,#d,#v,#s(...)
  ".space %s",  // uninited arrays
  "=",          // equ
  NULL,         // 'seg' prefix (example: push seg seg001)
  NULL,         // Pointer to checkarg_preline() function.
  NULL,         // char *(*checkarg_atomprefix)(char *operand,void *res); // if !NULL, is called before each atom
  NULL,         // const char **checkarg_operations;
  NULL,         // translation to use in character and string constants.
  NULL,         // current IP (instruction pointer)
  NULL,         // func_header
  NULL,         // func_footer
  ".globl",     // "public" name keyword
  NULL,         // "weak"   name keyword
  ".extern",    // "extrn"  name keyword
                // .extern directive requires an explicit object size
  ".comm",      // "comm" (communal variable)
  NULL,         // get_type_name
  ".align",     // "align" keyword
  '(', ')',     // lbrace, rbrace
  "%",          // mod
  "&",          // and
  "|",          // or
  "^",          // xor
  "~",          // not
  "<<",         // shl
  ">>",         // shr
  NULL,         // sizeof_fmt
  0,            // flag2
  NULL,         // cmnt2
  NULL,         // low8
  NULL,         // high8
  NULL,         // low16
  NULL,         // high16
  "#include \"%s\"",  // a_include_fmt
  NULL,         // a_vstruc_fmt
  NULL,         // a_3byte
  NULL,         // a_rva
  NULL,         // a_yword
};

//-----------------------------------------------------------------------
//      HEW ASM
//-----------------------------------------------------------------------
const asm_t hew =
{
  AS_ASCIIC|AS_ALIGN2|ASH_HEXF1|ASD_DECF0|ASO_OCTF7|ASB_BINF4|AS_COLON|AS_N2CHR|AS_NCMAS|AS_ONEDUP,
  UAS_HEW,
  "HEW assembler",
  0,
  NULL,         // header lines
  NULL,         // no bad instructions
  ".org",       // org
  ".end",       // end

  ";",          // comment string
  '"',          // string delimiter
  '"',          // char delimiter
  "\"",         // special symbols in char and string constants

  ".sdata",     // ascii string directive
  ".data.b",    // byte directive
  ".data.w",    // word directive
  ".data.l",    // double words
  NULL,         // qwords
  NULL,         // oword  (16 bytes)
  ".float",     // float  (4 bytes)
  ".double",    // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  NULL,         // arrays (#h,#d,#v,#s(...)
  ".res %s",    // uninited arrays
  ": .assign",  // equ that allows set/reset values
//": .equ",     // equ          (does not allow for reuse)
//": .reg (%s)",// equ for regs (does not allow for reuse)
//": .bequ",    // equ for bits (does not allow for reuse)
  NULL,         // 'seg' prefix (example: push seg seg001)
  NULL,         // Pointer to checkarg_preline() function.
  NULL,         // char *(*checkarg_atomprefix)(char *operand,void *res); // if !NULL, is called before each atom
  NULL,         // const char **checkarg_operations;
  NULL,         // translation to use in character and string constants.
  "$",          // current IP (instruction pointer)
  NULL,         // func_header
  NULL,         // func_footer
  ".global",    // "public" name keyword
  NULL,         // "weak"   name keyword
  ".global",    // "extrn"  name keyword
  ".comm",      // "comm" (communal variable)
  NULL,         // get_type_name
  ".align",     // "align" keyword
  '(', ')',     // lbrace, rbrace
  "%",          // mod
  "&",          // and
  "|",          // or
  "~",          // xor
  "~",          // not
  "<<",         // shl
  ">>",         // shr
  "sizeof",     // sizeof_fmt
  0,            // flag2
  NULL,         // cmnt2
  "low",        // low8
  "high",       // high8
  "lword",      // low16
  "hword",      // high16
  ".include \"%s\"",  // a_include_fmt
  NULL,         // a_vstruc_fmt
  NULL,         // a_3byte
  NULL,         // a_rva
  NULL,         // a_yword
};

static const asm_t *const asms[] = { &gas, &hew, NULL };

//--------------------------------------------------------------------------
static char device[MAXSTR] = "";
static ioport_t *ports = NULL;
static size_t numports = 0;
static const char cfgname[] = "h8.cfg";

static void load_symbols(void)
{
  free_ioports(ports, numports);
  ports = read_ioports(&numports, cfgname, device, sizeof(device), NULL);
}

//--------------------------------------------------------------------------
const char *find_sym(ea_t address)
{
  const ioport_t *port = find_ioport(ports, numports, address);
  return port ? port->name : NULL;
}

//--------------------------------------------------------------------------
static const char *idaapi set_idp_options(const char *keyword,int /*value_type*/,const void * /*value*/)
{
  if ( keyword != NULL )
    return IDPOPT_BADKEY;
  if ( choose_ioport_device(cfgname, device, sizeof(device), NULL) )
    load_symbols();
  return IDPOPT_OK;
}

//--------------------------------------------------------------------------
netnode helper;
proctype_t ptype;

static const proctype_t ptypes[] =
{
             P300,
  MODE_ADV | P300,
             P300 | P2000 | P2600,
  MODE_ADV | P300 | P2000 | P2600,
             P300 | P2000 | P2600 | PSX,
  MODE_MID | P300 | P2000 | P2600 | PSX,
  MODE_ADV | P300 | P2000 | P2600 | PSX,
  MODE_MAX | P300 | P2000 | P2600 | PSX,
};


static int idaapi notify(processor_t::idp_notify msgid, ...)
{
  int ret = 1;
  va_list va;
  va_start(va, msgid);

// A well behaving processor module should call invoke_callbacks()
// in his notify() function. If this function returns 0, then
// the processor module should process the notification itself
// Otherwise the code should be returned to the caller:

  int code = invoke_callbacks(HT_IDP, msgid, va);
  if ( code )
  {
    ret = code;
    goto finish_up;
  }

  switch ( msgid )
  {
    case processor_t::init:
//      __emit__(0xCC);   // debugger trap
      helper.create("$ h8");
      helper.supval(0, device, sizeof(device));
      inf.mf = 1;
      break;

    case processor_t::term:
      free_ioports(ports, numports);
      break;

    case processor_t::newasm:    // new assembler type selected
      {
        int asmnum = va_arg(va, int);
        bool hew_asm = asmnum == 1;
        if ( advanced() )
        {
          register_names[R7]  = "r7";
          register_names[ER7] = hew_asm ? "er7" : "sp";
        }
        else
        {
          register_names[R7]  = hew_asm ? "r7" : "sp";
          register_names[ER7] = "er7";
        }
      }
      break;

    case processor_t::newfile:   // new file loaded
      load_symbols();
      if ( is_h8sx() )
      {
        set_default_segreg_value(NULL, VBR, 0);
        set_default_segreg_value(NULL, SBR, 0xFFFFFF00);
      }
      break;

    case processor_t::oldfile:   // old file loaded
      load_symbols();
      break;

    case processor_t::closebase:
    case processor_t::savebase:
      helper.supset(0, device);
      break;

    case processor_t::newprc:    // new processor type
      ptype = ptypes[va_arg(va, int)];
      if ( advanced() )
      {
        ph.flag |= PR_DEFSEG32;
      }
      if ( is_h8sx() )
      {
        ph.flag |= PR_SEGS;
        ph.regLastSreg = SBR;
        ph.segreg_size = 4;
      }
      break;

    case processor_t::newseg:    // new segment
      break;

    case processor_t::is_jump_func:
      {
        const func_t *pfn = va_arg(va, const func_t *);
        ea_t *jump_target = va_arg(va, ea_t *);
        ret = is_jump_func(pfn, jump_target);
      }
      break;

    case processor_t::is_sane_insn:
      ret = is_sane_insn(va_arg(va, int));
      break;

    case processor_t::may_be_func:
                                // can a function start here?
                                // arg: none, the instruction is in 'cmd'
                                // returns: probability 0..100
                                // 'cmd' structure is filled upon the entrace
                                // the idp module is allowed to modify 'cmd'
      ret = may_be_func();
      break;

    case processor_t::gen_regvar_def:
      {
        regvar_t *v = va_arg(va, regvar_t*);
        if ( is_hew_asm() )
        {
          printf_line(0, COLSTR("%s", SCOLOR_REG)
                      COLSTR(": .reg (", SCOLOR_SYMBOL)
                      COLSTR("%s", SCOLOR_REG)
                      COLSTR(")", SCOLOR_SYMBOL), v->user, v->canon);
          ret = 0;
        }
      }
      break;

    case processor_t::is_ret_insn:
      {
        ea_t ea = va_arg(va, ea_t);
        insn_t saved = cmd;
        int code2 = decode_insn(ea) != 0 && is_return_insn() ? 2 : 0;
        cmd = saved;
        ret = code2;
      }
      break;

    default:
      break;
  }

finish_up:
  va_end(va);
  return ret;
}

//-----------------------------------------------------------------------
#define FAMILY "Hitachi H8:"
static const char *const shnames[] =
{
  "h8300", "h8300a", "h8s300", "h8s300a", "h8sxn", "h8sxm", "h8sxa", "h8sx", NULL
};
static const char *const lnames[] =
{
  FAMILY"Hitachi H8/300H normal",
  "Hitachi H8/300H advanced",
  "Hitachi H8S normal",
  "Hitachi H8S advanced",
  "Hitachi H8SX normal",
  "Hitachi H8SX middle",
  "Hitachi H8SX advanced",
  "Hitachi H8SX maximum",
  NULL
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,        // version
  PLFM_H8,                      // id
  PRN_HEX | PR_USE32 | PR_WORD_INS,
  8,                            // 8 bits in a byte for code segments
  8,                            // 8 bits in a byte for other segments

  shnames,
  lnames,

  asms,

  notify,

  header,
  footer,

  segstart,
  segend,

  assumes,              // generate "assume" directives

  ana,                  // analyze instruction
  emu,                  // emulate instruction

  out,                  // generate text representation of instruction
  outop,                // generate ...                    operand
  intel_data,           // generate ...                    data directive
  NULL,                 // compare operands
  NULL,                 // can have type

  qnumber(register_names), // Number of registers
  register_names,       // Register names
  NULL,                 // get abstract register

  0,                    // Number of register files
  NULL,                 // Register file names
  NULL,                 // Register descriptions
  NULL,                 // Pointer to CPU registers

  rVcs,                 // first
  rVds,                 // last
  0,                    // size of a segment register
  rVcs, rVds,

  startcodes,           // start sequences
  NULL,                 // see is_ret_insn callback in the notify() function

  H8_null,
  H8_last,
  Instructions,

  NULL,                 // int  (*is_far_jump)(int icode);
  NULL,                 // Translation function for offsets
  0,                    // int tbyte_size;  -- doesn't exist
  ieee_realcvt,         // int (*realcvt)(void *m, ushort *e, ushort swt);
  { 0, 7, 15, 0 },      // char real_width[4];
                        // number of symbols after decimal point
                        // 2byte float (0-does not exist)
                        // normal float
                        // normal double
                        // long double
  h8_is_switch,         // int (*is_switch)(switch_info_t *si);
  NULL,                 // int32 (*gen_map_file)(FILE *fp);
  NULL,                 // ea_t (*extract_address)(ea_t ea,const char *string,int x);
  is_sp_based,          // int (*is_sp_based)(op_t &x);
  create_func_frame,    // int (*create_func_frame)(func_t *pfn);
  h8_get_frame_retsize, // int (*get_frame_retsize(func_t *pfn)
  h8_gen_stkvar_def,    // void (*gen_stkvar_def)(char *buf,const member_t *mptr,long v);
  gen_spcdef,           // Generate text representation of an item in a special segment
  H8_rts,               // Icode of return instruction. It is ok to give any of possible return instructions
  set_idp_options,      // const char *(*set_idp_options)(const char *keyword,int value_type,const void *value);
  h8_is_align_insn,     // int (*is_align_insn)(ea_t ea);
  NULL,                 // mvm_t *mvm;
  0,                    // high_fixup_bits
};
