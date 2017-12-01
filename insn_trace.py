"""
IDA: create instructions in unexplored code

Sometimes obfuscated code includes:

 * illegal instructions
 * jumps into the middle of subsequent instructions
 * etc

Of course these instructions are never executed, but IDA's recursive descent
algorithm fails to decode these subroutines successfully.  This debug hook
attempts to address this situation via instruction tracing at runtime.

To use this hook,
 * set a breakpoint at the obfuscated code
 * enable instruction-level tracing
 * activate this hook code

# https://hex-rays.com/products/ida/support/sdkdoc/dbg_8hpp.html
# https://github.com/idapython/src/blob/master/examples/debughook.py
"""

import ida_bytes
import ida_dbg
import ida_ua
import idc


class InstructionTracer(ida_dbg.DBG_Hooks):

    def __init__(self, *args):
        super(InstructionTracer, self).__init__(*args)
        self._visited_addrs = set()

    def clear_state(self):
        self._visited_addrs.clear()

    def dbg_trace(self, tid, ip):
        if ip in self._visited_addrs:
            return 1
        self._visited_addrs.add(ip)
        if idc.is_unknown(ida_bytes.get_flags(ip)):
            ida_ua.create_insn(ip)
        else:
            idc.msg(
                'Skipping explored EA at address 0x{0:X}\n'.format(ip)
            )
        # print idc.generate_disasm_line(ip, 0)
        if ida_ua.decode_insn(ip) > 0:
            if 'ret' in ida_ua.cmd.get_canon_mnem().lower():
                idc.msg('Found ret instruction, suspending execution\n')
                ida_dbg.suspend_process()
        else:
            idc.msg(
                'Unable to decode instruction at address 0x{0:X}\n'.format(ip)
            )
            ida_dbg.suspend_process()
        return 0


# my_tracer = InstructionTracer()
# my_tracer.hook()
# insn_dbg.unhook()
