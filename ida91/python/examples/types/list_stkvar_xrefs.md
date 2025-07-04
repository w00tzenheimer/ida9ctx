```python
"""
summary: list all xrefs to a function stack variable

description:
  Contrary to (in-memory) data & code xrefs, retrieving stack variables
  xrefs requires a bit more work than just using ida_xref's first_to(),
  next_to() (or higher level utilities such as idautils.XrefsTo)

keywords: xrefs

level: intermediate
"""

ACTION_NAME = "list_stkvar_xrefs:list"
ACTION_SHORTCUT = "Ctrl+Shift+F7"

import ida_bytes
import ida_frame
import ida_funcs
import ida_ida
import ida_kernwin
import ida_typeinf
import ida_ua

class list_stkvar_xrefs_ah_t(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        cur_ea = ida_kernwin.get_screen_ea()
        pfn = ida_funcs.get_func(cur_ea)
        if not pfn:
            print("Please position the cursor within a function")
            return

        v = ida_kernwin.get_current_viewer()
        result = ida_kernwin.get_highlight(v)
        if not result:
            print("Please highlight the stack variable name")
            return

        stkvar_name, _ = result
        frame = ida_typeinf.tinfo_t()
        pfn = ida_funcs.get_func(cur_ea)
        frame.get_func_frame(pfn)
        stkvar_idx, stkvar = frame.get_udm(stkvar_name)
        if stkvar_idx < 0:
            print("No stack variable named \"%s\"" % stkvar_name)
            return

        for ea in pfn:
            F = ida_bytes.get_flags(ea)
            for n in range(ida_ida.UA_MAXOP):
                if not ida_bytes.is_stkvar(F, n):
                    continue
                insn = ida_ua.insn_t()
                if not ida_ua.decode_insn(insn, ea):
                    continue
                v = ida_frame.calc_stkvar_struc_offset(pfn, insn, n)
                if v >= stkvar.begin()/8 and v < stkvar.end()/8:
                    print("Found xref at 0x%08x, operand #%d" % (ea, n))

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET \
            if ctx.widget_type == ida_kernwin.BWN_DISASM \
               else ida_kernwin.AST_DISABLE_FOR_WIDGET

adesc = ida_kernwin.action_desc_t(
    ACTION_NAME,
    "List stack variable xrefs",
    list_stkvar_xrefs_ah_t(),
    ACTION_SHORTCUT)

if ida_kernwin.register_action(adesc):
    print("Action registered. Please press \"%s\" to use" % ACTION_SHORTCUT)

```
