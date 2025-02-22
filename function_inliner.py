import idaapi
import idc
import ida_allins
import idautils
import ida_bytes
import ida_funcs
from keystone import Ks, KS_ARCH_ARM64

ks = Ks(KS_ARCH_ARM64, 0)

def get_func_flowchart(pfn):
    if pfn is None: return False
    flowChart = idaapi.FlowChart(pfn)
    if flowChart is None: 
        return False
    return flowChart

def inline_func(pfn):
    pfn.flags |= idaapi.FUNC_OUTLINE 
    ida_funcs.update_func(pfn)

def check_inlined_attr(addr):
    return ida_funcs.get_func(addr).flags & idaapi.FUNC_OUTLINE

# heuristics:
# 1. in __text segment
# 2. does not start with PACIBSP or PACIASP
# 3. end with ret
def verify_inst_blk(blk, pac_mode=False, ninst=10):
    if "__text" not in idc.get_segm_name(blk.start_ea):
        return False
    if idc.print_insn_mnem(blk.start_ea) in ["PACIASP", "PACIBSP"]:
        return False
    if not pac_mode and idc.print_insn_mnem(blk.end_ea - 4) != "RET":
        return False
    num_inst = (blk.end_ea - blk.start_ea ) // 4
    if num_inst > ninst:
        return False
    return True
 
def is_simple_blk_pac(flow):
    if flow.size != 3:
        return False
    start_blk = flow[0]
    num_inst = (start_blk.end_ea - start_blk.start_ea ) // 4
    if num_inst < 3:
        return False
    if idc.print_insn_mnem(start_blk.end_ea - 8) == "EOR" and \
        idc.print_insn_mnem(start_blk.end_ea - 4) == "TBZ" and \
        idc.print_insn_mnem(start_blk.end_ea) == "BRK":
        if verify_inst_blk(start_blk, pac_mode=True):
            patch_pac_insn(start_blk.end_ea - 4)
            return start_blk.end_ea - 4 # address of last instruction (TBZ)
    return False

def is_simple_blk(flow):
    if flow.size != 1:
        return False
    return verify_inst_blk(flow[0])

def patch_pac_insn(tbz_insn_ea):
    insn = idautils.DecodeInstruction(tbz_insn_ea)
    b_target = insn.ops[2].addr
    # patch from eor insn
    topatch, _ = ks.asm(f"b {hex(b_target)}; nop; nop", tbz_insn_ea - 4)
    ida_bytes.patch_bytes(tbz_insn_ea - 4, bytes(topatch))
    print(f"patched pac check @ {hex(tbz_insn_ea)}")

def inline_simple_calls(addr):
    for item_ea in idautils.FuncItems(addr):
        insn = idautils.DecodeInstruction(item_ea)
        if insn.itype != ida_allins.ARM_bl:
            continue
        target_func_ea = insn.ops[0].addr
        if check_inlined_attr(target_func_ea):
            continue
            
        target_func_pfn = idaapi.get_func(target_func_ea)
        target_func_flow = get_func_flowchart(target_func_pfn)
        if not target_func_flow:
            continue

        if is_simple_blk(target_func_flow):
            inline_func(target_func_pfn)
            print(f"Inlined: {hex(item_ea)} -> {hex(target_func_ea)}")
        elif is_simple_blk_pac(target_func_flow):
            inline_func(target_func_pfn)
            print(f"Inlined (PAC): {hex(item_ea)} -> {hex(target_func_ea)}")
