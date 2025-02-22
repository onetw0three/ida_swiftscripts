from ida_hexrays import *

def parse_reg(reg_name):
    reg_info = ida_idp.reg_info_t()
    if not ida_idp.parse_reg_name(reg_info, reg_name):
        print("Bad reg name:", reg_name)
        return None, None
    mreg = reg2mreg(reg_info.reg)
    if mreg == -1:
        print(f"Failed to convert {reg_name} to microregister")
        return None, None
    return mreg, reg_info.size

def create_mov_reg_reg(ea:int, src_reg: int , dst_reg: int, size: int):
    m = minsn_t(ea)
    m.opcode = m_mov
    m.l.make_reg(*parse_reg(get_mreg_name(src_reg, size)))
    m.d.make_reg(*parse_reg(get_mreg_name(dst_reg, size)))
    m.iprops |= IPROP_ASSERT
    return m

class swift_string_visitor_t(minsn_visitor_t):
    cnt = 0
    def __init__(self):
        minsn_visitor_t.__init__(self)
    def visit_minsn(self):
        ins = self.curins 
        if ins.opcode == m_sub and ins.r.t == mop_n and ins.r.nnn.value == 0x20:
            if not (ins.next and ins.next.opcode == m_or): return 0
            if ins.next.r.t == mop_n and ins.next.r.nnn.value == 0x8000000000000000:
                ins.swap(create_mov_reg_reg(ins.ea, ins.l.r, ins.d.r, 8))
                ins.next.swap(create_mov_reg_reg(ins.next.ea, ins.next.l.r, ins.next.d.r, 8))
                self.cnt = self.cnt + 2
        return 0 
    
class swift_string_optinsn_t(optinsn_t):
    def __init__(self):
        optinsn_t.__init__(self)
    def func(self, blk, ins, optflags):
        opt = swift_string_visitor_t()
        ins.for_all_insns(opt)
        if opt.cnt != 0: 
            blk.mba.verify(True)
        return opt.cnt    