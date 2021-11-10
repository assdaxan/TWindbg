# -*- coding: utf-8 -*-

import pykd
import color
import sys
import traceback

from utils import *

ARCH = None
PTRMASK = None
PTRSIZE = None
MAX_DEREF = 5

def init_arch():
    global ARCH, PTRMASK, PTRSIZE
    cpu_mode = pykd.getCPUMode() 
    if cpu_mode == pykd.CPUType.I386:
        ARCH = 'x86'
        PTRMASK = 0xffffffff
        PTRSIZE = 4
    elif cpu_mode == pykd.CPUType.AMD64:
        ARCH = 'x64'
        PTRMASK = 0xffffffffffffffff
        PTRSIZE = 8
    else:
        print_err("CPU mode: {} not supported.".format(cpu_mode))
        sys.exit(-1)

def init_context_handler():
    global context_handler
    if 'context_handler' not in globals():
        context_handler = ContextHandler(Context())

class Context():
    def __init__(self):
        self.regs_name = []
        self.seg_regs_name = ['cs', 'ds', 'es', 'fs', 'gs', 'ss']
        self.regs = {}
        self.eflags_tbl = {
            0: "carry",
            2: "parity",
            4: "auxiliary",
            6: "zero",
            7: "sign",
            8: "trap",
            9: "interrupt",
            10: "direction",
            11: "overflow",
            14: "nested",
            16: "resume",
            17: "virtualx86"
        }
        self.is_changed = {}
        self.sp_name = ""
        self.sp = None
        self.pc_name = ""
        self.pc = None
                
        self.init_regs_name()
        self.init_regs()
        
    def init_regs_name(self):
        if ARCH == 'x86':
            self.regs_name = ['eax', 'ebx', 'ecx', 'edx', 'edi', 'esi', 'ebp', 'esp', 'eip']
            self.sp_name = 'esp'
            self.pc_name = 'eip'
        else:
            self.regs_name = ['rax', 'rbx', 'rcx', 'rdx', 'rdi', 'rsi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rbp', 'rsp', 'rip']
            self.sp_name = 'rsp'
            self.pc_name = 'rip'
    
    def init_regs(self):
        for reg_name in self.regs_name + self.seg_regs_name:
            self.regs[reg_name] = None
            self.is_changed[reg_name] = False
            
    def update_regs(self):
        for reg_name in self.regs_name + self.seg_regs_name:
            reg_data = pykd.reg(reg_name)
            if reg_data != self.regs[reg_name]: # is changed
                self.is_changed[reg_name] = True
            else:
                self.is_changed[reg_name] = False
            
            self.regs[reg_name] = reg_data
        # update sp & pc
        self.sp = self.regs[self.sp_name]
        self.pc = self.regs[self.pc_name]

class ContextHandler(pykd.eventHandler):
    def __init__(self, context):
        pykd.eventHandler.__init__(self)
        self.context = context
        
    def onExecutionStatusChange(self, status):
        if status == pykd.executionStatus.Break: # step, trace, ...
            self.print_context()

    def print_context(self):
        self.context.update_regs()
        pykd.dprintln(color.blue("[------ Register --------------------------------------------------------------------------------------------]"), dml=True)
        self.print_regs()
        pykd.dprintln(color.blue("[------ Navigator -------------------------------------------------------------------------------------------]"), dml=True)
        self.print_navigator()
        pykd.dprintln(color.blue("[------ Code ------------------------------------------------------------------------------------------------]"), dml=True)
        self.print_code()
        pykd.dprintln(color.blue("[------ Stack -----------------------------------------------------------------------------------------------]"), dml=True)
        self.print_stack()
        pykd.dprintln(color.blue("[------------------------------------------------------------------------------------------------------------]"), dml=True)
        
    def print_regs(self):
        self.print_general_regs()
        self.print_seg_regs()
        self.print_eflags()
        
    def print_general_regs(self):
        for reg_name in self.context.regs_name:
            reg_data = self.context.regs[reg_name]
            reg_str = '{:3}: '.format(reg_name.upper())
            reg_color = self.set_reg_color(reg_name, color_changed=color.red, color_unchanged=color.lime)
            pykd.dprint(reg_color(reg_str), dml=True)

            if pykd.isValid(reg_data): # reg_data is a pointer
                try:
                    self.print_ptrs(reg_data)
                except:
                    pykd.dprintln("{:#x}".format(reg_data))
            else:
                pykd.dprintln("{:#x}".format(reg_data))

    def print_seg_regs(self):
        first_print = True
        for reg_name in self.context.seg_regs_name:
            reg_data = self.context.regs[reg_name]
            reg_str = '{:2}={:#x}'.format(reg_name.upper(), reg_data)
            reg_color = self.set_reg_color(reg_name, color_changed=color.red, color_unchanged=color.green)

            if first_print:
                pykd.dprint(reg_color(reg_str), dml=True)
                first_print = False
            else:
                pykd.dprint(" | " + reg_color(reg_str), dml=True)
        pykd.dprintln("")
    
    def print_eflags(self):
        eflags = pykd.reg('efl')
        eflags_str = color.green("EFLAGS: {:#x}".format(eflags))
        eflags_str += " ["
        for bit, flag_name in self.context.eflags_tbl.items():
            is_set = eflags & (1<<bit)
            eflags_str += " "
            if is_set:
                eflags_str += color.dark_red(flag_name)
            else:
                eflags_str += color.green(flag_name)
        eflags_str += " ]"
        pykd.dprintln(eflags_str, dml=True)

    def set_reg_color(self, reg_name, color_changed, color_unchanged):
        if self.context.is_changed[reg_name]:
            return color_changed
        else:
            return color_unchanged

    def print_navigator(self):
        def is_hex(data):
            try:
                int(data, 16)
                return True
            except:
                return False

        def expr(data):
            if (s_i:=data.find("[")) != -1 and (e_i:=data.rfind("]")) != -1:
                # return pykd.expr(data[s_i+1:e_i])
                data = data[s_i+1:e_i]
                s = ''
                t = ''
                
                if (s_i:=data.find("(")) != -1 and (e_i:=data.rfind(")")) != -1:
                    data = (data[s_i+1:e_i]).replace("`", "")
                    return int(data, 16)

                for i, v in enumerate(data):
                    if v not in ['+', '-', '*', '/']:
                        t += v
                    elif is_hex(t):
                        s += (str(int(t, 16)) + v)
                        t = ''
                    else:
                        s += (str(pykd.reg(t)) + v)
                        t = ''
                if t != '':
                    if (t[-1] == 'h') and is_hex(t[:-1]):
                        s += str(int(t[:-1], 16))
                    elif is_hex(t):
                        s+= str(int(t, 16))
                    else:
                        s += str(pykd.reg(t))
                return eval(s)

        def calc(data):
            try:
                return pykd.reg(data)
            except pykd.DbgException:
                if data.find("qword ptr") != -1:
                    return pykd.loadQWords(expr(data), 1)[0]
                elif data.find("dword ptr") != -1:
                    return pykd.loadDWords(expr(data), 1)[0]
                elif data.find("word ptr") != -1:
                    return pykd.loadWords(expr(data), 1)[0]
                elif data.find("byte ptr") != -1:
                    return pykd.loadBytes(expr(data), 1)[0]
                else:
                    return expr(data)

        pc = self.context.pc
        op_str, asm_str = disasm(pc)
        t = asm_str.split(" ")
        operator, operand = t[0], ' '.join(t[1:]).strip()
        try:
            if operand.find(",") != -1:
                operand_1, operand_2 = operand.split(",")
                value_1, value_2 = calc(operand_1), calc(operand_2)
                if pykd.isValid(value_1): # reg_data is a pointer
                    pykd.dprint("{} = ".format(operand_1), dml=True)
                    self.print_ptrs(value_1)
                else:
                    pykd.dprintln("{} = {:#x}".format(operand_1, value_1), dml=True)

                if pykd.isValid(value_2): # reg_data is a pointer
                    pykd.dprint("{} = ".format(operand_2), dml=True)
                    self.print_ptrs(value_2)
                else:
                    pykd.dprintln("{} = {:#x}".format(operand_2, value_2), dml=True)
            else:
                value = calc(operand)
                if pykd.isValid(value): # reg_data is a pointer
                    pykd.dprint("{} = ".format(operand), dml=True)
                    self.print_ptrs(value)
                else:
                    pykd.dprintln("{} = {:#x}".format(operand, value), dml=True)
        except:
            pass

    def print_code(self):
        def parse_jmp_addr(data):
            op_str, asm_str = disasm(pc)
            t = asm_str.split(" ")
            operator, operand = t[0], ' '.join(t[1:]).strip()
            if operator in ["jmp", "je", "jz", "jne", "jnz", "js", "jns", "jg", 
                          "jnle", "jge", "jnl", "jl", "jnge", "jle", "jng", 
                          "ja", "jnbe", "jae", "jnb", "jb", "jnae", "jbe", "jna"]:
                return operator, pykd.expr(operand.split(" ")[1])
            return operator, 0

        def chk_eflag(name):
            for bit, flag_name in self.context.eflags_tbl.items():
                if flag_name == name:
                    is_set = pykd.reg('efl') & (1<<bit)
                    return is_set
        flag = False
        pc = self.context.pc
        j_oper, j_addr = parse_jmp_addr(pc)
        if  (j_oper in ['jmp']) or \
            (j_oper in ['je', 'jz'] and chk_eflag('zero')) or \
            (j_oper in ['jne', 'jnz'] and (not chk_eflag('zero')) ) or \
            (j_oper in ['js'] and chk_eflag('sign')) or \
            (j_oper in ['jns'] and (not chk_eflag('sign')) ) or \
            (j_oper in ['jg', 'jnle'] and (not chk_eflag('zero') and (chk_eflag("sign")^chk_eflag('overflow'))) ) or \
            (j_oper in ['jge', 'jnl'] and (not (chk_eflag("sign")^chk_eflag('overflow'))) ) or \
            (j_oper in ['jl', 'jnge'] and (chk_eflag('sign')^chk_eflag('overflow')) ) or \
            (j_oper in ['jle', 'jng'] and ((chk_eflag('sign')^chk_eflag('overflow')) or chk_eflag('zero')) ) or \
            (j_oper in ['ja', 'jnbe'] and (not chk_eflag('carry') and not chk_eflag('zero')) ) or \
            (j_oper in ['jae', 'jnb'] and (not chk_eflag('carry')) ) or \
            (j_oper in ['jb', 'jnae'] and chk_eflag('carry') ) or \
            (j_oper in ['jbe', 'jna'] and (chk_eflag('carry') or chk_eflag('zero')) ):
            flag = True

        for offset in range(-5, 20): # pc-5 ~ pc+20
            addr = pykd.disasm().findOffset(offset)
            op_str, asm_str = disasm(addr)
            code_str = "{:#x}: {:30s}{}".format(addr, op_str, asm_str)
            if addr == pc: # current pc, highlight
                if flag == True:
                    pykd.dprintln(color.red_highlight(code_str), dml=True)
                else:
                    pykd.dprintln(color.lime_highlight(code_str), dml=True)
            elif addr == j_addr:
                if flag == True:
                    pykd.dprintln(color.orange(code_str), dml=True)
                else:
                    pykd.dprintln(color.green(code_str), dml=True)
            else:
                t = asm_str.split(" ")
                operator, operand = t[0], ' '.join(t[1:]).strip()
                if operator == 'call':
                    pykd.dprintln(color.skyblue(code_str), dml=True)
                else:
                    pykd.dprintln(code_str, dml=True)
        flag = False
    
    def print_stack(self):
        self.print_nline_ptrs(self.context.sp, 8)
        
    def print_nline_ptrs(self, start_addr, line_num):
        for i in range(line_num):
            pykd.dprint("{:02d}:{:04x}| ".format(i, i * PTRSIZE))
            addr = start_addr + i * PTRSIZE
            if not pykd.isValid(addr):
                print_err("Invalid memory address: {:#x}".format(addr))
                break
            else:
                self.print_ptrs(addr)  

    def print_ptrs(self, addr):
        ptrs_str = ""
        ptr_values, is_cyclic = self.smart_dereference(addr)
        # print all ptrs except last two
        for ptr in ptr_values[:-2:]:
            ptrs_str += "{:#x} --> ".format(ptr)
        # handle last two's format
        last_ptr, last_val = ptr_values[-2], ptr_values[-1]
        if is_cyclic:
            ptrs_str += "{:#x} --> {:#x}".format(last_ptr, last_val) + color.dark_red(" ( cyclic dereference )")
        else:
            ptrs_str += self.enhance_type(last_ptr, last_val)
        pykd.dprintln(ptrs_str, dml=True)

    def enhance_type(self, ptr, val):
        ret_str = ""
        if is_executable(ptr): # code page
            symbol = pykd.findSymbol(ptr) + ":"
            asm_str = disasm(ptr)[1]
            ret_str = "{:#x}".format(ptr)
            ret_str += color.skyblue(" ({:45s}{})".format(symbol, asm_str))
        else:
            ret_str = "{:#x} --> {:#x}".format(ptr, val)
            val_str = get_string(ptr)
            if val_str: # val is probably a string
                ret_str += color.purple(" (\"{}\")".format(val_str))
        return ret_str

    def smart_dereference(self, ptr):
        ptr_values, is_cyclic = [ptr], False
        for _ in range(MAX_DEREF):
            val = deref_ptr(ptr)
            if val == None: # no more dereference
                break
            elif val in ptr_values[:-1:]: # cyclic dereference
                ptr_values.append(val)
                is_cyclic = True
                break
            else:
                ptr_values.append(val)
                ptr = val

        return ptr_values, is_cyclic
    
